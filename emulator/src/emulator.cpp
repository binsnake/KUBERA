#include <shared/context.hpp>
#include "sig_scanner.hpp"
#include "pch.hpp"

std::array<KGPR, X86_REG_ENDING> reg_map;
std::array<int, X86_REG_ENDING> avx_map {};

InstructionExceptionInfo g_instruction_exception_table [ X86_INS_ENDING ];

std::unique_ptr<PE::Parser> parser = nullptr;

constexpr int64_t KUSER_SHARED_DATA_BASE = 0x7FFE0000;
constexpr size_t KUSER_SHARED_DATA_SIZE = 2688; // 0xA80
constexpr int64_t KUSER_SHARED_DATA_END = KUSER_SHARED_DATA_BASE + KUSER_SHARED_DATA_SIZE;

bool EmulationContext::is_within_stack_bounds ( uint64_t address, uint8_t size ) const noexcept {
	const auto stack_base_addr = reinterpret_cast< uint64_t >( rsp_base.get ( ) );
	const auto stack_limit = stack_base_addr;
	const auto stack_top = stack_base_addr + stack_allocated;
	return ( address >= stack_limit && ( address + size ) <= stack_top );
}

uint64_t EmulationContext::get_access_mask ( x86_reg reg, uint8_t size ) const noexcept {
	switch ( size ) {
		case 8: return 0xFFFFFFFFFFFFFFFFULL;
		case 4: return 0x00000000FFFFFFFFULL;
		case 2:
			return 0x000000000000FFFFULL;
		case 1:
			if ( reg == X86_REG_CH || reg == X86_REG_DH || reg == X86_REG_BH || reg == X86_REG_AH )
				return 0x000000000000FF00ULL;
			return 0x00000000000000FFULL;
		default: return 0;
	}
}

uint8_t EmulationContext::get_access_shift ( x86_reg reg, uint8_t size ) const noexcept {
	if ( size == 1 ) {
		if ( reg == X86_REG_AH || reg == X86_REG_BH || reg == X86_REG_CH || reg == X86_REG_DH ) {
			return 8;
		}
	}
	return 0;
}

uint64_t EmulationContext::get_reg ( x86_reg reg, uint8_t size ) const {
	if ( reg == X86_REG_RIP ) {
		const auto current_instr_ip = decoder.back ( )->last_successful_ip ( );
		const auto current_instr_len = decoder.back ( )->last_successful_length ( );
		return current_instr_ip + current_instr_len;
	}

	const auto full_reg = reg_map [ reg ];
	const auto concrete_full = cpu->registers [ full_reg ];
	const auto access_mask = get_access_mask ( reg, size );
	const auto shift = get_access_shift ( reg, size );
	const auto extracted_value = ( concrete_full & access_mask ) >> shift;

	return extracted_value;
}

void EmulationContext::set_reg ( x86_reg reg, uint64_t val, uint8_t size, InstructionEffect& effect ) {
	const auto full_reg = reg_map [ reg ];
	uint64_t old_full_val_emu = cpu->registers [ full_reg ];

	const auto old_full_concrete = static_cast< uint64_t >( old_full_val_emu );
	const auto value_to_set = static_cast< uint64_t >( val );
	const auto access_mask = get_access_mask ( reg, size );
	const auto shift = get_access_shift ( reg, size );
	GET_OPERAND_MASK ( size_mask, size );

	uint64_t new_full_concrete;

	if ( size == 4 && ( full_reg >= KRAX && full_reg <= KR15 ) ) {
		new_full_concrete = static_cast< uint32_t >( value_to_set ); // Zero upper 32 bits
	}
	else {
		uint64_t shifted_value = ( value_to_set & size_mask ) << shift;
		new_full_concrete = ( old_full_concrete & ~access_mask ) | ( shifted_value & access_mask );
	}

	cpu->registers [ full_reg ] = new_full_concrete;

	if ( reg == X86_REG_RSP ) {
		cpu->rsp_offset = new_full_concrete - reinterpret_cast< uint64_t >( rsp_base.get ( ) );
	}
	if ( !effect.no_log ) {
		log_reg_change ( effect, reg, old_full_val_emu, new_full_concrete, "set" );
	}
}

uint64_t EmulationContext::get_stack ( uint64_t address, uint8_t size ) const {
	if ( !is_within_stack_bounds ( address, size ) ) {
		uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( );
		GuestExceptionInfo ex;
		ex.set_access_violation ( faulting_rip, address, false ); // Read violation outside stack
		throw ex;
	}

	return *( uint64_t* ) ( address );
}

uint128_t EmulationContext::get_stack_128 ( uint64_t address ) const {
	if ( !is_within_stack_bounds ( address, 16 ) ) {
		uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( );
		GuestExceptionInfo ex;
		ex.set_access_violation ( faulting_rip, address, false ); // Read violation outside stack
		throw ex;
	}

	return *( uint128_t* ) ( address );
}

void EmulationContext::set_stack ( uint64_t address, uint64_t val, InstructionEffect& effect, uint8_t size ) {
	if ( !is_within_stack_bounds ( address, size ) ) {
		uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( ); // RIP of instruction *causing* access
		GuestExceptionInfo ex;
		// Writing outside allocated stack region typically triggers Stack Overflow semantically
		ex.set_exception ( EXCEPTION_STACK_OVERFLOW, faulting_rip, address );
		throw ex;
	}

	void* ptr = reinterpret_cast< void* >( address );
	uint64_t old_val_preview = 0; // For logging
	if ( options.enable_logging ) { // Read old value only if logging
		memcpy ( &old_val_preview, ptr, size > 8 ? 8 : size ); // Preview up to 8 bytes
	}

	switch ( size ) {
		case 1: *static_cast< uint8_t* >( ptr ) = static_cast< uint8_t >( val ); break;
		case 2: *static_cast< uint16_t* >( ptr ) = static_cast< uint16_t >( val ); break;
		case 4: *static_cast< uint32_t* >( ptr ) = static_cast< uint32_t >( val ); break;
		case 8: *static_cast< uint64_t* >( ptr ) = val; break;
		default:
		{
			uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( );
			std::println ( "INTERNAL ERROR: Unsupported write size ({}) to stack @ 0x{:X}", size, address );
			GuestExceptionInfo ex;
			ex.set_exception ( 0xDEADBABE, faulting_rip );
			throw ex;
		}
	}

	// Log stack change uses a different function signature in context.hpp
		// log_stack_change(effect, address, old_val_preview, val, size); // Adapt if logging needed
	if ( options.enable_logging ) {
		effect.push_to_changes ( this, std::format ( "[STACK:0x{:016x}] = 0x{:x} (size={})", address, val, size ) );
	}
	effect.modified_mem.insert ( address );
}
void EmulationContext::set_stack_128 ( uint64_t address, uint128_t val, InstructionEffect& effect ) {
	if ( !is_within_stack_bounds ( address, 16 ) ) {
		uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( ); // RIP of instruction *causing* access
		GuestExceptionInfo ex;
		// Writing outside allocated stack region typically triggers Stack Overflow semantically
		ex.set_exception ( EXCEPTION_STACK_OVERFLOW, faulting_rip, address );
		throw ex;
	}

	void* ptr = reinterpret_cast< void* >( address );
	*( uint128_t* ) ptr = val;

	if ( options.enable_logging ) {
		effect.push_to_changes ( this, std::format ( "[STACK:0x{:016x}] = 0x{} (size=16)", address, val.str ( ) ) );
	}
	effect.modified_mem.insert ( address );
}

uint64_t dereference_by_size ( const uint8_t* ptr, size_t size ) noexcept {
	switch ( size ) {
		case 1: return static_cast< uint64_t >( *ptr );
		case 2: return static_cast< uint64_t >( *reinterpret_cast< const uint16_t* >( ptr ) );
		case 4: return static_cast< uint64_t >( *reinterpret_cast< const uint32_t* >( ptr ) );
		case 8: return *reinterpret_cast< const uint64_t* >( ptr );
		default:
			std::print ( "Unsupported read size {:#x} at KUSER_SHARED_DATA {:#x}h\n", size, reinterpret_cast< uint64_t >( ptr ) );
			return 0ULL;
	}
}
void EmulationContext::allocate_kuser_shared_data ( InstructionEffect& effect ) {
	if ( options.enable_logging ) {
		effect.push_to_changes ( this, std::format ( "KUSER_SHARED_DATA allocated at 0x{:016x}, ProcessorFeatures set at 0x{:016x}", KUSER_SHARED_DATA_BASE, KUSER_SHARED_DATA_BASE + 0x3C0 ) );
	}
}

void EmulationContext::set_rcx_to_ioport ( uint16_t port, InstructionEffect& effect ) {
	uint64_t port_value = windows->io_ports.count ( port ) ? windows->io_ports [ port ] : 0;
	set_reg ( X86_REG_RCX, port_value, 8, effect );
	if ( options.enable_logging ) {
		effect.push_to_changes ( this, std::format ( "RCX set to I/O port 0x{:04x} value: 0x{:x}", port, port_value ) );
	}
}
uint64_t EmulationContext::get_memory ( uint64_t addr, uint8_t size ) const {
	uint64_t faulting_rip = 0;
	if ( decoder.back ( )->last_successful_ip ( ) != 0 && decoder.back ( )->last_successful_ip ( ) < 0x7FFFFFFFFFFF ) {
		faulting_rip = decoder.back ( )->last_successful_ip ( );
	}

	if ( addr < 0x1000 ) {
		GuestExceptionInfo ex;
		ex.set_access_violation ( faulting_rip, addr, false );
		throw ex;
	}

	if ( addr >= KUSER_SHARED_DATA_BASE && addr < KUSER_SHARED_DATA_END ) {
		return *( uint64_t* ) addr;
	}

	if ( is_within_stack_bounds ( addr, size ) ) {
		return get_stack ( addr, size );
	}

	// Loaded Modules Check
	for ( const auto& [base, mod] : windows->loaded_modules ) {
		if ( addr >= mod.base_address && addr < mod.base_address + mod.size ) {
			if ( addr + size > mod.base_address + mod.size ) {
				GuestExceptionInfo ex;
				ex.set_access_violation ( faulting_rip, addr, false );
				throw ex;
			}
			try {
				const uint8_t* ptr = reinterpret_cast< const uint8_t* >( addr );
				return dereference_by_size ( ptr, size );
			}
			catch ( ... ) {
				GuestExceptionInfo ex;
				ex.set_access_violation ( faulting_rip, addr, false );
				throw ex;
			}
		}
	}
	if ( !IsBadReadPtr ( reinterpret_cast< const void* >( addr ), 8 ) ) {
		auto value = *( uint64_t* ) addr;
		return value;
	}

	GuestExceptionInfo ex;
	ex.set_access_violation ( faulting_rip, addr, false );
	throw ex;
}

void EmulationContext::set_memory ( uint64_t addr, uint64_t val, uint8_t size, InstructionEffect& effect ) {
	uint64_t faulting_rip = decoder.back ( )->last_successful_ip ( );

	if ( addr < 0x1000 ) {
		GuestExceptionInfo ex;
		ex.set_access_violation ( faulting_rip, addr, true );
		throw ex;
	}

	if ( is_within_stack_bounds ( addr, size ) ) {
		return set_stack ( addr, val, effect, size );
	}

	if ( IsBadWritePtr ( ( void* ) addr, size ) ) {
		GuestExceptionInfo ex;
		ex.set_access_violation ( faulting_rip, addr, true );
		throw ex;
	}

	try {
		void* ptr = reinterpret_cast< void* >( addr );
		uint64_t old_val_preview = 0;
		if ( options.enable_logging ) memcpy ( &old_val_preview, ptr, size > 8 ? 8 : size );

		switch ( size ) {
			case 1: *static_cast< uint8_t* >( ptr ) = static_cast< uint8_t >( val ); break;
			case 2: *static_cast< uint16_t* >( ptr ) = static_cast< uint16_t >( val ); break;
			case 4: *static_cast< uint32_t* >( ptr ) = static_cast< uint32_t >( val ); break;
			case 8: *static_cast< uint64_t* >( ptr ) = val; break;
			default:
			{
				std::println ( "INTERNAL ERROR: Unsupported write size ({}) to module memory @ 0x{:X}", size, addr );
				GuestExceptionInfo ex;
				ex.set_exception ( 0xDEADBABE, faulting_rip );
				throw ex;
			}
		}

		if ( options.enable_logging ) {
			effect.push_to_changes ( this, std::format ( "[MODULE:0x{:016x}] = 0x{:x} (size={})", addr, val, size ) );
		}
		windows->memory_writes [ addr ].push_back ( val );
		return;

	}
	catch ( ... ) {
		GuestExceptionInfo ex;
		ex.set_access_violation ( faulting_rip, addr, true );
		throw ex;
	}
	GuestExceptionInfo ex;
	ex.set_access_violation ( faulting_rip, addr, true );
	throw ex;
}

void EmulationContext::allocate_stack ( int64_t size, InstructionEffect& effect ) noexcept {
	uint64_t old_rsp = get_reg ( X86_REG_RSP );
	uint64_t new_rsp = old_rsp - static_cast< uint64_t >( size );
	set_reg ( X86_REG_RSP, new_rsp, 8, effect );

	stack_allocated += size;
	if ( options.enable_logging ) {
		effect.changes.push_back (
				std::format ( "allocate_stack: reserved {} bytes, newstate.rsp_offset= {}", size, cpu->rsp_offset )
		);
	}
}


void EmulationContext::increment_tsc ( ) {
	cpu->tsc += 3;
}

void EmulationContext::push_call_frame ( uint64_t ret_addr, InstructionEffect& effect ) {
	CallFrame frame {};
	frame.rsp_before_call = get_reg ( X86_REG_RSP ); // RSP *after* CALL pushed ret addr
	frame.return_addr = ret_addr;

	call_stack.push_back ( frame );
	if ( options.enable_logging ) {
		effect.push_to_changes ( this, std::format ( "Pushed call frame: return addr=0x{:016x}, RSP_after_push=0x{:016x}", ret_addr, frame.rsp_before_call ) );
	}
}

void EmulationContext::pop_call_frame ( InstructionEffect& effect ) {
	if ( call_stack.empty ( ) ) {
		std::println ( "Pop call frame with empty call stack (allowed)" );
		if ( options.enable_logging ) {
			effect.push_to_changes ( this, "Pop call frame with empty call stack" );
		}
		return;
	}

	CallFrame frame = call_stack.back ( );
	call_stack.pop_back ( );

	if ( options.enable_logging ) {
		effect.push_to_changes ( this, std::format ( "Popped call frame: return addr=0x{:016x}", frame.return_addr ) );
	}
}

uint32_t EmulationContext::get_eflags ( ) const noexcept {
	uint32_t eflags = 0;
	const auto& flags = cpu->cpu_flags.flags;

	eflags |= ( flags.CF & 1 );
	eflags |= ( options.allow_reserved_write ? flags.reserved1 : 1 ) << 1;
	eflags |= flags.PF << 2;
	eflags |= ( options.allow_reserved_write ? flags.reserved2 : 0 ) << 3;
	eflags |= flags.AF << 4;
	eflags |= ( options.allow_reserved_write ? flags.reserved3 : 1 ) << 5;
	eflags |= flags.ZF << 6;
	eflags |= flags.SF << 7;
	eflags |= flags.TF << 8;
	eflags |= flags.IF << 9;
	eflags |= flags.DF << 10;
	eflags |= flags.OF << 11;
	eflags |= flags.IOPL << 12;
	eflags |= flags.NT << 14;
	eflags |= ( options.allow_reserved_write ? flags.reserved4 : 0 ) << 15;
	eflags |= flags.RF << 16;
	eflags |= flags.VM << 17;
	eflags |= flags.AC << 18;
	eflags |= flags.VIF << 19;
	eflags |= flags.VIP << 20;
	eflags |= flags.ID << 21;
	eflags |= flags.reserved5 << 22;
	return eflags;
}

uint64_t EmulationContext::get_rflags ( ) const noexcept {
	const auto& flags = cpu->cpu_flags.flags;
	return ( uint64_t ( flags.CF & 1 ) ) |
		( uint64_t ( options.allow_reserved_write ? flags.reserved1 : 1 ) << 1 ) |  // Reserved1 always 1
		( uint64_t ( flags.PF ) << 2 ) |
		( uint64_t ( options.allow_reserved_write ? flags.reserved2 : 0 ) << 3 ) |  // Reserved2 always 0
		( uint64_t ( flags.AF ) << 4 ) |
		( uint64_t ( options.allow_reserved_write ? flags.reserved3 : 0 ) << 5 ) |  // Reserved3 always 0
		( uint64_t ( flags.ZF ) << 6 ) |
		( uint64_t ( flags.SF ) << 7 ) |
		( uint64_t ( flags.TF ) << 8 ) |
		( uint64_t ( flags.IF ) << 9 ) |
		( uint64_t ( flags.DF ) << 10 ) |
		( uint64_t ( flags.OF ) << 11 ) |
		( uint64_t ( flags.IOPL ) << 12 ) |
		( uint64_t ( flags.NT ) << 14 ) |
		( uint64_t ( options.allow_reserved_write ? flags.reserved4 : 0 ) << 15 ) |  // Reserved4 always 0
		( uint64_t ( flags.RF ) << 16 ) |
		( uint64_t ( flags.VM ) << 17 ) |
		( uint64_t ( flags.AC ) << 18 ) |
		( uint64_t ( flags.VIF ) << 19 ) |
		( uint64_t ( flags.VIP ) << 20 ) |
		( uint64_t ( flags.ID ) << 21 ) |
		( uint64_t ( flags.reserved5 ) << 22 ) |
		( uint64_t ( flags.reserved6 ) << 32 );
}

void EmulationContext::set_rflags ( uint64_t rflags, InstructionEffect& effect ) noexcept {
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF;
	uint64_t old_PF = flags.PF;
	uint64_t old_AF = flags.AF;
	uint64_t old_ZF = flags.ZF;
	uint64_t old_SF = flags.SF;
	uint64_t old_TF = flags.TF;
	uint64_t old_IF = flags.IF;
	uint64_t old_DF = flags.DF;
	uint64_t old_OF = flags.OF;
	uint64_t old_AC = flags.AC;

	flags.CF = ( rflags >> 0 ) & 1;  
	flags.PF = ( rflags >> 2 ) & 1;  
	flags.AF = ( rflags >> 4 ) & 1;  
	flags.ZF = ( rflags >> 6 ) & 1;  
	flags.SF = ( rflags >> 7 ) & 1;  
	flags.TF = ( rflags >> 8 ) & 1;  
	flags.DF = ( rflags >> 10 ) & 1; 
	flags.OF = ( rflags >> 11 ) & 1; 
	flags.AC = ( rflags >> 18 ) & 1; 
	if ( options.allow_reserved_write ) {
		flags.reserved1 = ( rflags >> 1 ) & 1;
		flags.reserved2 = ( rflags >> 3 ) & 1;
		flags.reserved3 = ( rflags >> 5 ) & 1;
		flags.reserved4 = ( rflags >> 15 ) & 1;
		flags.reserved5 = ( rflags >> 22 ) & 0x3FF;
		flags.reserved6 = ( rflags >> 32 ) & 0xFFFFFFFF;
	}

	if ( cpu->current_privilege_level == 0 ) {
		if ( cpu->current_privilege_level <= flags.IOPL ) {
			uint64_t old_IF = flags.IF;
			flags.IF = ( rflags >> 9 ) & 1;
			if ( old_IF != flags.IF ) log_flag_change ( effect, "IF", old_IF, flags.IF );
		}

		flags.IOPL = ( rflags >> 12 ) & 3;  
		flags.NT = ( rflags >> 14 ) & 1;    
		flags.RF = ( rflags >> 16 ) & 1;    
		flags.VM = ( rflags >> 17 ) & 1;    
		flags.VIF = ( rflags >> 19 ) & 1;   
		flags.VIP = ( rflags >> 20 ) & 1;   
		if ( options.allow_reserved_write ) {
			flags.ID = ( rflags >> 21 ) & 1;
		}
	}

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_AF != flags.AF ) log_flag_change ( effect, "AF", old_AF, flags.AF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_TF != flags.TF ) log_flag_change ( effect, "TF", old_TF, flags.TF );
	if ( old_DF != flags.DF ) log_flag_change ( effect, "DF", old_DF, flags.DF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AC != flags.AC ) log_flag_change ( effect, "AC", old_AC, flags.AC );
}

void EmulationContext::set_eflags ( uint32_t eflags, InstructionEffect& effect ) noexcept {
	set_rflags ( eflags, effect );
}
#include <Windows.h>
#include <semantics/src/pch.hpp>

#define CONTEXT_X86_MAIN           0x00010000
#define CONTEXT_AMD64_MAIN         0x100000
#define CONTEXT_CONTROL_32         (CONTEXT_X86_MAIN | 0x1L)
#define CONTEXT_CONTROL_64         (CONTEXT_AMD64_MAIN | 0x1L)
#define CONTEXT_INTEGER_32         (CONTEXT_X86_MAIN | 0x2L)
#define CONTEXT_INTEGER_64         (CONTEXT_AMD64_MAIN | 0x2L)
#define CONTEXT_SEGMENTS_32        (CONTEXT_X86_MAIN | 0x4L)
#define CONTEXT_SEGMENTS_64        (CONTEXT_AMD64_MAIN | 0x4L)
#define CONTEXT_FLOATING_POINT_32  (CONTEXT_X86_MAIN | 0x8L)
#define CONTEXT_FLOATING_POINT_64  (CONTEXT_AMD64_MAIN | 0x8L)
#define CONTEXT_DEBUG_REGISTERS_32 (CONTEXT_X86_MAIN | 0x10L)
#define CONTEXT_DEBUG_REGISTERS_64 (CONTEXT_AMD64_MAIN | 0x10L)
#define CONTEXT_XSTATE_32          (CONTEXT_X86_MAIN | 0x20L)
#define CONTEXT_XSTATE_64          (CONTEXT_AMD64_MAIN | 0x20L)

#define CONTEXT64_ALL                                                                            \
    (CONTEXT_CONTROL_64 | CONTEXT_INTEGER_64 | CONTEXT_SEGMENTS_64 | CONTEXT_FLOATING_POINT_64 | \
     CONTEXT_DEBUG_REGISTERS_64)
// thank you sogen!
void EmulationContext::save_context ( CONTEXT* context ) {
	if ( ( context->ContextFlags & CONTEXT_DEBUG_REGISTERS_64 ) == CONTEXT_DEBUG_REGISTERS_64 ) {
		context->Dr0 = get_reg<uint64_t> ( x86_reg::X86_REG_DR0 );
		context->Dr1 = get_reg<uint64_t> ( x86_reg::X86_REG_DR1 );
		context->Dr2 = get_reg<uint64_t> ( x86_reg::X86_REG_DR2 );
		context->Dr3 = get_reg<uint64_t> ( x86_reg::X86_REG_DR3 );
		context->Dr6 = get_reg<uint64_t> ( x86_reg::X86_REG_DR6 );
		context->Dr7 = get_reg<uint64_t> ( x86_reg::X86_REG_DR7 );
	}

	if ( ( context->ContextFlags & CONTEXT_CONTROL_64 ) == CONTEXT_CONTROL_64 ) {
		context->SegSs = get_reg<uint16_t> ( x86_reg::X86_REG_SS );
		context->SegCs = get_reg<uint16_t> ( x86_reg::X86_REG_CS );
		context->Rip = get_reg<uint64_t> ( x86_reg::X86_REG_RIP );
		context->Rsp = get_reg<uint64_t> ( x86_reg::X86_REG_RSP );
		context->EFlags = get_eflags ( );
	}

	if ( ( context->ContextFlags & CONTEXT_INTEGER_64 ) == CONTEXT_INTEGER_64 ) {
		context->Rax = get_reg<uint64_t> ( x86_reg::X86_REG_RAX );
		context->Rbx = get_reg<uint64_t> ( x86_reg::X86_REG_RBX );
		context->Rcx = get_reg<uint64_t> ( x86_reg::X86_REG_RCX );
		context->Rdx = get_reg<uint64_t> ( x86_reg::X86_REG_RDX );
		context->Rbp = get_reg<uint64_t> ( x86_reg::X86_REG_RBP );
		context->Rsi = get_reg<uint64_t> ( x86_reg::X86_REG_RSI );
		context->Rdi = get_reg<uint64_t> ( x86_reg::X86_REG_RDI );
		context->R8 = get_reg<uint64_t> ( x86_reg::X86_REG_R8 );
		context->R9 = get_reg<uint64_t> ( x86_reg::X86_REG_R9 );
		context->R10 = get_reg<uint64_t> ( x86_reg::X86_REG_R10 );
		context->R11 = get_reg<uint64_t> ( x86_reg::X86_REG_R11 );
		context->R12 = get_reg<uint64_t> ( x86_reg::X86_REG_R12 );
		context->R13 = get_reg<uint64_t> ( x86_reg::X86_REG_R13 );
		context->R14 = get_reg<uint64_t> ( x86_reg::X86_REG_R14 );
		context->R15 = get_reg<uint64_t> ( x86_reg::X86_REG_R15 );
	}

	if ( ( context->ContextFlags & CONTEXT_SEGMENTS_64 ) == CONTEXT_SEGMENTS_64 ) {
		context->SegDs = get_reg<uint16_t> ( x86_reg::X86_REG_DS );
		context->SegEs = get_reg<uint16_t> ( x86_reg::X86_REG_ES );
		context->SegFs = get_reg<uint16_t> ( x86_reg::X86_REG_FS );
		context->SegGs = get_reg<uint16_t> ( x86_reg::X86_REG_GS );
	}

	if ( ( context->ContextFlags & CONTEXT_FLOATING_POINT_64 ) == CONTEXT_FLOATING_POINT_64 ) {
		context->FltSave.ControlWord = cpu->fpu.fpu_control_word;
		context->FltSave.StatusWord = cpu->fpu.fpu_status_word;
		context->FltSave.TagWord = static_cast<BYTE>(cpu->fpu.fpu_tag_word);
		// windows float register types are incompatible with float80_t
		//for ( int i = 0; i < 8; i++ ) {
		//	const auto reg = static_cast< x86_register > ( static_cast< int > ( x86_reg::X86_REG_st0 ) + i );
		//	context.FltSave.FloatRegisters [ i ] = emu.reg<M128A> ( reg );
		//}
	}

	if ( ( context->ContextFlags & CONTEXT_INTEGER_64 ) == CONTEXT_INTEGER_64 ) {
		context->MxCsr = *reinterpret_cast<DWORD*>(&cpu->cpu_flags.mxcsr);
		for ( int i = 0; i < 16; i++ ) {
			const auto reg = static_cast< x86_reg > ( static_cast< int > ( x86_reg::X86_REG_XMM0 ) + i );
			const auto value = get_xmm_raw ( reg );
			M128A xmm {};
			xmm.Low = ( value & 0xFFFFFFFFFFFFFFFFULL ).convert_to<ULONGLONG> ( );
			xmm.High = ( value >> 64 ).convert_to<LONGLONG> ( );
			( &context->Xmm0 ) [ i ] = xmm;
		}
	}
}


template <typename T>
T& get_subword ( uint64_t& reg ) noexcept {
	static_assert( sizeof ( T ) <= sizeof ( uint64_t ), "Type too large for register" );
	return reinterpret_cast< T& >( reg );
}

template <typename T>
const T& EmulationContext::get_reg ( x86_reg reg ) const {
	static_assert( sizeof ( T ) <= sizeof ( uint64_t ), "this type does not fit in general purpose registers" );
	return reinterpret_cast< const T& >( this->cpu->registers [ reg_map [ reg ] ] );
}

template <typename T>
T& EmulationContext::get_reg_mut ( x86_reg reg ) {
	static_assert( sizeof ( T ) <= sizeof ( uint64_t ), "this type does not fit in general purpose registers" );
	return get_subword<T> ( this->cpu->registers [ reg_map [ reg ] ] );
}


uint128_t EmulationContext::get_xmm_raw ( x86_reg _reg ) const {
	auto reg = avx_map [ _reg ];
	uint512_t value = ( *cpu->avx_registers ) [ reg ];
	return value.convert_to<uint128_t> ( );
}

void EmulationContext::set_xmm_raw ( x86_reg _reg, const uint128_t& value, InstructionEffect& effect ) {
	auto reg = avx_map [ _reg ];
	( *cpu->avx_registers ) [ reg ] = value;
}

uint256_t EmulationContext::get_ymm_raw ( x86_reg _reg ) const {
	auto reg = avx_map [ _reg ];
	uint512_t value = ( *cpu->avx_registers ) [ reg ];
	return value.convert_to<uint256_t> ( );
}

void EmulationContext::set_ymm_raw ( x86_reg _reg, const uint256_t& value, InstructionEffect& effect ) {
	auto reg = avx_map [ _reg ];
	( *cpu->avx_registers ) [ reg ] = value;
}

uint512_t EmulationContext::get_zmm_raw ( x86_reg _reg ) const {
	auto reg = avx_map [ _reg ];
	uint512_t value = ( *cpu->avx_registers ) [ reg ];
	return value;
}

void EmulationContext::set_zmm_raw ( x86_reg _reg, const uint512_t& value, InstructionEffect& effect ) {
	auto reg = avx_map [ _reg ];
	( *cpu->avx_registers ) [ reg ] = value;
}

float EmulationContext::get_xmm_float ( x86_reg reg ) const {
	uint128_t raw = get_xmm_raw ( reg );
	uint32_t low_bits = static_cast< uint32_t >( raw & 0xFFFFFFFF );
	return std::bit_cast< float >( low_bits );
}

void EmulationContext::set_xmm_float ( x86_reg reg, float value, InstructionEffect& effect ) {
	uint128_t current_raw = get_xmm_raw ( reg );
	uint32_t new_low_bits = std::bit_cast< uint32_t >( value );
	current_raw = ( current_raw & ~uint128_t ( 0xFFFFFFFF ) ) | uint128_t ( new_low_bits );
	set_xmm_raw ( reg, current_raw, effect );
	effect.modified_regs.insert ( reg );
}

double EmulationContext::get_xmm_double ( x86_reg reg ) const {
	uint128_t raw = get_xmm_raw ( reg );
	uint64_t low_bits = static_cast< uint64_t >( raw & 0xFFFFFFFFFFFFFFFF );
	return std::bit_cast< double >( low_bits );
}

void EmulationContext::set_xmm_double ( x86_reg reg, double value, InstructionEffect& effect ) {
	uint128_t current_raw = get_xmm_raw ( reg );
	uint64_t new_low_bits = std::bit_cast< uint64_t >( value );
	current_raw = ( current_raw & ~uint128_t ( 0xFFFFFFFFFFFFFFFF ) ) | uint128_t ( new_low_bits );
	set_xmm_raw ( reg, current_raw, effect );
	effect.modified_regs.insert ( reg );
}

uint128_t EmulationContext::get_memory_128 ( uint64_t addr ) const {
	// Read low 64 bits, then high 64 bits
	uint64_t low = get_memory ( addr, 8 );
	uint64_t high = get_memory ( addr + 8, 8 );
	return ( uint128_t ( high ) << 64 ) | low;
}

void EmulationContext::set_memory_128 ( uint64_t addr, const uint128_t& val, InstructionEffect& effect ) {
	// Write low 64 bits, then high 64 bits
	uint64_t low = static_cast< uint64_t >( val & 0xFFFFFFFFFFFFFFFF );
	uint64_t high = static_cast< uint64_t >( val >> 64 );
	set_memory ( addr, low, 8, effect );
	set_memory ( addr + 8, high, 8, effect );
}

uint256_t EmulationContext::get_memory_256 ( uint64_t addr ) const {
	// Read four 64-bit chunks
	uint64_t p0 = get_memory ( addr + 0, 8 );
	uint64_t p1 = get_memory ( addr + 8, 8 );
	uint64_t p2 = get_memory ( addr + 16, 8 );
	uint64_t p3 = get_memory ( addr + 24, 8 );
	return ( uint256_t ( p3 ) << 192 ) | ( uint256_t ( p2 ) << 128 ) | ( uint256_t ( p1 ) << 64 ) | uint256_t ( p0 );
}

void EmulationContext::set_memory_256 ( uint64_t addr, const uint256_t& val, InstructionEffect& effect ) {
	// Write four 64-bit chunks
	uint64_t p0 = static_cast< uint64_t >( val & 0xFFFFFFFFFFFFFFFFULL );
	uint64_t p1 = static_cast< uint64_t >( ( val >> 64 ) & 0xFFFFFFFFFFFFFFFFULL );
	uint64_t p2 = static_cast< uint64_t >( ( val >> 128 ) & 0xFFFFFFFFFFFFFFFFULL );
	uint64_t p3 = static_cast< uint64_t >( ( val >> 192 ) & 0xFFFFFFFFFFFFFFFFULL );
	set_memory ( addr + 0, p0, 8, effect );
	set_memory ( addr + 8, p1, 8, effect );
	set_memory ( addr + 16, p2, 8, effect );
	set_memory ( addr + 24, p3, 8, effect );
}

uint512_t EmulationContext::get_memory_512 ( uint64_t addr ) const {
	// Read eight 64-bit chunks
	uint64_t p0 = get_memory ( addr + 0, 8 );
	uint64_t p1 = get_memory ( addr + 8, 8 );
	uint64_t p2 = get_memory ( addr + 16, 8 );
	uint64_t p3 = get_memory ( addr + 24, 8 );
	uint64_t p4 = get_memory ( addr + 32, 8 );
	uint64_t p5 = get_memory ( addr + 40, 8 );
	uint64_t p6 = get_memory ( addr + 48, 8 );
	uint64_t p7 = get_memory ( addr + 56, 8 );
	return ( uint512_t ( p7 ) << 448 ) | ( uint512_t ( p6 ) << 384 ) | ( uint512_t ( p5 ) << 320 ) | ( uint512_t ( p4 ) << 256 ) |
		( uint512_t ( p3 ) << 192 ) | ( uint512_t ( p2 ) << 128 ) | ( uint512_t ( p1 ) << 64 ) | uint512_t ( p0 );
}

void EmulationContext::set_memory_512 ( uint64_t addr, const uint512_t& val, InstructionEffect& effect ) {
	for ( int i = 0; i < 8; ++i ) {
		set_memory ( addr + ( i * 8 ), static_cast< uint64_t > ( ( val >> ( i * 64 ) ) & 0xFFFFFFFFFFFFFFFFULL ), 8, effect );
	}
}

static constexpr uint64_t CR0_AM_BIT = 1ULL << 18;
bool EmulationContext::is_alignment_check_enabled ( ) const noexcept {
	auto cr0_val = get_reg ( X86_REG_CR0, 8 );
	bool cr0_am = ( cr0_val & CR0_AM_BIT ) != 0;
	return cr0_am && cpu->cpu_flags.flags.AC && cpu->current_privilege_level == 3;
}

float80_t EmulationContext::read_float80_from_memory ( uint64_t addr, InstructionEffect& effect ) {
	uint64_t significand_bits = get_memory ( addr, 8 );
	uint16_t exponent_sign_bits = static_cast< uint16_t >( get_memory ( addr + 8, 2 ) );

	bool sign = ( exponent_sign_bits >> 15 ) & 1;
	int16_t exponent_raw = exponent_sign_bits & 0x7FFF;

	if ( exponent_raw == 0x7FFF ) {
		bool is_quiet_nan = ( significand_bits >> 62 ) & 1;
		if ( ( ( significand_bits >> 63 ) & 1 ) == 0 && significand_bits << 1 == 0 ) {
			// Intel Manual Vol 1, Section 8.3.7 differentiates Inf from NaN this way.
			return sign ? -std::numeric_limits<float80_t>::infinity ( ) : std::numeric_limits<float80_t>::infinity ( );
		}
		else {
			return std::numeric_limits<float80_t>::quiet_NaN ( );
		}
	}
	else if ( exponent_raw == 0 ) {
		if ( significand_bits == 0 ) {
			return float80_t ( 0.0 ); // Loses sign info potentially
		}
		else {
			int exponent_unbiased = 1 - 16383;
			float80_t significand_val = significand_bits;
			significand_val /= boost::multiprecision::pow ( float80_t ( 2 ), 64 );
			float80_t result = boost::multiprecision::ldexp ( significand_val, exponent_unbiased );
			return sign ? -result : result;
		}
	}
	else {
		if ( !( ( significand_bits >> 63 ) & 1 ) ) {
			effect.push_to_changes ( *this, "Warning: Reading potentially invalid 80-bit normalized number (integer bit is 0)" );
		}
		int exponent_unbiased = exponent_raw - 16383; // Unbias exponent
		float80_t significand_val = significand_bits;
		significand_val /= boost::multiprecision::pow ( float80_t ( 2 ), 63 );
		float80_t result = boost::multiprecision::ldexp ( significand_val, exponent_unbiased );
		return sign ? -result : result;
	}
}

void EmulationContext::write_float80_to_memory ( uint64_t addr, const float80_t& val, InstructionEffect& effect ) {
	using namespace boost::multiprecision;

	uint64_t significand_bits = 0;
	uint16_t exponent_sign_bits = 0;
	bool sign = val < 0;

	int classification = fpclassify ( val );

	if ( classification == FP_INFINITE ) {
		exponent_sign_bits = 0x7FFF;
		significand_bits = 0x8000000000000000ULL;
	}
	else if ( classification == FP_NAN ) {
		exponent_sign_bits = 0x7FFF;
		significand_bits = 0xC000000000000000ULL;
	}
	else if ( classification == FP_ZERO ) {
		exponent_sign_bits = 0;
		significand_bits = 0;
	}
	else {
		int exponent_unbiased;
		float80_t significand_normalized = frexp ( val, &exponent_unbiased );

		int exponent_biased = exponent_unbiased + 16383 - 1; // Adjust exponent and bias. -1 because frexp gives [0.5, 1)

		if ( exponent_biased <= 0 ) { // Denormal or underflowed to zero (Zero already handled)
			// Denormal case: Adjust exponent and shift significand
			exponent_biased = 0; // Exponent field is 0
			// Significand = M * 2^(exponent_unbiased) * 2^(64 - (1-16383))
			// This requires careful scaling to get the raw bits with implicit integer bit 0
			float80_t scaled_sig = ldexp ( val, 64 - ( 1 - 16383 ) ); // Scale denormal value appropriately
			significand_bits = scaled_sig.convert_to<uint64_t> ( ); // Approximate conversion

			effect.push_to_changes ( *this, "Warning: Writing denormal 80-bit float - precision may be lost." );

		}
		else if ( exponent_biased >= 0x7FFF ) { // Overflow (Infinity already handled)
			// Should not happen if Infinity case was correct
			exponent_sign_bits = 0x7FFF;
			significand_bits = 0x8000000000000000ULL;
			effect.push_to_changes ( *this, "Warning: Overflow during 80-bit float write conversion." );
		}
		else { // Normalized Case
			// Scale significand M (in [0.5, 1.0)) to have explicit integer bit 1 at position 63
			// M * 2^64 should yield the significand bits directly if M is in [0.5, 1.0)
			float80_t scaled_significand = ldexp ( significand_normalized, 64 );
			significand_bits = scaled_significand.convert_to<uint64_t> ( );
			// Ensure explicit integer bit is set (it should be by frexp/ldexp)
			significand_bits |= ( 1ULL << 63 );
			exponent_sign_bits = static_cast< uint16_t >( exponent_biased );
		}
	}

	// Set the sign bit
	if ( sign ) {
		exponent_sign_bits |= ( 1 << 15 );
	}

	// Write the 10 bytes
	set_memory ( addr, significand_bits, 8, effect );
	set_memory ( addr + 8, exponent_sign_bits, 2, effect );
}

void EmulationContext::initialize_exception_table ( ) noexcept {
	// --- Data Movement Instructions ---
	// MOV (mem read/write, alignment checks, FS/GS possible)
	g_instruction_exception_table [ X86_INS_MOV ] = {
			.categories = {.MEMORY = true, .ALIGNMENT = true }
			// Note: MOV to/from CRn/DRn/Segment Regs is privileged
	};
	g_instruction_exception_table [ X86_INS_MOVABS ] = { // MOVABS reg, imm (no mem)
			.categories = {}
	};
	g_instruction_exception_table [ X86_INS_MOVAPS ] = { // SSE aligned move (mem read/write, intrinsic align, SSE state)
			.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
			.is_sse_avx_related = true, .requires_intrinsic_alignment = true, .intrinsic_alignment_bytes = 16
	};
	g_instruction_exception_table [ X86_INS_MOVUPS ] = { // SSE unaligned move (mem read/write, AC align possible, SSE state)
			.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
			.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_MOVQ ] = { // MMX/SSE64 move (mem read/write, AC align possible, MMX/SSE state)
		 .categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
		 .is_mmx_related = true, .is_sse_avx_related = true // Can target GP or XMM/MMX
	};
	g_instruction_exception_table [ X86_INS_MOVZX ] = { // Zero-extend move (mem read possible, alignment)
			.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_MOVSX ] = { // Sign-extend move (mem read possible, alignment)
		 .categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_MOVSXD ] = { // Sign-extend doubleword to quadword (mem read possible, alignment)
			.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_PUSH ] = { // Stack write, maybe mem read, stack align/bounds
			.categories = {.MEMORY = true, .STACK = true, .ALIGNMENT = true },
			.is_explicit_push = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_PUSHFQ ] = { // Stack write, stack align/bounds
			.categories = {.STACK = true, .ALIGNMENT = true },
			.is_explicit_push = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_POP ] = { // Stack read, maybe mem write, stack align/bounds
			.categories = {.MEMORY = true, .STACK = true, .ALIGNMENT = true },
			.is_explicit_pop = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_POPFQ ] = { // Stack read, stack align/bounds, potentially privileged flag changes
			.categories = {.STACK = true, .ALIGNMENT = true }, // Add INVALID_USAGE if simulating privilege checks for flags like IF/IOPL
			.is_explicit_pop = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_LEA ] = { // Address calculation, no memory access itself, but uses mem operand syntax
			.categories = {.MEMORY = true } // Category needed to trigger FS/GS NULL check if used in address
	};
	g_instruction_exception_table [ X86_INS_SAHF ] = { // Loads AH into flags
			.categories = {}
	};
	g_instruction_exception_table [ X86_INS_LAHF ] = { // Stores flags into AH
			.categories = {}
	};
	g_instruction_exception_table [ X86_INS_XCHG ] = { // Mem read/write, alignment, lock possible
			.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true },
			.lock_prefix_allowed = true
	};
	// STOS variants (mem write, use RDI/ES, REP prefix interaction)
	g_instruction_exception_table [ X86_INS_STOSB ] =
		g_instruction_exception_table [ X86_INS_STOSW ] =
		g_instruction_exception_table [ X86_INS_STOSD ] =
		g_instruction_exception_table [ X86_INS_STOSQ ] = {
				.categories = {.MEMORY = true, .ALIGNMENT = true }, // Uses ES:RDI implicitly, host OS handles segment violation
				.uses_string_registers = true
				// REP prefix handling is usually dynamic
	};
	// MOVS variants (mem read/write, use RSI/DS, RDI/ES, REP prefix interaction)
	g_instruction_exception_table [ X86_INS_MOVSB ] =
		g_instruction_exception_table [ X86_INS_MOVSW ] =
		g_instruction_exception_table [ X86_INS_MOVSD ] = // Note: MOVSD is also SSE double scalar move
		g_instruction_exception_table [ X86_INS_MOVSQ ] = {
				.categories = {.MEMORY = true, .ALIGNMENT = true }, // Uses DS:RSI, ES:RDI
				.uses_string_registers = true
	};
	// SSE MOVSD (Scalar Double)
	g_instruction_exception_table [ X86_INS_MOVSD ] = { // Overwrite string op entry if capstone ID conflicts
			.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
			.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_MOVSS ] = { // SSE scalar single
			.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
			.is_sse_avx_related = true
	};


	// --- Arithmetic Instructions ---

	g_instruction_exception_table [ X86_INS_ADD ] =
		g_instruction_exception_table [ X86_INS_ADC ] =
		g_instruction_exception_table [ X86_INS_SUB ] =
		g_instruction_exception_table [ X86_INS_SBB ] =
		g_instruction_exception_table [ X86_INS_XADD ] = { // Mem read/write possible, alignment, lock possible
				.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true },
				.lock_prefix_allowed = true
	};
	g_instruction_exception_table [ X86_INS_INC ] =
		g_instruction_exception_table [ X86_INS_DEC ] =
		g_instruction_exception_table [ X86_INS_NEG ] = { // Mem read/write possible, alignment, lock possible
				.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true},
				.lock_prefix_allowed = true
	};
	g_instruction_exception_table [ X86_INS_MUL ] = { // Mem read possible, alignment
			.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_IMUL ] = { // Mem read possible, alignment
			.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_DIV ] =
		g_instruction_exception_table [ X86_INS_IDIV ] = { // Mem read possible, alignment, divide error
				.categories = {.MEMORY = true, .ARITHMETIC = true, .ALIGNMENT = true },
				.is_divide = true
	};
	g_instruction_exception_table [ X86_INS_CDQ ] =
		g_instruction_exception_table [ X86_INS_CWD ] = // AX -> DX:AX
		g_instruction_exception_table [ X86_INS_CBW ] = // AL -> AX
		g_instruction_exception_table [ X86_INS_CWDE ] = // AX -> EAX
		g_instruction_exception_table [ X86_INS_CDQE ] = // EAX -> RAX
		g_instruction_exception_table [ X86_INS_CQO ] = { // RAX -> RDX:RAX
				.categories = {}
	};

	// --- SSE Arithmetic ---
	g_instruction_exception_table [ X86_INS_ADDSS ] =
		g_instruction_exception_table [ X86_INS_SUBSS ] =
		g_instruction_exception_table [ X86_INS_MULSS ] =
		g_instruction_exception_table [ X86_INS_DIVSS ] =
		g_instruction_exception_table [ X86_INS_MINSS ] =
		g_instruction_exception_table [ X86_INS_MAXSS ] =
		g_instruction_exception_table [ X86_INS_SQRTSS ] =
		g_instruction_exception_table [ X86_INS_RCPSS ] =
		g_instruction_exception_table [ X86_INS_RSQRTSS ] = { // Mem read possible, align, SIMD FP state/exceptions
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_ADDSD ] = // Add scalar double (if ID different from MOVS)
		g_instruction_exception_table [ X86_INS_SUBSD ] =
		g_instruction_exception_table [ X86_INS_MULSD ] =
		g_instruction_exception_table [ X86_INS_DIVSD ] =
		g_instruction_exception_table [ X86_INS_MINSD ] =
		g_instruction_exception_table [ X86_INS_MAXSD ] =
		g_instruction_exception_table [ X86_INS_SQRTSD ] = {
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};

	// --- SSE Comparisons ---
	g_instruction_exception_table [ X86_INS_CMPSS ] =
		g_instruction_exception_table [ X86_INS_COMISS ] =
		g_instruction_exception_table [ X86_INS_UCOMISS ] = { // Mem read possible, align, SIMD FP state/exceptions
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_CMPSD ] = // Add if ID different
		g_instruction_exception_table [ X86_INS_COMISD ] =
		g_instruction_exception_table [ X86_INS_UCOMISD ] = {
			 .categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
			 .is_sse_avx_related = true
	};

	// --- SSE Conversions ---
	g_instruction_exception_table [ X86_INS_CVTSI2SS ] = // Mem read possible (int source), align, SIMD FP state
		g_instruction_exception_table [ X86_INS_CVTSI2SD ] = {
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_CVTSS2SI ] = // Mem read possible (float source), align, SIMD FP state
		g_instruction_exception_table [ X86_INS_CVTSD2SI ] =
		g_instruction_exception_table [ X86_INS_CVTTSS2SI ] = // Truncating versions
		g_instruction_exception_table [ X86_INS_CVTTSD2SI ] = {
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_CVTSS2SD ] =
		g_instruction_exception_table [ X86_INS_CVTSD2SS ] = { // Mem read possible, align, SIMD FP state
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};

	// --- SSE Logical/Util ---
	g_instruction_exception_table [ X86_INS_ANDPS ] =
		g_instruction_exception_table [ X86_INS_ANDNPS ] = // Add if needed
		g_instruction_exception_table [ X86_INS_ORPS ] =
		g_instruction_exception_table [ X86_INS_XORPS ] = { // Mem read possible, align, SSE state (#NM)
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true }, // FPU_SIMD for #NM check
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_ANDPD ] = // Add if needed
		g_instruction_exception_table [ X86_INS_ANDNPD ] = // Add if needed
		g_instruction_exception_table [ X86_INS_ORPD ] = // Add if needed
		g_instruction_exception_table [ X86_INS_XORPD ] = { // Add if needed
			 .categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
			 .is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_MOVHLPS ] = // Register only
		g_instruction_exception_table [ X86_INS_MOVLHPS ] = { // Register only
				.categories = {.FPU_SIMD = true },
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_UNPCKLPS ] =
		g_instruction_exception_table [ X86_INS_UNPCKHPS ] = // Add if needed
		g_instruction_exception_table [ X86_INS_UNPCKLPD ] = // Add if needed
		g_instruction_exception_table [ X86_INS_UNPCKHPD ] = { // Add if needed
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};
	g_instruction_exception_table [ X86_INS_ROUNDSS ] =
		g_instruction_exception_table [ X86_INS_ROUNDSD ] = { // Add if needed
				.categories = {.MEMORY = true, .ALIGNMENT = true, .FPU_SIMD = true },
				.is_sse_avx_related = true
	};


	// --- Logical Instructions ---

	g_instruction_exception_table [ X86_INS_AND ] =
		g_instruction_exception_table [ X86_INS_OR ] =
		g_instruction_exception_table [ X86_INS_XOR ] = {
				.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true },
				.lock_prefix_allowed = true
	};
	g_instruction_exception_table [ X86_INS_TEST ] = {
		 .categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_NOT ] = { // Mem read/write possible, alignment, lock possible
			.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true },
			.lock_prefix_allowed = true
	};

	g_instruction_exception_table [ X86_INS_SHL ] =
		g_instruction_exception_table [ X86_INS_SHR ] =
		g_instruction_exception_table [ X86_INS_SAL ] =
		g_instruction_exception_table [ X86_INS_SAR ] =
		g_instruction_exception_table [ X86_INS_ROL ] =
		g_instruction_exception_table [ X86_INS_ROR ] =
		g_instruction_exception_table [ X86_INS_RCL ] =
		g_instruction_exception_table [ X86_INS_RCR ] = { // Mem read/write possible, alignment
				.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_SHLD ] =
		g_instruction_exception_table [ X86_INS_SHRD ] = { // Mem read/write possible, alignment
				.categories = {.MEMORY = true, .ALIGNMENT = true }
	};

	// --- Conditional Moves --- (No exceptions typically triggered by the move itself)
	g_instruction_exception_table [ X86_INS_CMOVO ] =
		g_instruction_exception_table [ X86_INS_CMOVNO ] =
		g_instruction_exception_table [ X86_INS_CMOVB ] = // NAE, C
		g_instruction_exception_table [ X86_INS_CMOVAE ] = // NB, NC
		g_instruction_exception_table [ X86_INS_CMOVE ] = // Z
		g_instruction_exception_table [ X86_INS_CMOVNE ] = // NZ
		g_instruction_exception_table [ X86_INS_CMOVBE ] = // NA
		g_instruction_exception_table [ X86_INS_CMOVA ] = // NBE
		g_instruction_exception_table [ X86_INS_CMOVS ] =
		g_instruction_exception_table [ X86_INS_CMOVNS ] =
		g_instruction_exception_table [ X86_INS_CMOVP ] = // PE
		g_instruction_exception_table [ X86_INS_CMOVNP ] = // PO
		g_instruction_exception_table [ X86_INS_CMOVL ] = // NGE
		g_instruction_exception_table [ X86_INS_CMOVGE ] = // NL
		g_instruction_exception_table [ X86_INS_CMOVLE ] = // NG
		g_instruction_exception_table [ X86_INS_CMOVG ] = { // NLE
				.categories = {.MEMORY = true, .ALIGNMENT = true } // Only if source is memory
	};

	// --- Control Flow Instructions ---
	g_instruction_exception_table [ X86_INS_CMP ] = { // Mem read possible, alignment
			.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_CMPXCHG ] = { // Mem read/write, alignment, lock allowed
			.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true},
			.lock_prefix_allowed = true
	};
	g_instruction_exception_table [ X86_INS_CALL ] = { // Mem read possible (indirect), stack write, stack align/bounds, control flow
			.categories = {.MEMORY = true, .STACK = true, .ALIGNMENT = true, .CONTROL_FLOW = true },
			.is_explicit_push = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_RET ] = { // Stack read, stack align/bounds, control flow
			.categories = {.STACK = true, .ALIGNMENT = true, .CONTROL_FLOW = true },
			.is_explicit_pop = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_JMP ] = { // Mem read possible (indirect), control flow
			.categories = {.MEMORY = true, .CONTROL_FLOW = true }
	};
	// Conditional Jumps (No memory access by default, control flow category)
	g_instruction_exception_table [ X86_INS_JE ] =
		g_instruction_exception_table [ X86_INS_JNE ] =
		g_instruction_exception_table [ X86_INS_JB ] =
		g_instruction_exception_table [ X86_INS_JBE ] =
		g_instruction_exception_table [ X86_INS_JA ] =
		g_instruction_exception_table [ X86_INS_JAE ] =
		g_instruction_exception_table [ X86_INS_JL ] =
		g_instruction_exception_table [ X86_INS_JLE ] =
		g_instruction_exception_table [ X86_INS_JG ] =
		g_instruction_exception_table [ X86_INS_JGE ] =
		g_instruction_exception_table [ X86_INS_JS ] =
		g_instruction_exception_table [ X86_INS_JNS ] =
		g_instruction_exception_table [ X86_INS_JO ] =
		g_instruction_exception_table [ X86_INS_JNO ] =
		g_instruction_exception_table [ X86_INS_JP ] =
		g_instruction_exception_table [ X86_INS_JNP ] =
		g_instruction_exception_table [ X86_INS_JCXZ ] =
		g_instruction_exception_table [ X86_INS_JECXZ ] =
		g_instruction_exception_table [ X86_INS_JRCXZ ] = {
				.categories = {.CONTROL_FLOW = true }
	};

	// --- Stack Frame Instructions ---
	g_instruction_exception_table [ X86_INS_ENTER ] = { // Stack write/read, stack align/bounds
			.categories = {.STACK = true, .ALIGNMENT = true },
			.is_explicit_push = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_LEAVE ] = { // Stack read, modifies RSP/RBP
			.categories = {.STACK = true, .ALIGNMENT = true },
			.is_explicit_pop = true, .modifies_rsp_implicitly = true
	};
	g_instruction_exception_table [ X86_INS_NOP ] = {
			.categories = {}
	};

	// --- Bit Manipulation Instructions --- (BMI1/BMI2)
	g_instruction_exception_table [ X86_INS_BZHI ] =
		g_instruction_exception_table [ X86_INS_ANDN ] =
		g_instruction_exception_table [ X86_INS_BEXTR ] = { // Mem read possible, alignment
				.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_POPCNT ] = { // Mem read possible, alignment
			.categories = {.MEMORY = true, .ALIGNMENT = true }
	};
	g_instruction_exception_table [ X86_INS_BSWAP ] = { // Register only
			.categories = {}
	};
	g_instruction_exception_table [ X86_INS_BT ] =
		g_instruction_exception_table [ X86_INS_BTS ] =
		g_instruction_exception_table [ X86_INS_BTR ] =
		g_instruction_exception_table [ X86_INS_BTC ] = { // Mem read/write possible, alignment, lock allowed for BTS/BTR/BTC
				.categories = {.MEMORY = true, .INVALID_USAGE = true, .ALIGNMENT = true },
				.lock_prefix_allowed = true
	};
	// Override BT (no lock, no write)
	g_instruction_exception_table [ X86_INS_BT ] = {
		 .categories = {.MEMORY = true, .ALIGNMENT = true },
		 .lock_prefix_allowed = false
	};
	// SETcc instructions (Register only, no exceptions)
	g_instruction_exception_table [ X86_INS_SETB ] =
		g_instruction_exception_table [ X86_INS_SETAE ] =
		g_instruction_exception_table [ X86_INS_SETBE ] =
		g_instruction_exception_table [ X86_INS_SETA ] =
		g_instruction_exception_table [ X86_INS_SETE ] =
		g_instruction_exception_table [ X86_INS_SETNE ] =
		g_instruction_exception_table [ X86_INS_SETL ] =
		g_instruction_exception_table [ X86_INS_SETLE ] =
		g_instruction_exception_table [ X86_INS_SETG ] =
		g_instruction_exception_table [ X86_INS_SETGE ] =
		g_instruction_exception_table [ X86_INS_SETS ] =
		g_instruction_exception_table [ X86_INS_SETNS ] =
		g_instruction_exception_table [ X86_INS_SETO ] =
		g_instruction_exception_table [ X86_INS_SETNO ] =
		g_instruction_exception_table [ X86_INS_SETP ] =
		g_instruction_exception_table [ X86_INS_SETNP ] = {
				.categories = {.MEMORY = true, .ALIGNMENT = true } // Only if destination is memory
	};

	// --- Flags & Misc Instructions ---
	g_instruction_exception_table [ X86_INS_CLI ] = { // Privileged check needed if CPL > IOPL (complex)
				.categories = {.INVALID_USAGE = true }, // Treat as privileged for simplicity in user-mode emu
				.is_privileged = true // Simplification for user-mode
	};
	g_instruction_exception_table [ X86_INS_CLD ] =
		g_instruction_exception_table [ X86_INS_CLC ] =
		g_instruction_exception_table [ X86_INS_CMC ] =
		g_instruction_exception_table [ X86_INS_STC ] = {
				.categories = {}
	};
	g_instruction_exception_table [ X86_INS_RDTSC ] = { // Can be privileged based on CR4.TSD
			.categories = {.INVALID_USAGE = true } // Needs runtime check of CR4/CPL
	};
	g_instruction_exception_table [ X86_INS_CPUID ] = {
			.categories = {}
	};
	g_instruction_exception_table [ X86_INS_XGETBV ] = { // Can cause #UD if XSETBV/XGETBV not enabled, or #GP(0) with invalid ECX
			.categories = {.INVALID_USAGE = true }
	};
	g_instruction_exception_table [ X86_INS_SYSCALL ] = {
			.categories = {} // Handled by OS
	};

	g_instruction_exception_table [ X86_INS_BOUND ] = {
		 .categories = {.MEMORY = true, .ARITHMETIC = true, .ALIGNMENT = true },
		 .is_bound = true
	};

	g_instruction_exception_table [ X86_INS_INTO ] = {
			.categories = {.ARITHMETIC = true },
			.is_into = true
	};

	g_instruction_exception_table [ X86_INS_INT3 ] = {
	.categories = {.INVALID_USAGE = true }, // Belongs to usage category
	.is_int3 = true,
	// All other flags default to false/0
	};

	g_instruction_exception_table [ X86_INS_HLT ] = {
	.categories = {.INVALID_USAGE = true }, // Belongs to usage category
	.is_privileged = true,
	// All other flags default to false/0
	};
}

template const uint8_t& EmulationContext::get_reg<uint8_t> ( x86_reg ) const;
template const uint16_t& EmulationContext::get_reg<uint16_t> ( x86_reg ) const;
template const uint32_t& EmulationContext::get_reg<uint32_t> ( x86_reg ) const;
template const uint64_t& EmulationContext::get_reg<uint64_t> ( x86_reg ) const;
template uint8_t& EmulationContext::get_reg_mut<uint8_t> ( x86_reg );
template uint16_t& EmulationContext::get_reg_mut<uint16_t> ( x86_reg );
template uint32_t& EmulationContext::get_reg_mut<uint32_t> ( x86_reg );
template uint64_t& EmulationContext::get_reg_mut<uint64_t> ( x86_reg );

void init_reg_map ( ) {
	std::array<KGPR, X86_REG_ENDING> ( ).fill ( static_cast< KGPR >( -1 ) );

	reg_map [ X86_REG_RAX ] = KRAX;
	reg_map [ X86_REG_EAX ] = KRAX;
	reg_map [ X86_REG_AX ] = KRAX;
	reg_map [ X86_REG_AH ] = KRAX;
	reg_map [ X86_REG_AL ] = KRAX;
	reg_map [ X86_REG_RBX ] = KRBX;
	reg_map [ X86_REG_EBX ] = KRBX;
	reg_map [ X86_REG_BX ] = KRBX;
	reg_map [ X86_REG_BH ] = KRBX;
	reg_map [ X86_REG_BL ] = KRBX;
	reg_map [ X86_REG_RCX ] = KRCX;
	reg_map [ X86_REG_ECX ] = KRCX;
	reg_map [ X86_REG_CX ] = KRCX;
	reg_map [ X86_REG_CH ] = KRCX;
	reg_map [ X86_REG_CL ] = KRCX;
	reg_map [ X86_REG_RDX ] = KRDX;
	reg_map [ X86_REG_EDX ] = KRDX;
	reg_map [ X86_REG_DX ] = KRDX;
	reg_map [ X86_REG_DH ] = KRDX;
	reg_map [ X86_REG_DL ] = KRDX;
	reg_map [ X86_REG_RSI ] = KRSI;
	reg_map [ X86_REG_ESI ] = KRSI;
	reg_map [ X86_REG_SI ] = KRSI;
	reg_map [ X86_REG_SIL ] = KRSI;
	reg_map [ X86_REG_RDI ] = KRDI;
	reg_map [ X86_REG_EDI ] = KRDI;
	reg_map [ X86_REG_DI ] = KRDI;
	reg_map [ X86_REG_DIL ] = KRDI;
	reg_map [ X86_REG_RBP ] = KRBP;
	reg_map [ X86_REG_EBP ] = KRBP;
	reg_map [ X86_REG_BP ] = KRBP;
	reg_map [ X86_REG_BPL ] = KRBP;
	reg_map [ X86_REG_RSP ] = KRSP;
	reg_map [ X86_REG_ESP ] = KRSP;
	reg_map [ X86_REG_SP ] = KRSP;
	reg_map [ X86_REG_SPL ] = KRSP;
	reg_map [ X86_REG_R8 ] = KR8;
	reg_map [ X86_REG_R8D ] = KR8;
	reg_map [ X86_REG_R8W ] = KR8;
	reg_map [ X86_REG_R8B ] = KR8;
	reg_map [ X86_REG_R9 ] = KR9;
	reg_map [ X86_REG_R9D ] = KR9;
	reg_map [ X86_REG_R9W ] = KR9;
	reg_map [ X86_REG_R9B ] = KR9;
	reg_map [ X86_REG_R10 ] = KR10;
	reg_map [ X86_REG_R10D ] = KR10;
	reg_map [ X86_REG_R10W ] = KR10;
	reg_map [ X86_REG_R10B ] = KR10;
	reg_map [ X86_REG_R11 ] = KR11;
	reg_map [ X86_REG_R11D ] = KR11;
	reg_map [ X86_REG_R11W ] = KR11;
	reg_map [ X86_REG_R11B ] = KR11;
	reg_map [ X86_REG_R12 ] = KR12;
	reg_map [ X86_REG_R12D ] = KR12;
	reg_map [ X86_REG_R12W ] = KR12;
	reg_map [ X86_REG_R12B ] = KR12;
	reg_map [ X86_REG_R13 ] = KR13;
	reg_map [ X86_REG_R13D ] = KR13;
	reg_map [ X86_REG_R13W ] = KR13;
	reg_map [ X86_REG_R13B ] = KR13;
	reg_map [ X86_REG_R14 ] = KR14;
	reg_map [ X86_REG_R14D ] = KR14;
	reg_map [ X86_REG_R14W ] = KR14;
	reg_map [ X86_REG_R14B ] = KR14;
	reg_map [ X86_REG_R15 ] = KR15;
	reg_map [ X86_REG_R15D ] = KR15;
	reg_map [ X86_REG_R15W ] = KR15;
	reg_map [ X86_REG_R15B ] = KR15;
	reg_map [ X86_REG_RIP ] = KRIP;
	reg_map [ X86_REG_EIP ] = KRIP;
	reg_map [ X86_REG_IP ] = KRIP;
	reg_map [ X86_REG_DR0 ] = KDR0;
	reg_map [ X86_REG_DR1 ] = KDR1;
	reg_map [ X86_REG_DR2 ] = KDR2;
	reg_map [ X86_REG_DR3 ] = KDR3;
	reg_map [ X86_REG_DR4 ] = KDR4;
	reg_map [ X86_REG_DR5 ] = KDR5;
	reg_map [ X86_REG_DR6 ] = KDR6;
	reg_map [ X86_REG_DR7 ] = KDR7;
	reg_map [ X86_REG_CR0 ] = KCR0;
	reg_map [ X86_REG_CR2 ] = KCR2;
	reg_map [ X86_REG_CR3 ] = KCR3;
	reg_map [ X86_REG_CR4 ] = KCR4;
	reg_map [ X86_REG_CR8 ] = KCR8;
	reg_map [ X86_REG_CS ] = KCS;
	reg_map [ X86_REG_DS ] = KDS;
	reg_map [ X86_REG_ES ] = KES;
	reg_map [ X86_REG_FS ] = KFS;
	reg_map [ X86_REG_GS ] = KGS;
	reg_map [ X86_REG_SS ] = KSS;
}

void init_avx_map ( ) {
	avx_map [ X86_REG_XMM0 ] = 0;
	avx_map [ X86_REG_XMM1 ] = 1;
	avx_map [ X86_REG_XMM2 ] = 2;
	avx_map [ X86_REG_XMM3 ] = 3;
	avx_map [ X86_REG_XMM4 ] = 4;
	avx_map [ X86_REG_XMM5 ] = 5;
	avx_map [ X86_REG_XMM6 ] = 6;
	avx_map [ X86_REG_XMM7 ] = 7;
	avx_map [ X86_REG_XMM8 ] = 8;
	avx_map [ X86_REG_XMM9 ] = 9;
	avx_map [ X86_REG_XMM10 ] = 10;
	avx_map [ X86_REG_XMM11 ] = 11;
	avx_map [ X86_REG_XMM12 ] = 12;
	avx_map [ X86_REG_XMM13 ] = 13;
	avx_map [ X86_REG_XMM14 ] = 14;
	avx_map [ X86_REG_XMM15 ] = 15;
	avx_map [ X86_REG_YMM0 ] = 0;
	avx_map [ X86_REG_YMM1 ] = 1;
	avx_map [ X86_REG_YMM2 ] = 2;
	avx_map [ X86_REG_YMM3 ] = 3;
	avx_map [ X86_REG_YMM4 ] = 4;
	avx_map [ X86_REG_YMM5 ] = 5;
	avx_map [ X86_REG_YMM6 ] = 6;
	avx_map [ X86_REG_YMM7 ] = 7;
	avx_map [ X86_REG_YMM8 ] = 8;
	avx_map [ X86_REG_YMM9 ] = 9;
	avx_map [ X86_REG_YMM10 ] = 10;
	avx_map [ X86_REG_YMM11 ] = 11;
	avx_map [ X86_REG_YMM12 ] = 12;
	avx_map [ X86_REG_YMM13 ] = 13;
	avx_map [ X86_REG_YMM14 ] = 14;
	avx_map [ X86_REG_YMM15 ] = 15;
	avx_map [ X86_REG_ZMM0 ] = 0;
	avx_map [ X86_REG_ZMM1 ] = 1;
	avx_map [ X86_REG_ZMM2 ] = 2;
	avx_map [ X86_REG_ZMM3 ] = 3;
	avx_map [ X86_REG_ZMM4 ] = 4;
	avx_map [ X86_REG_ZMM5 ] = 5;
	avx_map [ X86_REG_ZMM6 ] = 6;
	avx_map [ X86_REG_ZMM7 ] = 7;
	avx_map [ X86_REG_ZMM8 ] = 8;
	avx_map [ X86_REG_ZMM9 ] = 9;
	avx_map [ X86_REG_ZMM10 ] = 10;
	avx_map [ X86_REG_ZMM11 ] = 11;
	avx_map [ X86_REG_ZMM12 ] = 12;
	avx_map [ X86_REG_ZMM13 ] = 13;
	avx_map [ X86_REG_ZMM14 ] = 14;
	avx_map [ X86_REG_ZMM15 ] = 15;
};

uint64_t calc_initial_rsp ( uintptr_t stack_base,
																 size_t    stack_size,
																 size_t    shadow_space = 32,   // Win64
																 size_t    fake_ret_space = 8 ) {
	uintptr_t top = stack_base + stack_size;
	uintptr_t rsp = ( top - fake_ret_space ) & ~uintptr_t ( 0xF );

	rsp -= shadow_space;

	return static_cast< uint64_t >( rsp );
}

bool is_24h2 ( ) {
	OSVERSIONINFOEXW osInfo = { sizeof ( osInfo ) };
	if ( GetVersionExW ( ( LPOSVERSIONINFOW ) &osInfo ) ) {
		return osInfo.dwMajorVersion >= 10 && osInfo.dwBuildNumber >= 26100;
	}
	return false;
}

EmulationContext::EmulationContext ( ) {
	EmulationContext::initialize_exception_table ( );
	helpers::bind_arithmetic ( );
	helpers::bind_bit ( );
	helpers::bind_cf ( );
	helpers::bind_jx ( );
	helpers::bind_cpu ( );
	helpers::bind_fpu ( );
	helpers::bind_data ( );
	helpers::bind_logical ( );
	helpers::bind_frame ( );
	helpers::bind_avx ( );
	helpers::bind_winapi ( );
	init_reg_map ( );
	init_avx_map ( );
	cpu = std::make_unique<KCPU> ( );
	windows = std::make_unique<WindowsCompat> ( );
	cpu->avx_registers = std::make_unique<std::array<uint512_t, 16>> ( );
	cpu->registers.fill ( 0 );

	constexpr size_t stack_total_size = 0x200000; // 2MB stack
	constexpr size_t stack_alignment = 16;
	constexpr int64_t shadow_space_size = 32;
	constexpr int64_t fake_ret_addr_space = 8;
	constexpr uint64_t fake_ret_addr_value = 0xDEADBEEFBAADF00DULL;

	// Allocate stack
	rsp_base = std::unique_ptr<uint8_t [ ], void ( * )( uint8_t* )> (
			static_cast< uint8_t* >( _aligned_malloc ( stack_total_size, stack_alignment ) ),
			[ ] ( uint8_t* ptr ) { _aligned_free ( ptr ); } );
	if ( !rsp_base ) {
		throw std::runtime_error ( "Failed to allocate aligned stack" );
	}

	uintptr_t stack_base_addr = reinterpret_cast< uintptr_t >( rsp_base.get ( ) );
	if ( stack_base_addr % stack_alignment != 0 ) {
		_aligned_free ( rsp_base.release ( ) );
		throw std::runtime_error ( "Stack allocation is not aligned" );
	}

	stack_allocated = stack_total_size;

	// Setup TEB
	auto real_teb = reinterpret_cast< _TEB64* >( __readgsqword ( 0x30 ) );
	windows->teb = std::make_unique<_TEB64> ( );
	if ( is_24h2 ( ) ) {
		memcpy ( windows->teb.get ( ), real_teb, sizeof ( _TEB64 ) );
	}
	windows->teb->ProcessEnvironmentBlock = __readgsqword ( 0x60 );
	windows->teb->NtTib.StackBase = stack_base_addr + stack_total_size;
	windows->teb->NtTib.StackLimit = stack_base_addr;
	windows->teb->NtTib.Self = reinterpret_cast< DWORD64 >( windows->teb.get ( ) );
	windows->teb->ClientId.UniqueProcess = GetCurrentProcessId ( );
	windows->teb->ClientId.UniqueThread = GetCurrentThreadId ( );

	windows->ntdll_base = reinterpret_cast< uint64_t >( GetModuleHandleA ( "ntdll.dll" ) );
	windows->kernel32_base = reinterpret_cast< uint64_t >( GetModuleHandleA ( "kernel32.dll" ) );

	windows->ldr_initialize_thunk = reinterpret_cast< uint64_t >( GetProcAddress ( reinterpret_cast< HMODULE >( windows->ntdll_base ), "LdrInitializeThunk" ) );
	windows->rtl_user_thread_start = reinterpret_cast< uint64_t >( GetProcAddress ( reinterpret_cast< HMODULE >( windows->ntdll_base ), "RtlUserThreadStart" ) );
	windows->ki_user_exception_dispatcher = reinterpret_cast< uint64_t >( GetProcAddress ( reinterpret_cast< HMODULE >( windows->ntdll_base ), "KiUserExceptionDispatcher" ) );
	windows->ki_user_apc_dispatcher = reinterpret_cast< uint64_t >( GetProcAddress ( reinterpret_cast< HMODULE >( windows->ntdll_base ), "KiUserApcDispatcher" ) );

	InstructionEffect effect { .no_log = true };
	set_reg ( X86_REG_GS, ( uint64_t ) windows->teb.get ( ), 8, effect );

	uint64_t initial_rsp = calc_initial_rsp ( stack_base_addr, stack_total_size );
	set_reg ( X86_REG_RSP, initial_rsp, 8, effect );
	set_stack ( initial_rsp, fake_ret_addr_value, effect, 8 );
	push_call_frame ( fake_ret_addr_value, effect );

	set_rcx_to_ioport ( 0x0000, effect );

	initialize_imports ( parser );
	if ( options.enable_logging ) {
		std::print ( "Initialized State: Stack Base=0x{:016x}, Size=0x{:x}\n", stack_base_addr, stack_total_size );
		std::print ( "Initial Registers: RSP=0x{:016x}, RBP=0x{:016x}, rsp_offset=0x{:x}\n",
							 initial_rsp, get_reg ( X86_REG_RBP ), cpu->rsp_offset );
		std::print ( "Stack Top=0x{:016x}\n", windows->teb->NtTib.StackBase );
		std::print ( "Stack Bottom=0x{:016x}\n", windows->teb->NtTib.StackLimit );
		std::print ( "Fake return address 0x{:016x} at RSP 0x{:016x}\n", fake_ret_addr_value, initial_rsp );
	}
}
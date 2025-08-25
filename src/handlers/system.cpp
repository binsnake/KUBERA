#include "../../emulator.hpp"
#include <bit>
#include "helpers.hpp"

using namespace kubera;

/// CLI-Clear Interrupt Flag
/// Clears the interrupt flag (IF) to disable maskable interrupts.
void handlers::cli ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_cpl ( ) == 0 ) {
		context.get_flags ( ).IF = 0;
	}
	else {
		// !TODO(exception)
	}
}

/// CLD-Clear Direction Flag
/// Clears the direction flag (DF), causing string instructions to increment the index registers.
void handlers::cld ( const iced::Instruction& instr, KUBERA& context ) {
	context.get_flags ( ).DF = 0;
}
/// CLC-Clear Carry Flag
/// Clears the carry flag (CF)
void handlers::clc ( const iced::Instruction& instr, KUBERA& context ) {
	context.get_flags ( ).CF = 0;
}

/// CLUI-Clear User Interrupt Flag
/// Clears the user interrupt flag (IF), disabling user-level interrupts (alias for CLI in some contexts).
void handlers::clui ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_cpl ( ) == 0 ) {
		context.get_flags ( ).IF = 0;
	}
	else {
		// !TODO(cr4)
		// !TODO(exception)
	}
}

/// CMC-Complement Carry Flag
/// Complements (toggles) the carry flag (CF).
void handlers::cmc ( const iced::Instruction& instr, KUBERA& context ) {
	context.get_flags ( ).CF ^= 1;
}

/// STC-Set Carry Flag
/// Sets the carry flag (CF) to 1.
void handlers::stc ( const iced::Instruction& instr, KUBERA& context ) {
	context.get_flags ( ).CF = 1;
}

/// STI-Set Interrupt Flag
/// Sets the interrupt flag (IF) to enable maskable interrupts.
void handlers::sti ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_cpl ( ) == 0 ) {
		context.get_flags ( ).IF = 1;
	}
	else {
		// !TODO(exception)
	}
}

/// STD-Set Direction Flag
/// Sets the direction flag (DF), causing string instructions to decrement the index registers.
void handlers::std ( const iced::Instruction& instr, KUBERA& context ) {
	context.get_flags ( ).DF = 1;
}

/// LAHF-Load Status Flags into AH
/// Loads the SF, ZF, AF, PF, and CF flags into the AH register (bits 7, 6, 4, 2, and 0, respectively).
void handlers::lahf ( const iced::Instruction& instr, KUBERA& context ) {
	auto& flags = context.get_flags ( );
	uint8_t ah_val = static_cast< uint8_t >( ( flags.SF << 7 ) | ( flags.ZF << 6 ) | ( flags.AF << 4 ) | ( flags.PF << 2 ) | flags.CF );
	context.set_reg ( Register::AH, ah_val, 1 );
}

/// SAHF-Store AH into Status Flags
/// Stores the contents of the AH register into the SF, ZF, AF, PF, and CF flags (bits 7, 6, 4, 2, and 0, respectively).
void handlers::sahf ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t ah_val = context.get_reg ( Register::AH, 1 );
	auto& flags = context.get_flags ( );
	flags.SF = ( ah_val >> 7 ) & 1;
	flags.ZF = ( ah_val >> 6 ) & 1;
	flags.AF = ( ah_val >> 4 ) & 1;
	flags.PF = ( ah_val >> 2 ) & 1;
	flags.CF = ah_val & 1;
}

/// PUSHF-Push Flags
/// Pushes the lower 16 bits of the EFLAGS register onto the stack.
void handlers::pushf ( const iced::Instruction& instr, KUBERA& context ) {
	auto& flags = context.get_flags ( );
	uint16_t eflags = static_cast< uint16_t >( ( flags.SF << 7 ) | ( flags.ZF << 6 ) | ( flags.AF << 4 ) |
		( flags.PF << 2 ) | ( flags.CF ) | ( flags.IF << 9 ) | ( flags.DF << 10 ) );
	const uint64_t rsp = context.get_reg ( Register::RSP, 8 );
	const uint64_t addr = rsp - 2;
	context.set_memory<uint16_t> ( addr, eflags );
	context.set_reg ( Register::RSP, addr, 8 );
}

/// POPF-Pop Flags
/// Pops the lower 16 bits from the stack into the EFLAGS register.
void handlers::popf ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t rsp = context.get_reg ( Register::RSP, 8 );
	const uint16_t eflags = context.get_memory<uint16_t> ( rsp );
	auto& flags = context.get_flags ( );
	flags.SF = ( eflags >> 7 ) & 1;
	flags.ZF = ( eflags >> 6 ) & 1;
	flags.AF = ( eflags >> 4 ) & 1;
	flags.PF = ( eflags >> 2 ) & 1;
	flags.CF = eflags & 1;
	flags.IF = ( eflags >> 9 ) & 1;
	flags.DF = ( eflags >> 10 ) & 1;
	context.set_reg ( Register::RSP, rsp + 2, 8 );
}

/// RDTSC-Read Time-Stamp Counter
/// Reads the processor's time-stamp counter into EDX:EAX (high:low 32 bits).
void handlers::rdtsc ( const iced::Instruction& instr, KUBERA& context ) {
	// !TODO(cr4)
	const auto tsc = context.read_tsc ( );
	const auto low = static_cast< uint32_t >( tsc & 0xFFFFFFFF );
	const auto high = static_cast< uint32_t >( tsc >> 32 );
	context.set_reg ( Register::RAX, low, 4 );
	context.set_reg ( Register::RDX, high, 4 );
}

/// INT1-Debug Trap
/// Triggers a debug exception (#DB) for single-step debugging.
void handlers::int1 ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_cpl ( ) == 0 ) {
		// !TODO(exception)
	}
	else {
		// !TODO(exception)
	}
}

/// INT3-Breakpoint
/// Triggers a breakpoint exception (#BP) for debugging.
void handlers::int3 ( const iced::Instruction& instr, KUBERA& context ) {
	// !TODO(exception)
}

/// INT-Software Interrupt
/// Triggers a software interrupt with the specified vector number (generic handler for all interrupts).
void handlers::int_ ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_cpl ( ) == 0 ) {
		// !TODO(exception)
	}
	else {
		// !TODO(exception)
	}
}

/// FXSAVE-Save x87 FPU, MMX, and SSE State
/// Saves the x87 FPU (FCW, FSW, FTW, FOP, FIP, FDP), MMX, and SSE (MXCSR, XMM0-XMM15) state to a 512-byte memory region specified by the destination operand.
void handlers::fxsave ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t base_addr = helpers::calculate_mem_addr( instr, context );
	if ( base_addr % 16 != 0 ) {
		// !TODO(exception)
		return;
	}
	auto& fpu = context.get_fpu ( );
	context.set_memory<uint16_t> ( base_addr + 0, fpu.fpu_control_word.value );
	context.set_memory<uint16_t> ( base_addr + 2, fpu.fpu_status_word.value );

	uint8_t ftag = 0;
	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = fpu.get_fpu_phys_idx ( i );
		if ( fpu.get_fpu_tag ( phys_idx ) == x86::FPU_TAG_EMPTY ) {
			ftag |= ( 1 << i );
		}
	}
	context.set_memory<uint8_t> ( base_addr + 4, ftag );
	context.set_memory<uint8_t> ( base_addr + 5, 0 );

	context.set_memory<uint16_t> ( base_addr + 6, 0 ); // FOP
	context.set_memory<uint64_t> ( base_addr + 8, 0 ); // FIP
	context.set_memory<uint64_t> ( base_addr + 16, 0 ); // FDP

	context.set_memory<uint32_t> ( base_addr + 24, context.get_mxcsr ( ).value );
	context.set_memory<uint32_t> ( base_addr + 28, 0xFFFF ); // MXCSR_MASK

	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = fpu.get_fpu_phys_idx ( i );
		const float80_t& st_val = fpu.fpu_stack [ phys_idx ];
		uint64_t current_reg_addr = base_addr + 32 + ( i * 16 );
		context.write_type<float80_t> ( current_reg_addr, st_val );
		for ( int j = 10; j < 16; ++j ) {
			context.set_memory<uint8_t> ( current_reg_addr + j, 0 );
		}
	}

	for ( int i = 0; i < 31; ++i ) {
		uint128_t xmm_val = context.get_xmm_raw ( static_cast< Register > ( static_cast< int > ( Register::XMM0 ) + i ) );
		context.set_memory<uint128_t> ( base_addr + 160 + ( i * 16 ), xmm_val );
	}

	for ( int i = 0; i < 96; i += 8 ) {
		context.set_memory<uint64_t> ( base_addr + 416 + i, 0 );
	}
}

/// FXRSTOR-Restore x87 FPU, MMX, and SSE State
/// Restores the x87 FPU (FCW, FSW, FTW, FOP, FIP, FDP), MMX, and SSE (MXCSR, XMM0-XMM15) state from a 512-byte memory region specified by the source operand.
void handlers::fxrstor ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t base_addr = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	if ( base_addr % 16 != 0 ) {
		// !TODO(exception)
		return;
	}

	uint16_t fcw = context.get_memory<uint16_t> ( base_addr + 0 );
	if ( ( fcw & 0xE0C0 ) != 0 ) {
		// !TODO(exception)
		return;
	}
	auto& fpu = context.get_fpu ( );
	fpu.fpu_control_word.value = fcw;

	uint16_t fsw = context.get_memory<uint16_t> ( base_addr + 2 );
	fpu.fpu_status_word.value = fsw;
	fpu.fpu_top = ( fsw & x86::FSW_TOP_MASK ) >> x86::FSW_TOP_SHIFT;

	uint8_t ftag = context.get_memory<uint8_t> ( base_addr + 4 );
	fpu.fpu_tag_word.value = 0;

	uint32_t mxcsr_val = context.get_memory<uint32_t> ( base_addr + 24 );
	if ( ( mxcsr_val >> 16 ) != 0 ) {
		// !TODO(exception)
		return;
	}
	context.get_mxcsr ( ) = static_cast< x86::Mxcsr >( mxcsr_val );

	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = fpu.get_fpu_phys_idx ( i );
		uint64_t current_reg_addr = base_addr + 32 + ( i * 16 );
		fpu.fpu_stack [ phys_idx ] = context.read_type_float80_t ( current_reg_addr );
		fpu.set_fpu_tag ( phys_idx, ( ftag >> i ) & 1 ? x86::FPU_TAG_EMPTY :
																fpu.classify_fpu_operand ( fpu.fpu_stack [ phys_idx ] ) );
	}

	for ( auto i = 0u; i < 31u; ++i ) {
		uint128_t xmm_val = context.get_memory<uint128_t> ( base_addr + 160 + ( i * 16 ) );
		context.set_xmm_raw ( static_cast< Register > ( static_cast< int > ( Register::XMM0 ) + i ), xmm_val );
	}
}

/// HLT-Halt
/// Halts the processor until the next interrupt or reset.
void handlers::hlt ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_cpl ( ) == 0 ) {
		// !TODO(halt)
	}
	else {
		// !TODO(exception)
	}
}

/// STMXCSR-Store MXCSR Register
/// Stores the MXCSR register to a 32-bit memory location specified by the destination operand.
void handlers::stmxcsr ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t dest_addr = helpers::calculate_mem_addr( instr, context );
	const size_t op_size = instr.op0_size ( );
	if ( op_size != 4 ) {
		// !TODO(exception)
		return;
	}
	context.set_memory<uint32_t> ( dest_addr, context.get_mxcsr ( ).value );
}

/// LDMXCSR-Load MXCSR Register
/// Loads the MXCSR register from a 32-bit memory location specified by the source operand.
void handlers::ldmxcsr ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t src_addr = helpers::calculate_mem_addr( instr, context );
	const size_t op_size = instr.op0_size ( );
	if ( op_size != 4 ) {
		// !TODO(exception)
		return;
	}
	const uint32_t mxcsr_val = context.get_memory<uint32_t> ( src_addr );
	if ( ( mxcsr_val >> 16 ) != 0 ) {
		// !TODO(exception)
		return;
	}
	context.get_mxcsr ( ) = x86::Mxcsr { .value = mxcsr_val };
}

/// XGETBV-Get Value of Extended Control Register
/// Reads the specified extended control register (XCR) into EDX:EAX (high:low 32 bits).
void handlers::xgetbv ( const iced::Instruction& instr, KUBERA& context ) {
	// !TODO(implement)
	throw std::runtime_error ( "xgetbv not implemented!" );
	//const uint32_t ecx_in = context.get_reg_internal<KubRegister::RCX, Register::ECX, uint32_t> ( );
	//const uint64_t xcr_val = _xgetbv ( ecx_in );
	//const uint32_t eax_out = static_cast< uint32_t >( xcr_val & 0xFFFFFFFF );
	//const uint32_t edx_out = static_cast< uint32_t >( xcr_val >> 32 );
	//context.set_reg_internal<KubRegister::RAX, Register::EAX> ( eax_out );
	//context.set_reg_internal<KubRegister::RDX, Register::EDX> ( edx_out );
}

/// CPUID-CPU Identification
/// Returns processor identification and feature information in RAX, RBX, RCX, and RDX based on the input in RAX and RCX.
void handlers::cpuid ( const iced::Instruction& instr, KUBERA& context ) {
	const uint32_t eax_in = context.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( );
	const uint32_t ecx_in = context.get_reg_internal<KubRegister::RCX, Register::RCX, uint32_t> ( );

	// !TODO(isolation)
	// !TODO(PRIORITY)
	std::array<int, 4> cpu_info;
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64)
#ifdef _MSC_VER
	__cpuidex ( cpu_info.data ( ), eax_in, ecx_in );
#else
	__asm__ __volatile__ (
			"cpuid"
			: "=a"( cpu_info [ 0 ] ), "=b"( cpu_info [ 1 ] ), "=c"( cpu_info [ 2 ] ), "=d"( cpu_info [ 3 ] )
			: "a"( eax_in ), "c"( ecx_in )
	);
#endif
#else
	throw std::runtime_error ( "CPUID emulation not available for non-x86 platforms" );
#endif

	context.set_reg_internal<KubRegister::RAX, Register::RAX> ( cpu_info [ 0 ] );
	context.set_reg_internal<KubRegister::RBX, Register::RBX> ( cpu_info [ 1 ] );
	context.set_reg_internal<KubRegister::RCX, Register::RCX> ( cpu_info [ 2 ] );
	context.set_reg_internal<KubRegister::RDX, Register::RDX> ( cpu_info [ 3 ] );
}

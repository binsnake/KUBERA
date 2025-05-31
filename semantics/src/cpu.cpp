#include "pch.hpp"


void rdtsc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.increment_tsc ( );

	const auto tsc = state.cpu->tsc;
	const auto low = static_cast< uint32_t >( tsc & 0xFFFFFFFF );
	const auto high = static_cast< uint32_t >( tsc >> 32 );

	state.set_reg ( X86_REG_RAX, low, 4, effect );
	state.set_reg ( X86_REG_RDX, high, 4, effect );

	effect.push_to_changes ( state, std::format ( "RDTSC: RAX=0x{:08x}, RDX=0x{:08x} (TSC=0x{:016x})", low, high, tsc ) );
	effect.modified_regs.insert ( X86_REG_RAX );
	effect.modified_regs.insert ( X86_REG_RDX );
}

void cpuid ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const auto eax_in = state.get_reg<uint32_t> ( X86_REG_RAX );
	const auto ecx_in = state.get_reg<uint32_t> ( X86_REG_RCX );

	int cpu_info [ 4 ] = { 0 }; // EAX, EBX, ECX, EDX

	__cpuidex ( cpu_info, eax_in, ecx_in );

	state.set_reg ( X86_REG_RAX, static_cast< uint32_t >( cpu_info [ 0 ] ), 4, effect );
	state.set_reg ( X86_REG_RBX, static_cast< uint32_t >( cpu_info [ 1 ] ), 4, effect );
	state.set_reg ( X86_REG_RCX, static_cast< uint32_t >( cpu_info [ 2 ] ), 4, effect );
	state.set_reg ( X86_REG_RDX, static_cast< uint32_t >( cpu_info [ 3 ] ), 4, effect );

	effect.push_to_changes ( state, std::format ( "CPUID[RAX={:#x}, RCX={:#x}]: RAX={:#08x}, RBX={:#08x}, RCX={:#08x}, RDX={:#08x}",
													 eax_in, ecx_in, cpu_info [ 0 ], cpu_info [ 1 ], cpu_info [ 2 ], cpu_info [ 3 ] ) );

	effect.modified_regs.insert ( X86_REG_RAX );
	effect.modified_regs.insert ( X86_REG_RBX );
	effect.modified_regs.insert ( X86_REG_RCX );
	effect.modified_regs.insert ( X86_REG_RDX );
}

void xgetbv ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const auto ecx_in = state.get_reg <uint32_t> ( X86_REG_RCX );
	const auto xcr_val = _xgetbv ( ecx_in ); // Intrinsic to get XCR value from host

	const auto eax_out = static_cast< uint32_t >( xcr_val & 0xFFFFFFFF );
	const auto edx_out = static_cast< uint32_t >( xcr_val >> 32 );

	state.set_reg ( X86_REG_RAX, eax_out, 4, effect );
	state.set_reg ( X86_REG_RDX, edx_out, 4, effect );

	effect.push_to_changes ( state, std::format ( "XGETBV[ECX=0x{:x}]: RAX=0x{:08x}, RDX=0x{:08x} (XCR=0x{:016x})",
													 ecx_in, eax_out, edx_out, xcr_val ) );
	effect.modified_regs.insert ( X86_REG_RAX );
	effect.modified_regs.insert ( X86_REG_RDX );
}

struct SyscallState {
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t rsp;
};

extern "C" void execute_raw_syscall (
		uint64_t rax, uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9,
		uint64_t* stack_args, size_t stack_arg_count, SyscallState* state
);

void syscall ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto syscall_num = state.get_reg ( X86_REG_RAX );
	auto arg1 = state.get_reg ( X86_REG_RCX );
	auto arg2 = state.get_reg ( X86_REG_RDX );
	auto arg3 = state.get_reg ( X86_REG_R8 );
	auto arg4 = state.get_reg ( X86_REG_R9 );
	auto current_rsp = state.get_reg ( X86_REG_RSP );

	std::vector<uint64_t> stack_args;
	if ( syscall_num == 0x18 ) {
		for ( size_t i = 4; i < 9; ++i ) {
			uint64_t addr = current_rsp + ( i - 4 ) * 8;
			stack_args.push_back ( state.get_stack ( addr, false ) );
		}
	}

	struct RealBuffer {
		uint64_t virtual_addr;
		std::unique_ptr<uint8_t [ ]> real_mem;
		size_t size;
	};
	std::vector<RealBuffer> real_buffers;

	if ( syscall_num == 0x1c ) {
		size_t len = ( size_t ) arg4;
		if ( len ) {
			RealBuffer buf { arg3, std::make_unique<uint8_t [ ]> ( len ), len };
			for ( size_t i = 0; i < len; ++i )
				buf.real_mem [ i ] = static_cast< uint8_t > ( state.get_memory ( arg3 + i, 1 ) );
			real_buffers.push_back ( std::move ( buf ) );
		}
	}

	SyscallState post;
	execute_raw_syscall ( syscall_num,
											arg1, arg2, arg3, arg4,
											stack_args.data ( ), stack_args.size ( ),
											&post );

	state.set_reg ( X86_REG_RAX, post.rax, 8, effect );
	state.set_reg ( X86_REG_RCX, post.rcx, 8, effect );
	state.set_reg ( X86_REG_RDX, post.rdx, 8, effect );
	state.set_reg ( X86_REG_R8, post.r8, 8, effect );
	state.set_reg ( X86_REG_R9, post.r9, 8, effect );
	state.set_reg ( X86_REG_R10, post.r10, 8, effect );


	for ( auto& buf : real_buffers ) {
		for ( size_t i = 0; i < buf.size; i += 8 ) {
			uint64_t v = 0;
			memcpy ( &v, buf.real_mem.get ( ) + i, sizeof ( v ) );
			uint64_t va = buf.virtual_addr + i;
			if ( state.is_within_stack_bounds ( ( int64_t ) va, 8 ) )
				state.set_stack ( va, v, effect );
			else {
				state.set_memory ( va, v, 8, effect );
				effect.modified_mem.insert ( va );
			}
		}
	}

	effect.push_to_changes (
			state,
			std::format ( "syscall 0x{:x} returned 0x{:016x}", syscall_num, post.rax )
	);
}




void hlt ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	if ( state.cpu->current_privilege_level == 3 ) {
		if ( state.options.enable_logging ) {
			effect.push_to_changes ( state, "HLT executed in user mode (pre-check failed?). Forcing PRIV_INSTRUCTION exception." );
		}

		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_PRIV_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}
	else {
		if ( state.options.enable_logging ) {
			effect.push_to_changes ( state, "HLT executed in non-user mode. Halting emulation simulation." );
		}

		state.exit_due_to_critical_error = true;
	}
}


void int1 (
		capstone::Instruction& instr,
		EmulationContext& state,
		InstructionEffect& effect
) {
	effect.push_to_changes ( state, "INT 0x01 - Debug exception" );
	GuestExceptionInfo ex;
	ex.set_exception ( EXCEPTION_DEBUG_EVENT, instr.ip ( ) ); // TODO: find correct wincode
	throw ex;
}

void int3 (
		capstone::Instruction& instr,
		EmulationContext& state,
		InstructionEffect& effect
) {
	effect.push_to_changes ( state, "INT 0x03 - Breakpoint" );
	GuestExceptionInfo ex;
	ex.set_exception ( EXCEPTION_BREAKPOINT, instr.ip ( ) );
	throw ex;
}

void int_ (
		capstone::Instruction& instr,
		EmulationContext& state,
		InstructionEffect& effect
) {
	// must be an immediate interrupt
	const auto ops = instr.operands ( );
	if ( instr.operand_count ( ) < 1 || ops [ 0 ].type != X86_OP_IMM ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	uint8_t vector = static_cast< uint8_t >( ops [ 0 ].imm & 0xFF );
	switch ( vector ) {
		case 0x00:
		{
			effect.push_to_changes ( state, "INT 0x0 - Divide Error" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_INT_DIVIDE_BY_ZERO, instr.ip ( ) );
			throw ex;
		}
		case 0x01:
		{
			effect.push_to_changes ( state, "INT 0x01 - Debug Exception" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_SINGLE_STEP, instr.ip ( ) );
			throw ex;
		}
		case 0x02:
		{
			effect.push_to_changes ( state, "INT 0x02 - Non-Maskable Interrupt" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_NONCONTINUABLE_EXCEPTION, instr.ip ( ) );
			throw ex;
		}
		case 0x03:
		{
			effect.push_to_changes ( state, "INT 0x03 - Breakpoint" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_BREAKPOINT, instr.ip ( ) );
			throw ex;
		}
		case 0x04:
		{
			effect.push_to_changes ( state, "INT 0x04 - Overflow" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_INT_OVERFLOW, instr.ip ( ) );
			throw ex;
		}
		case 0x05:
		{
			effect.push_to_changes ( state, "INT 0x05 - Bounds Check" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ARRAY_BOUNDS_EXCEEDED, instr.ip ( ) );
			throw ex;
		}
		case 0x06:
		{
			effect.push_to_changes ( state, "INT 0x06 - Invalid Opcode" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x07:
		{
			effect.push_to_changes ( state, "INT 0x07 - Device Not Available" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x08:
		{
			effect.push_to_changes ( state, "INT 0x08 - Double Fault" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x09:
		{
			effect.push_to_changes ( state, "INT 0x09 - Coprocessor Segment Overrun" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x0A:
		{
			effect.push_to_changes ( state, "INT 0x0A - Invalid TSS" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x0B:
		{
			effect.push_to_changes ( state, "INT 0x0B - Segment Not Present" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x0C:
		{
			effect.push_to_changes ( state, "INT 0x0C - Stack-Segment Fault" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ACCESS_VIOLATION, instr.ip ( ) );
			throw ex;
		}
		case 0x0D:
		{
			effect.push_to_changes ( state, "INT 0x0D - General Protection Fault" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ACCESS_VIOLATION, instr.ip ( ) );
			throw ex;
		}
		case 0x0E:
		{
			effect.push_to_changes ( state, "INT 0x0E - Page Fault" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ACCESS_VIOLATION, instr.ip ( ) );
			throw ex;
		}
		case 0x10:
		{
			effect.push_to_changes ( state, "INT 0x10 - x87 FPU Math Fault" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x11:
		{
			effect.push_to_changes ( state, "INT 0x11 - Alignment Check" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_DATATYPE_MISALIGNMENT, instr.ip ( ) );
			throw ex;
		}
		case 0x12:
		{
			effect.push_to_changes ( state, "INT 0x12 - Machine Check" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_NONCONTINUABLE_EXCEPTION, instr.ip ( ) );
			throw ex;
		}
		case 0x13:
		{
			effect.push_to_changes ( state, "INT 0x13 - SIMD FP Exception" );
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
		case 0x29:
		{
			uint8_t ch = static_cast< uint8_t >( state.get_reg<uint32_t> ( X86_REG_EAX ) & 0xFF );
			effect.push_to_changes (
					state,
					std::format ( "INT29 -> byte 0x{:02x} ('{}')", ch, static_cast< char >( ch ) )
			);
			state.console_output.push_back ( static_cast< char >( ch ) );
			uint32_t next_eip = static_cast< uint32_t >( instr.ip ( ) + instr.length ( ) );
			state.set_reg ( X86_REG_EIP, next_eip, 4, effect );
			effect.modified_regs.insert ( X86_REG_EIP );
			return;
		}
		default:
		{
			GuestExceptionInfo ex;
			ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
			throw ex;
		}
	}
}

void fxsave ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) != 1 || ops [ 0 ].type != X86_OP_MEM ) {
		effect.push_to_changes ( state, "FXSAVE: Invalid operand (must be memory)." );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	uint64_t base_addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
	if ( state.exit_due_to_critical_error ) return;

	// --- Save FPU State ---
	// 0-1: FCW
	state.set_memory ( base_addr + 0, state.cpu->fpu.fpu_control_word, 2, effect );
	// 2-3: FSW
	state.set_memory ( base_addr + 2, state.cpu->fpu.fpu_status_word, 2, effect );
	// 4-5: FTW (Abridged FPU Tag Word - compact form)
	// Each ST(i) has a 2-bit tag. FTW[i] = tag_is_empty(ST(i)) ? 1 : 0
	// This is the "abridged" version for FXSAVE.
	// The full 16-bit FPU Tag Word (FTW) has 2 bits per register.
	// FXSAVE saves an 8-bit "FTW" (sometimes called FTAG or Abridged FTW)
	// where bit i corresponds to ST(i). Bit is 0 if tag is valid/zero/special, 1 if empty.
	uint8_t ftag = 0;
	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = state.get_fpu_phys_idx ( i );
		if ( state.get_fpu_tag ( phys_idx ) == FPU_TAG_EMPTY ) {
			ftag |= ( 1 << i );
		}
	}
	state.set_memory ( base_addr + 4, ftag, 1, effect ); // Store as byte
	state.set_memory ( base_addr + 5, 0, 1, effect );    // Reserved byte after FTAG, should be 0.
	// Some diagrams show FTW as 2 bytes, with byte 5 being part of it.
	// Let's be safe and zero byte 5.

// 6-7: FOP (Last FPU Opcode)
// This is usually the last non-control FPU instruction's opcode (11 bits).
// Emulating this accurately is complex. For now, set to 0.
	state.set_memory ( base_addr + 6, 0, 2, effect );

	// 8-15: FIP (FPU Instruction Pointer - 64-bit in 64-bit mode)
	// This should be the RIP of the last non-control FPU instruction. Complex to track perfectly.
	// For now, 0 or a placeholder. Ideally, it would be the RIP of the last x87 instruction.
	uint64_t last_fpu_instr_ip = 0; // Placeholder
	state.set_memory ( base_addr + 8, last_fpu_instr_ip, 8, effect );

	// 16-23: FDP (FPU Data Pointer - 64-bit in 64-bit mode)
	// Address of the last FPU memory operand. Also complex.
	uint64_t last_fpu_data_ptr = 0; // Placeholder
	state.set_memory ( base_addr + 16, last_fpu_data_ptr, 8, effect );

	// --- Save SSE/MXCSR State ---
	// 24-27: MXCSR
	state.set_memory ( base_addr + 24, *( uint32_t* ) &state.cpu->cpu_flags.mxcsr, 4, effect );
	// 28-31: MXCSR_MASK (Typically 0x0000FFBF, can be changed by LDMXCSR but rare for mask)
	state.set_memory ( base_addr + 28, 0x0000FFBF, 4, effect );

	// --- Save ST(i)/MMX Registers ---
	// 32-159: ST0/MM0 through ST7/MM7 (8 registers * 16 bytes/reg = 128 bytes)
	// Each 80-bit FPU register is saved in a 16-byte memory region, bottom-aligned.
	// The upper 6 bytes of each 16-byte region are reserved and should be written as 0.
	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = state.get_fpu_phys_idx ( i ); // Get physical stack index for ST(i)
		const float80_t& st_val = state.cpu->fpu.fpu_stack [ phys_idx ];
		uint64_t current_reg_addr = base_addr + 32 + ( i * 16 );

		// This is tricky. float80_t needs to be serialized to 10 bytes.
		// For simplicity, if write_float80_to_memory handles the 10-byte write:
		state.write_float80_to_memory ( current_reg_addr, st_val, effect );
		// Then zero out the remaining 6 reserved bytes in that 16-byte slot
		for ( int j = 10; j < 16; ++j ) {
			state.set_memory ( current_reg_addr + j, 0, 1, effect );
		}
	}

	// --- Save XMM Registers ---
	// 160-415: XMM0 through XMM15 (16 registers * 16 bytes/reg = 256 bytes)
	for ( int i = 0; i < 16; ++i ) {
		x86_reg xmm_reg = static_cast< x86_reg > ( X86_REG_XMM0 + i );
		uint128_t xmm_val = state.get_xmm_raw ( xmm_reg );
		state.set_memory_128 ( base_addr + 160 + ( i * 16 ), xmm_val, effect );
	}

	// 416-511: Reserved, must be zeroed by FXSAVE. (96 bytes)
	for ( int i = 0; i < 96; i += 8 ) { // Zero out in 8-byte chunks
		state.set_memory ( base_addr + 416 + i, 0, 8, effect );
	}

	effect.push_to_changes ( state, std::format ( "fxsave to [0x{:016x}]", base_addr ) );
	// FXSAVE does not modify any flags.
}

void fxrstor ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) != 1 || ops [ 0 ].type != X86_OP_MEM ) {
		effect.push_to_changes ( state, "FXRSTOR: Invalid operand (must be memory)." );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	uint64_t base_addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
	if ( state.exit_due_to_critical_error ) return;

	// Alignment Check: Must be 16-byte aligned
	if ( ( base_addr % 16 ) != 0 ) {
		effect.push_to_changes ( state, std::format ( "FXRSTOR: Misaligned memory access at 0x{:x} (must be 16-byte aligned).", base_addr ) );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ACCESS_VIOLATION, instr.ip ( ), base_addr ); // #GP(0)
		throw ex;
	}

	// --- Restore FPU State ---
	// 0-1: FCW
	uint16_t fcw = static_cast< uint16_t >( state.get_memory ( base_addr + 0, 2 ) );
	// Check reserved bits in FCW (bits 6, 7, 13, 14, 15 must be 0 for FXRSTOR)
	if ( ( fcw & 0xE0C0 ) != 0 ) { // Mask for bits 6,7,13,14,15
		effect.push_to_changes ( state, std::format ( "FXRSTOR: FCW 0x{:04x} has reserved bits set.", fcw ) );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ACCESS_VIOLATION, instr.ip ( ) ); throw ex; // #GP
	}
	state.cpu->fpu.fpu_control_word = fcw;

	// 2-3: FSW
	uint16_t fsw = static_cast< uint16_t >( state.get_memory ( base_addr + 2, 2 ) );
	// FSW reserved bits are implicitly handled by what we store/use.
	state.cpu->fpu.fpu_status_word = fsw;
	state.cpu->fpu.fpu_top = ( fsw & FSW_TOP_MASK ) >> FSW_TOP_SHIFT; // Update TOP from FSW

	// 4-5: FTW (Abridged FPU Tag Word)
	uint8_t ftag_abridged = static_cast< uint8_t >( state.get_memory ( base_addr + 4, 1 ) );
	// Convert abridged FTAG back to full 16-bit FTW for internal representation
	// An abridged bit of 1 means EMPTY. 0 means NOT EMPTY (valid, zero, or special).
	// For FXRSTOR, if a tag is loaded as "not empty", the actual ST(i) content determines if it's V/Z/S.
	// The TAG word is restored based on the value in memory.
	// For now, we'll just store the tags. A full FPU model would validate ST(i) against its tag.
	state.cpu->fpu.fpu_tag_word = 0; // Will be reconstructed based on loaded ST values later.
	// The FTAG in memory is more of a hint for FXRSTOR.
	// The actual tags will be re-evaluated when ST registers are loaded.

// 6-7: FOP (FPU Opcode) - Loaded, but its use in emulation is minor unless for deep x87 exception debugging.
// state.cpu->fpu.fpu_last_opcode = static_cast<uint16_t>(state.get_memory(base_addr + 6, 2));

// 8-15: FIP (FPU Instruction Pointer - 64-bit)
// state.cpu->fpu.fpu_last_ip = state.get_memory(base_addr + 8, 8);

// 16-23: FDP (FPU Data Pointer - 64-bit)
// state.cpu->fpu.fpu_last_dp = state.get_memory(base_addr + 16, 8);

// --- Restore SSE/MXCSR State ---
// 24-27: MXCSR
	uint32_t mxcsr_val = static_cast< uint32_t >( state.get_memory ( base_addr + 24, 4 ) );
	// Check reserved bits in MXCSR (bits 16-31 must be 0)
	if ( ( mxcsr_val >> 16 ) != 0 ) {
		effect.push_to_changes ( state, std::format ( "FXRSTOR: MXCSR 0x{:08x} has reserved bits set.", mxcsr_val ) );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ACCESS_VIOLATION, instr.ip ( ) ); throw ex; // #GP
	}
	*( uint32_t* ) &state.cpu->cpu_flags.mxcsr = mxcsr_val;

	// 28-31: MXCSR_MASK - Generally not loaded by FXRSTOR; MXCSR is validated against the current CPU's mask.
	// uint32_t mxcsr_mask_from_mem = static_cast<uint32_t>(state.get_memory(base_addr + 28, 4));
	// For simplicity, we assume MXCSR value itself was valid or FXSAVE produced a valid one.

	// --- Restore ST(i)/MMX Registers ---
	// 32-159: ST0/MM0 through ST7/MM7 (8 registers * 16 bytes/reg = 128 bytes)
	// Each 80-bit FPU register is loaded from a 16-byte memory region.
	// The upper 6 bytes are ignored.
	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = state.get_fpu_phys_idx ( i ); // Get physical stack index for ST(i)
		uint64_t current_reg_addr = base_addr + 32 + ( i * 16 );
		state.cpu->fpu.fpu_stack [ phys_idx ] = state.read_float80_from_memory ( current_reg_addr, effect );
		// After loading all ST regs, re-evaluate and set tags based on loaded values and the FTAG from memory.
		// This is important because the FTAG from memory only says "empty" or "not empty".
		// If "not empty", the actual value determines if it's V, Z, or S.
		if ( ( ftag_abridged >> i ) & 1 ) { // If abridged tag says empty
			state.set_fpu_tag ( phys_idx, FPU_TAG_EMPTY );
		}
		else { // Abridged tag says not empty, classify based on loaded value.
			state.set_fpu_tag ( phys_idx, state.classify_fpu_operand ( state.cpu->fpu.fpu_stack [ phys_idx ] ) );
		}
	}

	// --- Restore XMM Registers ---
	// 160-415: XMM0 through XMM15 (16 registers * 16 bytes/reg = 256 bytes)
	for ( int i = 0; i < 16; ++i ) {
		x86_reg xmm_reg = static_cast< x86_reg > ( X86_REG_XMM0 + i );
		uint128_t xmm_val = state.get_memory_128 ( base_addr + 160 + ( i * 16 ) );
		state.set_xmm_raw ( xmm_reg, xmm_val, effect );
	}

	// 416-511: Reserved, ignored by FXRSTOR.

	effect.push_to_changes ( state, std::format ( "fxrstor from [0x{:016x}]", base_addr ) );
	// FXRSTOR can change all the loaded FPU/SSE flags and registers.
}

// And register it in bind_cpu():
void helpers::bind_cpu ( ) {
	BIND ( rdtsc );
	BIND ( cpuid );
	BIND ( xgetbv );
	BIND ( syscall );
	BIND ( int_ );
	BIND ( int1 );
	BIND ( int3 );
	BIND ( fxsave );
	BIND ( fxrstor );

	BIND ( hlt );
}

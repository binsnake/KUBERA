#include "pch.hpp"

void mov ( capstone::Instruction& instr,
				 EmulationContext& state,
				 InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	const uint8_t    size = ops [ 0 ].size;

	if ( state.get_reg<uint64_t> ( X86_REG_RSP ) !=
			reinterpret_cast< uint64_t >( state.rsp_base.get ( ) + state.cpu->rsp_offset ) ) {
		state.set_reg ( X86_REG_RSP,
									reinterpret_cast< uint64_t >( state.rsp_base.get ( ) + state.cpu->rsp_offset ),
									8, effect );
	}

	const uint64_t src = helpers::get_src<uint64_t> ( &instr, 1, state, size );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, src, size, effect );
		return;
	}

	const uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );

	if ( state.is_within_stack_bounds ( addr, size ) ) {
		state.set_stack ( addr, src, effect, size );
	}
	else {
		state.set_memory ( addr, src, size, effect );
		effect.push_to_changes ( state,
				std::format ( "[{:016x}] = {:#x} (size={})", addr, src, size ) );
	}

	effect.modified_mem.insert ( addr );
}


void movabs ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	x86_reg dst = ops [ 0 ].reg;
	uint64_t imm = ops [ 1 ].imm;

	state.set_reg ( dst, imm, 8, effect );
}

void movaps ( capstone::Instruction& instr,
						EmulationContext& ctx,
						InstructionEffect& eff ) {
	auto ops = instr.operands ( );
	const auto& dst = ops [ 0 ];
	const auto& src = ops [ 1 ];

	if ( dst.type == X86_OP_REG && src.type == X86_OP_REG ) {
		ctx.set_xmm_raw ( dst.reg, ctx.get_xmm_raw ( src.reg ), eff );
		eff.push_to_changes ( ctx,
			std::format ( "XMM{}=XMM{}", dst.reg - X86_REG_XMM0, src.reg - X86_REG_XMM0 ) );
		return;
	}

	if ( dst.type == X86_OP_REG && src.type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( src, instr, ctx );
		if ( addr % 16 != 0 ) {
			if ( ctx.cpu->cpu_flags.flags.AC ) throw GuestExceptionInfo {/*...*/ };
			return;
		}
		auto val = ctx.get_memory_128 ( addr );
		ctx.set_xmm_raw ( dst.reg, val, eff );
		eff.push_to_changes ( ctx,
			std::format ( "XMM{}=[0x{:016x}]", dst.reg - X86_REG_XMM0, addr ) );
		eff.modified_mem.insert ( addr );
		return;
	}

	if ( dst.type == X86_OP_MEM && src.type == X86_OP_REG ) {
		uint64_t addr = helpers::calculate_mem_addr ( dst, instr, ctx );
		if ( addr % 16 != 0 ) return;
		auto val = ctx.get_xmm_raw ( src.reg );
		if ( ctx.is_within_stack_bounds ( addr, 16 ) )
			ctx.set_stack_128 ( addr, val, eff );
		else
			ctx.set_memory_128 ( addr, val, eff );
		eff.push_to_changes ( ctx,
			std::format ( "[0x{:016x}]=XMM{}", addr, src.reg - X86_REG_XMM0 ) );
		eff.modified_mem.insert ( addr );
		return;
	}

	std::println ( "MOVAPS: unsupported at 0x{:x}", instr.ip ( ) );
}

void movzx ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( ); // ops[0] is DEST, ops[1] is SRC

	// Validate destination: must be a register
	if ( ops [ 0 ].type != X86_OP_REG ) {
		effect.push_to_changes ( state, std::format ( "MOVZX Error: Destination operand is not a register at IP 0x{:x}", instr.ip ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}
	x86_reg dst_reg = ops [ 0 ].reg;
	uint8_t dst_size = ops [ 0 ].size;

	// Validate source: must be register or memory
	const cs_x86_op& src_op = ops [ 1 ];
	if ( src_op.type != X86_OP_REG && src_op.type != X86_OP_MEM ) {
		effect.push_to_changes ( state, std::format ( "MOVZX Error: Source operand is not register or memory at IP 0x{:x}", instr.ip ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}
	uint8_t src_size = src_op.size;

	// Validate operand sizes for MOVZX
	// Valid forms (src_size -> possible dst_sizes):
	// 1 (byte)  -> 2 (word), 4 (dword), 8 (qword)
	// 2 (word)  -> 4 (dword), 8 (qword)
	// 4 (dword) -> 8 (qword) (e.g., movzx rax, ebx; requires REX.W if src is GPR)
	bool valid_size_combination = false;
	if ( src_size == 1 && ( dst_size == 2 || dst_size == 4 || dst_size == 8 ) ) {
		valid_size_combination = true;
	}
	else if ( src_size == 2 && ( dst_size == 4 || dst_size == 8 ) ) {
		valid_size_combination = true;
	}
	else if ( src_size == 4 && dst_size == 8 ) {
		valid_size_combination = true;
	}

	if ( !valid_size_combination ) {
		effect.push_to_changes ( state, std::format ( "MOVZX Error: Invalid operand size combination (src: {}, dst: {}) at IP 0x{:x}", src_size, dst_size, instr.ip ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	// Fetch the source value using its actual size.
	// helpers::get_src should correctly retrieve 'src_size' bytes from the source operand.
	uint64_t src_val_raw = helpers::get_src<uint64_t> ( &instr, 1, state, src_size );

	// Create a mask for the source operand's actual size.
	// GET_OPERAND_MASK is defined in context.hpp:
	// #define GET_OPERAND_MASK(x, y) uint64_t x = (1ULL << (y*8)) - 1; if (y == 8) {x = 0xFFFFFFFFFFFFFFFFULL;}
	GET_OPERAND_MASK ( source_mask, src_size );

	// Apply the mask to ensure only the source operand's bits are considered.
	// This effectively performs the zero-extension because src_val_raw is uint64_t.
	uint64_t value_to_set = src_val_raw & source_mask;

	// Set the destination register.
	// EmulationContext::set_reg handles writing to partial registers and
	// zeroing upper bits for 32-bit destinations (e.g., EAX when RAX is the full register).
	state.set_reg ( dst_reg, value_to_set, dst_size, effect );
}

void push ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto src = helpers::get_src<uint64_t> ( &instr, 0, state, instr.operands ( ) [ 0 ].size );

	state.allocate_stack ( 8, effect );

	uint64_t new_rsp = state.get_reg ( X86_REG_RSP );
	state.set_stack ( new_rsp, src, effect, 8 );
	effect.modified_mem.insert ( new_rsp );
}

void pop ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t dst_op_size = ops [ 0 ].size;
	int64_t stack_addr = state.get_reg ( X86_REG_RSP );
	auto val_popped = state.get_stack ( stack_addr, false );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		uint64_t result = val_popped;
		state.set_reg ( ops [ 0 ].reg, result, dst_op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		int64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		state.set_memory ( addr, val_popped, 8, effect );
		effect.modified_mem.insert ( addr );
	}


	uint64_t new_rsp = stack_addr + 8; // Increment RSP by 8
	state.set_reg ( X86_REG_RSP, new_rsp, 8, effect );

	state.stack_allocated -= 8; // Decrease allocation tracking
	if ( state.stack_allocated < 0 ) state.stack_allocated = 0; // Prevent underflow

	if ( state.options.enable_logging ) {
		effect.push_to_changes ( state, std::format ( "Adjusted stack allocation by -0x8" ) );
	}
}

void lea ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t dst_size = ops [ 0 ].size;
	x86_reg dst_reg = ops [ 0 ].reg;
	const cs_x86_op& mem_op = ops [ 1 ]; // Source is memory operand structure

	uint64_t effective_address = 0;

	// --- FIX: Handle RIP-relative addressing directly ---
	if ( mem_op.mem.base == X86_REG_RIP ) {
		effective_address = static_cast< int64_t >( instr.ip ( ) + instr.length ( ) ) + mem_op.mem.disp;
		if ( mem_op.mem.index != X86_REG_INVALID ) {
			std::print ( "Warning: LEA with RIP-relative addressing should not have an index register in instruction {}\n", instr.to_string ( ) );
			// Decide how to handle - ignore index? error? For LEA, we just calculate, so ignoring might be okay.
		}
	}
	// --- Handle other addressing modes ---
	else {
		if ( mem_op.mem.base != X86_REG_INVALID ) {
			uint64_t base_val = state.get_reg ( mem_op.mem.base, 8 ); // Address calculation uses 64-bit regs
			effective_address = base_val;
		}
		if ( mem_op.mem.index != X86_REG_INVALID ) {
			uint64_t index_val = state.get_reg ( mem_op.mem.index, 8 );
			effective_address += index_val * mem_op.mem.scale;
		}
		effective_address += mem_op.mem.disp;
	}

	// --- END FIX ---


	// Store the calculated effective address in the destination register
	// Truncate/zero-extend according to destination register size (set_reg handles this)
	state.set_reg ( dst_reg, effective_address, dst_size, effect );

	// Updatestate.rsp_offsetif RSP was the destination
	if ( dst_reg == X86_REG_RSP ) {
		// Syncstate.rsp_offset*after* RSP is updated
	}
}
void movsx ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t dst_size = ops [ 0 ].size;
	uint8_t src_size = ops [ 1 ].size;
	auto dst = ops [ 0 ].reg;
	auto src = helpers::get_src<uint64_t> ( &instr, 1, state, src_size );
	uint64_t val = src;
	if ( src_size == 1 ) val = static_cast< int8_t >( val );
	else if ( src_size == 2 ) val = static_cast< int16_t >( val );
	else if ( src_size == 4 ) val = static_cast< int32_t >( val );
	state.set_reg ( dst, val, dst_size, effect );
}

void sahf ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	USE_FLAG_LOGGER ( );
	auto ah = state.get_reg ( X86_REG_AH, 1 );
	uint8_t ah_val = static_cast< uint8_t >( ah );
	auto& flags = state.cpu->cpu_flags.flags;
	flags.SF = ( ( ah_val >> 7 ) & 1 );
	flags.ZF = ( ( ah_val >> 6 ) & 1 );
	flags.AF = ( ( ah_val >> 4 ) & 1 );
	flags.PF = ( ( ah_val >> 2 ) & 1 );
	flags.CF = ( ah_val & 1 );
}

void lahf ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto& flags = state.cpu->cpu_flags.flags;
	uint8_t ah_val = static_cast< uint8_t >( ( flags.SF << 7 ) | ( flags.ZF << 6 ) |
		( flags.AF << 4 ) | ( flags.PF << 2 ) |
		( flags.CF ) );
	state.set_reg ( X86_REG_AH, ah_val, 1, effect );
}

void movsxd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t dst_size = ops [ 0 ].size;
	uint8_t src_size = ops [ 1 ].size;
	auto dst = ops [ 0 ].reg;
	auto src = helpers::get_src<uint64_t> ( &instr, 1, state, src_size );
	uint64_t val = static_cast< int32_t >( src );
	state.set_reg ( dst, val, dst_size, effect );
}

void xchg ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	auto val1 = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	x86_reg reg1 = ( ops [ 0 ].type == X86_OP_REG ) ? ops [ 0 ].reg : X86_REG_INVALID;
	int64_t addr1 = ( ops [ 0 ].type == X86_OP_MEM ) ?
		state.get_reg ( ops [ 0 ].mem.base ) + ops [ 0 ].mem.disp : 0;

	auto val2 = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	x86_reg reg2 = ( ops [ 1 ].type == X86_OP_REG ) ? ops [ 1 ].reg : X86_REG_INVALID;
	int64_t addr2 = ( ops [ 1 ].type == X86_OP_MEM ) ?
		state.get_reg ( ops [ 1 ].mem.base ) + ops [ 1 ].mem.disp : 0;

	if ( ops [ 0 ].type == X86_OP_REG && ops [ 1 ].type == X86_OP_REG ) {
		state.set_reg ( reg1, val2, op_size, effect );
		state.set_reg ( reg2, val1, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM && ops [ 1 ].type == X86_OP_REG ) {
		state.set_memory ( addr1, val2, 8, effect );
		state.set_reg ( reg2, val1, op_size, effect );
		effect.push_to_changes ( state, std::format ( "[{:016x}h] = {:#x}", addr1, val2 ) );
		effect.modified_mem.insert ( addr1 );
	}
	else if ( ops [ 0 ].type == X86_OP_REG && ops [ 1 ].type == X86_OP_MEM ) {
		state.set_reg ( reg1, val2, op_size, effect );
		state.set_memory ( addr2, val1, 8, effect );
		effect.push_to_changes ( state, std::format ( "[{:016x}h] = {:#x}", addr2, val1 ) );
		effect.modified_mem.insert ( addr2 );
	}
}

void pushfq ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	// allocate 8 bytes
	state.allocate_stack ( 8, effect );

	uint64_t addr = state.get_reg ( X86_REG_RSP );
	uint64_t rflags = state.get_rflags ( );
	state.set_stack ( addr, rflags, effect );
	effect.modified_mem.insert ( addr );
}

void popfq ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	int64_t stack_addr = state.get_reg ( X86_REG_RSP );
	auto val = state.get_stack ( stack_addr );
	state.cpu->rsp_offset += 8;
	state.set_reg ( X86_REG_RSP, ( uint64_t ) state.rsp_base.get ( ) + state.cpu->rsp_offset, 8, effect );

	state.set_rflags ( val, effect );
}

void movups ( capstone::Instruction& instr,
						EmulationContext& ctx,
						InstructionEffect& eff ) {
	auto ops = instr.operands ( );
	const auto& dst = ops [ 0 ];
	const auto& src = ops [ 1 ];

	if ( dst.type == X86_OP_REG && src.type == X86_OP_REG ) {
		ctx.set_xmm_raw ( dst.reg, ctx.get_xmm_raw ( src.reg ), eff );
		eff.push_to_changes ( ctx,
			std::format ( "XMM{}=XMM{}", dst.reg - X86_REG_XMM0, src.reg - X86_REG_XMM0 ) );
		return;
	}

	if ( dst.type == X86_OP_REG && src.type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( src, instr, ctx );
		auto val = ctx.get_memory_128 ( addr );
		ctx.set_xmm_raw ( dst.reg, val, eff );
		eff.push_to_changes ( ctx,
			std::format ( "XMM{}=[0x{:016x}]", dst.reg - X86_REG_XMM0, addr ) );
		eff.modified_mem.insert ( addr );
		return;
	}

	if ( dst.type == X86_OP_MEM && src.type == X86_OP_REG ) {
		uint64_t addr = helpers::calculate_mem_addr ( dst, instr, ctx );
		auto val = ctx.get_xmm_raw ( src.reg );
		if ( ctx.is_within_stack_bounds ( addr, 16 ) )
			ctx.set_stack_128 ( addr, val, eff );
		else
			ctx.set_memory_128 ( addr, val, eff );
		eff.push_to_changes ( ctx,
			std::format ( "[0x{:016x}]=XMM{}", addr, src.reg - X86_REG_XMM0 ) );
		eff.modified_mem.insert ( addr );
		return;
	}

	std::println ( "MOVUPS: unsupported at 0x{:x}", instr.ip ( ) );
}

void movq ( capstone::Instruction& instr,
					EmulationContext& ctx,
					InstructionEffect& eff ) {
	const cs_x86_op* op = instr.operands ( );
	const cs_x86_op& dst = op [ 0 ];
	const cs_x86_op& src = op [ 1 ];

	constexpr uint8_t OP_SIZE = 8;

	if ( dst.type == X86_OP_REG && src.type == X86_OP_REG &&
			dst.reg >= X86_REG_XMM0 && dst.reg <= X86_REG_XMM15 &&
			src.reg >= X86_REG_XMM0 && src.reg <= X86_REG_XMM15 ) {
		uint64_t lo64 = ctx.get_xmm_raw ( src.reg ).convert_to<uint64_t> ( );
		ctx.set_xmm_raw ( dst.reg, lo64, eff );
		eff.push_to_changes ( ctx, std::format ( "XMM{} = XMM{} (64?bit)",
													dst.reg - X86_REG_XMM0,
													src.reg - X86_REG_XMM0 ) );
		return;
	}

	if ( dst.type == X86_OP_REG && src.type == X86_OP_REG &&
			dst.reg >= X86_REG_RAX && dst.reg <= X86_REG_R15 &&
			src.reg >= X86_REG_XMM0 && src.reg <= X86_REG_XMM15 ) {
		uint64_t lo64 = ctx.get_xmm_raw ( src.reg ).convert_to<uint64_t> ( );
		ctx.set_reg ( dst.reg, lo64, OP_SIZE, eff );
		eff.push_to_changes ( ctx, std::format ( "{} = XMM{} (64?bit)",
													cs_reg_name ( ctx.decoder.back ( )->get_handle ( ), dst.reg ),
													src.reg - X86_REG_XMM0 ) );
		return;
	}

	if ( dst.type == X86_OP_REG && src.type == X86_OP_REG &&
			dst.reg >= X86_REG_XMM0 && dst.reg <= X86_REG_XMM15 &&
			src.reg >= X86_REG_RAX && src.reg <= X86_REG_R15 ) {
		uint64_t val = ctx.get_reg ( src.reg, OP_SIZE );
		ctx.set_xmm_raw ( dst.reg, val, eff );
		eff.push_to_changes ( ctx, std::format ( "XMM{} = {} (64?bit)",
													dst.reg - X86_REG_XMM0,
													cs_reg_name ( ctx.decoder.back ( )->get_handle ( ), src.reg ) ) );
		return;
	}

	if ( dst.type == X86_OP_REG && src.type == X86_OP_MEM &&
			dst.reg >= X86_REG_XMM0 && dst.reg <= X86_REG_XMM15 ) {
		uint64_t addr = helpers::calculate_mem_addr ( src, instr, ctx );
		uint64_t lo64 = ctx.get_memory ( addr, OP_SIZE );
		ctx.set_xmm_raw ( dst.reg, lo64, eff );
		eff.push_to_changes ( ctx, std::format ( "XMM{} = [0x{:016x}] (64?bit)",
													dst.reg - X86_REG_XMM0, addr ) );
		eff.modified_mem.insert ( addr );
		return;
	}


	if ( dst.type == X86_OP_MEM && src.type == X86_OP_REG &&
			src.reg >= X86_REG_XMM0 && src.reg <= X86_REG_XMM15 ) {
		uint64_t addr = helpers::calculate_mem_addr ( dst, instr, ctx );
		uint64_t lo64 = ctx.get_xmm_raw ( src.reg ).convert_to<uint64_t> ( );

		if ( ctx.is_within_stack_bounds ( addr, OP_SIZE ) )
			ctx.set_stack ( addr, lo64, eff, OP_SIZE );
		else
			ctx.set_memory ( addr, lo64, OP_SIZE, eff );

		eff.push_to_changes ( ctx, std::format ( "[0x{:016x}] = XMM{} (64?bit)",
													addr, src.reg - X86_REG_XMM0 ) );
		eff.modified_mem.insert ( addr );
		return;
	}

	std::println ( "MOVQ: unsupported operand combination at 0x{:016x}", instr.ip ( ) );
}

void cmpxchg ( capstone::Instruction& instr,
						 EmulationContext& state,
						 InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t          op_size = ops [ 0 ].size ? ops [ 0 ].size : 8;

	if ( op_size != 1 && op_size != 2 && op_size != 4 && op_size != 8 ) {
		effect.push_to_changes ( state,
				 std::format ( "cmpxchg: unsupported operand size {}", op_size ) );
		state.exit_due_to_critical_error = true;
		return;
	}
	const uint64_t mask = ( op_size == 8 )
		? 0xFFFFFFFFFFFFFFFFull
		: ( ( 1ull << ( op_size * 8 ) ) - 1ull );


	bool     dst_is_mem = ( ops [ 0 ].type == X86_OP_MEM );
	uint64_t dst_addr = 0;
	uint64_t dst_val = 0;

	if ( dst_is_mem ) {
		dst_addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );

		dst_val = state.is_within_stack_bounds ( dst_addr, op_size )
			? state.get_stack ( dst_addr, false )
			: state.get_memory ( dst_addr, op_size );
	}
	else {
		dst_val = state.get_reg ( ops [ 0 ].reg, op_size );
	}
	dst_val &= mask;

	uint64_t rax_full = state.get_reg ( X86_REG_RAX, 8 );
	uint64_t acc_bits = rax_full & mask;
	uint64_t src_bits = state.get_reg ( ops [ 1 ].reg, op_size ) & mask;

	bool has_lock = instr.prefix ( ) [ 0 ] == X86_PREFIX_LOCK;

	bool success = ( acc_bits == dst_val );
	auto next_zf = 0;
	if ( success ) {
		if ( dst_is_mem ) {
			if ( state.is_within_stack_bounds ( dst_addr, op_size ) )
				state.set_stack ( dst_addr, src_bits, effect, op_size );
			else
				state.set_memory ( dst_addr, src_bits, op_size, effect );

			effect.modified_mem.insert ( dst_addr );
			effect.push_to_changes ( state,
					std::format ( "[0x{:016x}] = 0x{:x} (cmpxchg ok{})",
															 dst_addr, src_bits, has_lock ? ", lock" : "" ) );
		}
		else {
			state.set_reg ( ops [ 0 ].reg, src_bits, op_size, effect );
			effect.modified_regs.insert ( ops [ 0 ].reg );
		}

		next_zf = 1;
	}
	else {
		uint64_t new_rax = ( rax_full & ~mask ) | dst_val;
		state.set_reg ( X86_REG_RAX, new_rax, 8, effect );
		effect.modified_regs.insert ( X86_REG_RAX );

		effect.push_to_changes ( state,
				std::format ( "RAX = 0x{:x} (cmpxchg fail{})",
														 dst_val, has_lock ? ", lock" : "" ) );
	}

	state.update_flags_sub ( acc_bits, dst_val, op_size, effect );
	state.cpu->cpu_flags.flags.ZF = next_zf;
}


void cmpxchg16b ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	USE_FLAG_LOGGER ( );
	const cs_x86_op* ops = instr.operands ( );

	if ( ops [ 0 ].type != X86_OP_MEM ) {
		effect.push_to_changes ( state, "CMPXCHG16B: Operand must be memory" );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );

	if ( addr % 16 != 0 ) {
		throw GuestExceptionInfo { };
	}

	uint128_t mem_val = state.get_memory_128 ( addr );

	uint64_t rax = state.get_reg ( X86_REG_RAX, 8 );
	uint64_t rdx = state.get_reg ( X86_REG_RDX, 8 );
	uint128_t rdx_rax = ( uint128_t ( rdx ) << 64 ) | rax;

	uint64_t rbx = state.get_reg ( X86_REG_RBX, 8 );
	uint64_t rcx = state.get_reg ( X86_REG_RCX, 8 );
	uint128_t rcx_rbx = ( uint128_t ( rcx ) << 64 ) | rbx;

	bool equal = ( mem_val == rdx_rax );

	bool has_lock = instr.prefix ( ) [ 0 ] == X86_PREFIX_LOCK;

	if ( equal ) {
		if ( state.is_within_stack_bounds ( addr, 16 ) ) {
			state.set_stack_128 ( addr, rcx_rbx, effect );
		}
		else {
			state.set_memory_128 ( addr, rcx_rbx, effect );
		}
		effect.modified_mem.insert ( addr );
		effect.push_to_changes ( state, std::format ( "CMPXCHG16B: Set [0x{:016x}] to RCX:RBX (success{})",
														 addr, has_lock ? ", lock" : "" ) );
	}
	else {
		uint64_t mem_low = static_cast< uint64_t >( mem_val );
		uint64_t mem_high = static_cast< uint64_t >( mem_val >> 64 );
		state.set_reg ( X86_REG_RAX, mem_low, 8, effect );
		state.set_reg ( X86_REG_RDX, mem_high, 8, effect );
		effect.push_to_changes ( state, std::format ( "CMPXCHG16B: Set RDX:RAX to [0x{:016x}] (fail{})",
														 addr, has_lock ? ", lock" : "" ) );
	}

	state.cpu->cpu_flags.flags.ZF = equal ? 1 : 0;
}



void stos ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint8_t op_size = 0;
	const char* size_suffix = "";

	switch ( instr.mnemonic ( ) ) {
		case X86_INS_STOSB:
			op_size = 1;
			size_suffix = "BYTE";
			break;
		case X86_INS_STOSW:
			op_size = 2;
			size_suffix = "WORD";
			break;
		case X86_INS_STOSD:
			op_size = 4;
			size_suffix = "DWORD";
			break;
		case X86_INS_STOSQ:
			op_size = 8;
			size_suffix = "QWORD";
			break;
		default:
			effect.push_to_changes ( state, std::format ( "STOS: Unexpected instruction ID {}", instr.mnemonic ( ) ) );
			state.exit_due_to_critical_error = true;
			return;
	}

	bool is_rep = instr.is_rep ( );
	auto rdi_emu = state.get_reg ( X86_REG_RDI, 8 );
	auto rax_emu = state.get_reg ( X86_REG_RAX, 8 );
	bool df = state.cpu->cpu_flags.flags.DF != 0;
	int64_t step = df ? -static_cast< int64_t >( op_size ) : static_cast< int64_t >( op_size );

	uint64_t rdi_val = rdi_emu;
	uint64_t rax_val = rax_emu;
	int64_t count = 1;
	int64_t initial_rcx = 0;

	if ( is_rep ) {
		initial_rcx = state.get_reg ( X86_REG_RCX, 8 );
		count = initial_rcx;

		if ( count <= 0 ) {
			effect.push_to_changes ( state, std::format ( "REP STOS: RCX is 0 or negative ({}), no memory operation.", count ) );
			state.set_reg ( X86_REG_RCX, 0ULL, 8, effect );
			return;
		}
		effect.push_to_changes ( state, std::format ( "REP STOS{}: Count = {} ({:x}h)", size_suffix, count, count ) );
	}

	GET_OPERAND_MASK ( operand_mask, op_size );
	const auto masked_rax_val = rax_val & operand_mask;
	int64_t initial_rdi = rdi_val;

	for ( int64_t i = 0; i < count; ++i ) {
		int64_t current_dst_addr = rdi_val;

		state.set_memory ( current_dst_addr, masked_rax_val, op_size, effect );
		effect.modified_mem.insert ( current_dst_addr );

		rdi_val += step;
	}

	state.set_reg ( X86_REG_RDI, rdi_val, 8, effect );
	if ( is_rep ) {
		state.set_reg ( X86_REG_RCX, 0ULL, 8, effect );
		effect.push_to_changes ( state, std::format ( "Stored value 0x{:x} ({} bytes from RAX) {} times.",
														 masked_rax_val, op_size, count ) );
		effect.push_to_changes ( state, std::format ( "RDI: 0x{:016x} -> 0x{:016x}", initial_rdi, rdi_val ) );
		effect.push_to_changes ( state, std::format ( "RCX: 0x{:016x} -> 0h", initial_rcx ) );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Stored value 0x{:x} ({} bytes from RAX) to [0x{:016x}].",
														 masked_rax_val, op_size, initial_rdi ) );
		effect.push_to_changes ( state, std::format ( "RDI: 0x{:016x} -> 0x{:016x}", initial_rdi, rdi_val ) );
	}
}




static void movs_rep (
		capstone::Instruction& instr,
		EmulationContext& ctx,
		InstructionEffect& eff,
		uint8_t elemSize /* 1,2,4,8 */ ) {
	bool rep = instr.is_rep ( );
	uint64_t count = rep ? ctx.get_reg ( X86_REG_RCX, 8 ) : 1;
	if ( !count ) return;

	bool df = ( ctx.cpu->cpu_flags.flags.DF != 0 );
	int64_t step = df ? -int64_t ( elemSize ) : int64_t ( elemSize );

	uint64_t rsi = ctx.get_reg ( X86_REG_RSI, 8 );
	uint64_t rdi = ctx.get_reg ( X86_REG_RDI, 8 );

	for ( uint64_t i = 0; i < count; ++i ) {
		uint64_t src = rsi + i * step;
		uint64_t dst = rdi + i * step;
		try {
			auto val = ctx.get_memory ( src, elemSize );
			ctx.set_memory ( dst, val, elemSize, eff );
			eff.modified_mem.insert ( dst );
		}
		catch ( const GuestExceptionInfo& ) {
			break;
		}
	}

	ctx.set_reg ( X86_REG_RSI, rsi + count * step, 8, eff );
	ctx.set_reg ( X86_REG_RDI, rdi + count * step, 8, eff );
	if ( rep ) ctx.set_reg ( X86_REG_RCX, 0, 8, eff );

	if ( ctx.options.enable_logging ) {
		eff.push_to_changes ( ctx,
				std::format ( "MOVS{}  copied {} bytes  DF={}",
													elemSize == 1 ? 'B' :
													elemSize == 2 ? 'W' :
													elemSize == 4 ? 'D' : 'Q',
													elemSize * ( rep ? count : 1 ),
													df ) );
	}
}



void movsw ( capstone::Instruction& instr, EmulationContext& ctx, InstructionEffect& eff ) {
	movs_rep ( instr, ctx, eff, 2 );
}

void movsb ( capstone::Instruction& instr,
					 EmulationContext& ctx,
					 InstructionEffect& eff ) {
	movs_rep ( instr, ctx, eff, 1 );
}

void movsd ( capstone::Instruction& instr, EmulationContext& ctx, InstructionEffect& eff ) {
	movs_rep ( instr, ctx, eff, 4 );
}

void movsq ( capstone::Instruction& instr, EmulationContext& ctx, InstructionEffect& eff ) {
	movs_rep ( instr, ctx, eff, 8 );
}

void punpcklqdq ( capstone::Instruction& instr,
																EmulationContext& state,
																InstructionEffect& effect ) {



	const auto& ops = instr.operands ( );
	x86_reg dst = static_cast< x86_reg >( ops [ 0 ].reg );
	x86_reg src = static_cast< x86_reg >( ops [ 1 ].reg );

	uint128_t v1 = state.get_xmm_raw ( dst );
	uint128_t v2 = state.get_xmm_raw ( src );

	uint64_t lo1 = static_cast< uint64_t >( v1 );
	uint64_t lo2 = static_cast< uint64_t >( v2 );

	uint128_t result = ( uint128_t ( lo2 ) << 64 ) | lo1;

	state.set_xmm_raw ( dst, result, effect );

	effect.push_to_changes ( state,
			std::format ( "PUNPCKLQDQ: {} = [{:016x}, {:016x}]",
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), dst ),
													 lo1, lo2 ) );

}

void movlhps ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	if ( ops [ 0 ].type != X86_OP_REG || ops [ 1 ].type != X86_OP_REG ) {
		effect.push_to_changes ( state, "MOVLHPS: Operands must be registers" );
		return;
	}

	x86_reg dst = ops [ 0 ].reg;
	x86_reg src = ops [ 1 ].reg;

	if ( dst < X86_REG_XMM0 || dst > X86_REG_XMM15 ||
			src < X86_REG_XMM0 || src > X86_REG_XMM15 ) {
		effect.push_to_changes ( state, "MOVLHPS: Operands must be XMM registers" );
		return;
	}



	uint128_t dst_val = state.get_xmm_raw ( dst );
	uint128_t src_val = state.get_xmm_raw ( src );

	uint64_t dst_low = static_cast< uint64_t >( dst_val );
	uint64_t src_low = static_cast< uint64_t >( src_val );

	uint128_t new_dst = ( uint128_t ( src_low ) << 64 ) | dst_low;

	state.set_xmm_raw ( dst, new_dst, effect );

	csh handle = state.decoder.back ( )->get_handle ( );
	effect.push_to_changes ( state,
			std::format ( "MOVLHPS: {} high = {} low",
													 cs_reg_name ( handle, dst ),
													 cs_reg_name ( handle, src ) ) );
}

//could just like, not.
void prefetchw ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	if ( ops [ 0 ].type != X86_OP_MEM ) {
		effect.push_to_changes ( state, "PREFETCHW: Operand must be a memory address" );
		return;
	}

	uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );

	effect.push_to_changes ( state, std::format ( "PREFETCHW: Prefetch hint for write at [0x{:016x}]", addr ) );

}

void psrldq ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	if ( ops [ 0 ].type != X86_OP_REG || ops [ 1 ].type != X86_OP_IMM ) {
		effect.push_to_changes ( state, "PSRLDQ: Invalid operand types" );
		state.exit_due_to_critical_error = true;
		return;
	}

	x86_reg dst_reg = ops [ 0 ].reg;
	if ( dst_reg < X86_REG_XMM0 || dst_reg > X86_REG_XMM15 ) {
		effect.push_to_changes ( state, "PSRLDQ: Destination must be an XMM register" );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint8_t shift_amount = static_cast< uint8_t >( ops [ 1 ].imm );

	uint128_t val = state.get_xmm_raw ( dst_reg );

	if ( shift_amount > 15 ) {
		val = 0;
	}
	else {
		val = val >> ( shift_amount * 8 );
	}

	state.set_xmm_raw ( dst_reg, val, effect );

	csh handle = state.decoder.back ( )->get_handle ( );
	effect.push_to_changes ( state, std::format ( "PSRLDQ: {} >> {} bytes", cs_reg_name ( handle, dst_reg ), shift_amount ) );
}

void helpers::bind_data ( ) {
	BIND ( mov );
	BIND ( movsw );
	BIND ( movsd );
	BIND ( movsq );
	BIND ( movabs );
	BIND ( movsb );
	BIND ( movaps );
	BIND ( movups );
	BIND ( movzx );
	BIND ( push );
	BIND ( pop );
	BIND ( lea );
	BIND ( movsx );
	BIND ( sahf );
	BIND ( lahf );
	BIND ( movsxd );
	BIND ( xchg );
	BIND ( pushfq );
	BIND ( popfq );
	BIND ( movq );
	BIND ( cmpxchg );
	BIND ( cmpxchg16b );
	BIND ( stos );
	BIND ( punpcklqdq );
	BIND ( movlhps );
	BIND ( prefetchw );
	BIND ( psrldq );
}
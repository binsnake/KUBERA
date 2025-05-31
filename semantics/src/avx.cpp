#include "pch.hpp"
#include <cmath>
#include <cfenv>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/math/special_functions/modf.hpp>

void vpxor ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint8_t op_size_bytes = ops [ 0 ].size; // Size of the destination register in bytes (16 for XMM, 32 for YMM, 64 for ZMM)

	// Get src1 value (always a register for 3-operand form)
	uint512_t src1_val_full;
	switch ( op_size_bytes ) {
		case 16: // XMM
			src1_val_full = state.get_xmm_raw ( ops [ 1 ].reg );
			break;
		case 32: // YMM
			src1_val_full = state.get_ymm_raw ( ops [ 1 ].reg );
			break;
		case 64: // ZMM (AVX-512)
			src1_val_full = state.get_zmm_raw ( ops [ 1 ].reg );
			break;
		default:
			effect.push_to_changes ( state, std::format ( "VPXOR: Unsupported operand size {} bytes for src1.", op_size_bytes ) );
			state.exit_due_to_critical_error = true;
			return;
	}

	// Get src2 value (register or memory)
	uint512_t src2_val_full;
	if ( ops [ 2 ].type == X86_OP_REG ) {
		switch ( op_size_bytes ) {
			case 16:
				src2_val_full = state.get_xmm_raw ( ops [ 2 ].reg );
				break;
			case 32:
				src2_val_full = state.get_ymm_raw ( ops [ 2 ].reg );
				break;
			case 64:
				src2_val_full = state.get_zmm_raw ( ops [ 2 ].reg );
				break;
			default:
				effect.push_to_changes ( state, std::format ( "VPXOR: Unsupported operand size {} bytes for src2 register.", op_size_bytes ) );
				state.exit_due_to_critical_error = true; return;
		}
	}
	else if ( ops [ 2 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 2 ], instr, state );
		if ( state.exit_due_to_critical_error ) return;

		switch ( op_size_bytes ) {
			case 16: // XMM - 128 bit
				src2_val_full = state.get_memory_128 ( addr );
				break;
			case 32:
			{
				src2_val_full = state.get_memory_256 ( addr );
			}
			break;
			case 64:
			{
				src2_val_full = state.get_memory_512 ( addr );
			}
			break;
			default:
				effect.push_to_changes ( state, std::format ( "VPXOR: Unsupported operand size {} bytes for src2 memory.", op_size_bytes ) );
				state.exit_due_to_critical_error = true; return;
		}
	}
	else {
		effect.push_to_changes ( state, "VPXOR: Invalid type for src2 operand." );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint512_t result_full = src1_val_full ^ src2_val_full;

	// Store the result based on destination register size
	if ( op_size_bytes == 16 ) state.set_xmm_raw ( dst_reg, result_full.convert_to<uint128_t> ( ), effect );
	else if ( op_size_bytes == 32 ) state.set_ymm_raw ( dst_reg, result_full.convert_to<uint256_t> ( ), effect );
	else if ( op_size_bytes == 64 ) state.set_zmm_raw ( dst_reg, result_full, effect );
	// No else needed due to prior checks

	effect.push_to_changes ( state, std::format ( "vpxor {}, {}, {}", cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 0 ].reg ), cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 1 ].reg ), ops [ 2 ].type == X86_OP_REG ? cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 2 ].reg ) : "[mem]" ) );
	effect.modified_regs.insert ( dst_reg );
}

void vpcmpeqw ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint8_t op_size_bytes = ops [ 0 ].size; // 16 for XMM, 32 for YMM, 64 for ZMM
	int num_elements = op_size_bytes / sizeof ( uint16_t ); // Number of 16-bit words

	uint512_t src1_full, src2_full, result_full = 0;

	// Get src1
	if ( ops [ 1 ].type == X86_OP_REG ) {
		if ( op_size_bytes == 16 ) src1_full = state.get_xmm_raw ( ops [ 1 ].reg );
		else if ( op_size_bytes == 32 ) src1_full = state.get_ymm_raw ( ops [ 1 ].reg );
		else if ( op_size_bytes == 64 ) src1_full = state.get_zmm_raw ( ops [ 1 ].reg );
	}

	// Get src2
	if ( ops [ 2 ].type == X86_OP_REG ) {
		if ( op_size_bytes == 16 ) src2_full = state.get_xmm_raw ( ops [ 2 ].reg );
		else if ( op_size_bytes == 32 ) src2_full = state.get_ymm_raw ( ops [ 2 ].reg );
		else if ( op_size_bytes == 64 ) src2_full = state.get_zmm_raw ( ops [ 2 ].reg );
	}
	else if ( ops [ 2 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 2 ], instr, state );
		if ( state.exit_due_to_critical_error ) return;
		if ( op_size_bytes == 16 ) src2_full = state.get_memory_128 ( addr );
		else if ( op_size_bytes == 32 ) src2_full = state.get_memory_256 ( addr );
		else if ( op_size_bytes == 64 ) src2_full = state.get_memory_512 ( addr );
	}

	// Perform element-wise comparison
	for ( int i = 0; i < num_elements; ++i ) {
		uint16_t element1 = static_cast< uint16_t > ( ( src1_full >> ( i * 16 ) ) & 0xFFFF );
		uint16_t element2 = static_cast< uint16_t > ( ( src2_full >> ( i * 16 ) ) & 0xFFFF );

		if ( element1 == element2 ) {
			result_full |= ( uint512_t ( 0xFFFF ) << ( i * 16 ) ); // Set all bits to 1 for this element
		}
		// Else, bits for this element remain 0
	}

	// Store the result
	if ( op_size_bytes == 16 ) state.set_xmm_raw ( dst_reg, result_full.convert_to<uint128_t> ( ), effect );
	else if ( op_size_bytes == 32 ) state.set_ymm_raw ( dst_reg, result_full.convert_to<uint256_t> ( ), effect );
	else if ( op_size_bytes == 64 ) state.set_zmm_raw ( dst_reg, result_full, effect );

	effect.push_to_changes ( state, std::format ( "vpcmpeqw {}, {}, {}",
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 0 ].reg ),
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 1 ].reg ),
													 ops [ 2 ].type == X86_OP_REG ? cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 2 ].reg ) : "[mem]"
	) );
	effect.modified_regs.insert ( dst_reg );
}

void vpmovmskb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_gpr_reg = ops [ 0 ].reg;
	uint8_t dst_gpr_size = ops [ 0 ].size; // Should be 4 or 8 for the GPR
	x86_reg src_vec_reg = ops [ 1 ].reg;
	uint8_t src_vec_size_bytes = ops [ 1 ].size; // 16 for XMM, 32 for YMM, 64 for ZMM
	int num_bytes_in_vector = src_vec_size_bytes;

	uint512_t src_vec_full;
	if ( src_vec_size_bytes == 16 ) src_vec_full = state.get_xmm_raw ( src_vec_reg );
	else if ( src_vec_size_bytes == 32 ) src_vec_full = state.get_ymm_raw ( src_vec_reg );
	else src_vec_full = state.get_zmm_raw ( src_vec_reg );

	uint64_t result_mask = 0;
	for ( int i = 0; i < num_bytes_in_vector; ++i ) {
		uint8_t byte_val = static_cast< uint8_t > ( ( src_vec_full >> ( i * 8 ) ) & 0xFF );
		if ( ( byte_val >> 7 ) & 1 ) { // Check MSB of the byte
			result_mask |= ( 1ULL << i );
		}
	}

	state.set_reg ( dst_gpr_reg, result_mask, dst_gpr_size, effect );

	effect.push_to_changes ( state, std::format ( "vpmovmskb {}, {}",
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), dst_gpr_reg ),
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), src_vec_reg )
	) );
	// effect.modified_regs is handled by set_reg
}

void vzeroupper ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	for ( int i = 0; i < 16; ++i ) {
		x86_reg ymm_reg = static_cast< x86_reg > ( X86_REG_YMM0 + i );
		uint256_t current_ymm_val = state.get_ymm_raw ( ymm_reg );
		uint128_t lower_128_bits = current_ymm_val.convert_to<uint128_t> ( );
		state.set_ymm_raw ( ymm_reg, lower_128_bits, effect );
	}

	effect.push_to_changes ( state, "upper ymm zeroed" );
}

void vinsertf128 ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg ymm_dest_reg = ops [ 0 ].reg;
	x86_reg ymm_src1_reg = ops [ 1 ].reg;

	uint128_t xmm_src2_val;
	if ( ops [ 2 ].type == X86_OP_REG && ops [ 2 ].reg >= X86_REG_XMM0 && ops [ 2 ].reg <= X86_REG_XMM15 ) {
		xmm_src2_val = state.get_xmm_raw ( ops [ 2 ].reg );
	}
	else if ( ops [ 2 ].type == X86_OP_MEM && ops [ 2 ].size == 16 ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 2 ], instr, state );
		if ( state.exit_due_to_critical_error ) return;
		xmm_src2_val = state.get_memory_128 ( addr );
	}

	uint8_t imm = static_cast< uint8_t >( ops [ 3 ].imm );
	uint256_t ymm_src1_val = state.get_ymm_raw ( ymm_src1_reg );
	uint256_t result_val;

	if ( ( imm & 0x01 ) == 0 ) { // Insert into lower lane
		result_val = ( ymm_src1_val & ( uint256_t ( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ) ) | uint256_t ( xmm_src2_val ) );
	}
	else { // Insert into upper lane
		result_val = ( uint256_t ( xmm_src2_val ) << 128 ) | ( ymm_src1_val & uint256_t ( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ) );
	}

	state.set_ymm_raw ( ymm_dest_reg, result_val, effect );

	effect.push_to_changes ( state, std::format ( "vinsertf128 {}, {}, {}, 0x{:x}",
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), ymm_dest_reg ),
													 cs_reg_name ( state.decoder.back ( )->get_handle ( ), ymm_src1_reg ),
													 ops [ 2 ].type == X86_OP_REG ? cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 2 ].reg ) : "[m128]",
													 imm ) );
}

void vmovups ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	const cs_x86_op& dst_op = ops [ 0 ];
	const cs_x86_op& src_op = ops [ 1 ];
	uint8_t op_size_bytes = dst_op.size;
	if ( dst_op.type == X86_OP_MEM ) {
		op_size_bytes = src_op.size;
	}


	uint512_t val_to_move;

	// Read source
	if ( src_op.type == X86_OP_REG ) {
		if ( op_size_bytes == 16 ) val_to_move = state.get_xmm_raw ( src_op.reg );
		else if ( op_size_bytes == 32 ) val_to_move = state.get_ymm_raw ( src_op.reg );
		else val_to_move = state.get_zmm_raw ( src_op.reg );
	}
	else if ( src_op.type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( src_op, instr, state );
		if ( state.exit_due_to_critical_error ) return;
		if ( op_size_bytes == 16 ) val_to_move = state.get_memory_128 ( addr );
		else if ( op_size_bytes == 32 ) val_to_move = state.get_memory_256 ( addr );
		else val_to_move = state.get_memory_512 ( addr );
	}
	else { state.exit_due_to_critical_error = true; return; }

	// Write destination
	if ( dst_op.type == X86_OP_REG ) {
		if ( op_size_bytes == 16 ) state.set_xmm_raw ( dst_op.reg, val_to_move.convert_to<uint128_t> ( ), effect );
		else if ( op_size_bytes == 32 ) state.set_ymm_raw ( dst_op.reg, val_to_move.convert_to<uint256_t> ( ), effect );
		else state.set_zmm_raw ( dst_op.reg, val_to_move, effect );
	}
	else if ( dst_op.type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( dst_op, instr, state );
		if ( state.exit_due_to_critical_error ) return;
		if ( op_size_bytes == 16 ) state.set_memory_128 ( addr, val_to_move.convert_to<uint128_t> ( ), effect );
		else if ( op_size_bytes == 32 ) state.set_memory_256 ( addr, val_to_move.convert_to<uint256_t> ( ), effect );
		else state.set_memory_512 ( addr, val_to_move, effect );
	}
	else { state.exit_due_to_critical_error = true; return; }

	effect.push_to_changes ( state, std::format ( "vmovups {}, {}",
													 dst_op.type == X86_OP_REG ? cs_reg_name ( state.decoder.back ( )->get_handle ( ), dst_op.reg ) : "[mem]",
													 src_op.type == X86_OP_REG ? cs_reg_name ( state.decoder.back ( )->get_handle ( ), src_op.reg ) : "[mem]"
	) );
}

void vmovaps(capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect) {
    const cs_x86_op* ops = instr.operands();
    const cs_x86_op& dst_op = ops[0];
    const cs_x86_op& src_op = ops[1];
    uint8_t op_size_bytes = dst_op.size; 
    if (dst_op.type == X86_OP_MEM) {
        op_size_bytes = src_op.size;
    }
    uint8_t alignment_requirement = op_size_bytes;

    uint512_t val_to_move;

    // Read source
    if (src_op.type == X86_OP_REG) {
        if (op_size_bytes == 16) val_to_move = state.get_xmm_raw(src_op.reg);
        else if (op_size_bytes == 32) val_to_move = state.get_ymm_raw(src_op.reg);
        else val_to_move = state.get_zmm_raw(src_op.reg);
    } else if (src_op.type == X86_OP_MEM) {
        uint64_t addr = helpers::calculate_mem_addr(src_op, instr, state);
        if (state.exit_due_to_critical_error) return;
        if ((addr % alignment_requirement) != 0) {
            GuestExceptionInfo ex;
            ex.set_exception(EXCEPTION_ACCESS_VIOLATION, instr.ip(), addr); // General Protection Fault for misaligned access
            effect.push_to_changes(state, std::format("VMOVAPS: Misaligned memory access at 0x{:x} for source (required {} byte alignment).", addr, alignment_requirement));
            throw ex;
        }
        if (op_size_bytes == 16) val_to_move = state.get_memory_128(addr);
        else if (op_size_bytes == 32) val_to_move = state.get_memory_256(addr);
        else val_to_move = state.get_memory_512(addr);
    }

    // Write destination
    if (dst_op.type == X86_OP_REG) {
        if (op_size_bytes == 16) state.set_xmm_raw(dst_op.reg, val_to_move.convert_to<uint128_t>(), effect);
        else if (op_size_bytes == 32) state.set_ymm_raw(dst_op.reg, val_to_move.convert_to<uint256_t>(), effect);
        else state.set_zmm_raw(dst_op.reg, val_to_move, effect);
    } else if (dst_op.type == X86_OP_MEM) {
        uint64_t addr = helpers::calculate_mem_addr(dst_op, instr, state);
        if (state.exit_due_to_critical_error) return;
        if ((addr % alignment_requirement) != 0) {
            GuestExceptionInfo ex;
            ex.set_exception(EXCEPTION_ACCESS_VIOLATION, instr.ip(), addr); // General Protection Fault
            effect.push_to_changes(state, std::format("VMOVAPS: Misaligned memory access at 0x{:x} for destination (required {} byte alignment).", addr, alignment_requirement));
            throw ex;
        }
        if (op_size_bytes == 16) state.set_memory_128(addr, val_to_move.convert_to<uint128_t>(), effect);
        else if (op_size_bytes == 32) state.set_memory_256(addr, val_to_move.convert_to<uint256_t>(), effect);
        else state.set_memory_512(addr, val_to_move, effect);
    }

    effect.push_to_changes(state, std::format("vmovaps {}, {}",
        dst_op.type == X86_OP_REG ? cs_reg_name(state.decoder.back()->get_handle(), dst_op.reg) : "[mem]",
        src_op.type == X86_OP_REG ? cs_reg_name(state.decoder.back()->get_handle(), src_op.reg) : "[mem]"
    ));
}


void helpers::bind_avx ( ) {
	BIND ( vpxor );
	BIND ( vpcmpeqw );
	BIND ( vpmovmskb );
	BIND ( vzeroupper );
	BIND ( vinsertf128 );
	BIND ( vmovups );
	BIND ( vmovaps );
	BIND2 ( vmovdqu, vmovups );
	BIND2 ( movdqu, vmovups );
}
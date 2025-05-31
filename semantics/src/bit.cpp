#include "pch.hpp"

void bzhi ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;
	x86_reg dst = ops [ 0 ].reg;
	const auto src = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	const auto index_reg_val = helpers::get_src<uint64_t> ( &instr, 2, state, op_size );

	GET_OPERAND_MASK ( operand_mask, op_size );
	uint64_t src_val = src & operand_mask;
	uint64_t index_val = index_reg_val;

	uint8_t index_pos = index_val & 0xFF;
	uint8_t size_in_bits = op_size * 8;

	uint64_t res = 0;
	uint64_t temp_mask = 0;

	// Calculate the mask ((1 << index_pos) - 1) carefully
	if ( index_pos == 0 ) {
		temp_mask = 0; // Mask is zero if index is 0
	}
	else if ( index_pos >= size_in_bits ) {
		// If index >= size, mask includes all bits of the operand
		temp_mask = operand_mask;
	}
	else {
		// Calculate 1 << index_pos safely (won't overflow uint64_t)
		temp_mask = ( 1ULL << index_pos ) - 1;
	}

	// Apply the mask: DEST = SRC & temp_mask
	res = src_val & temp_mask;

	// Store the result (already masked to operand size)
	state.set_reg ( dst, res, op_size, effect );

	// --- Correct Flag Updates ---
	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_ZF = state.cpu->cpu_flags.flags.ZF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;
	uint64_t old_SF = state.cpu->cpu_flags.flags.SF;
	uint64_t old_AF = state.cpu->cpu_flags.flags.AF;
	uint64_t old_PF = state.cpu->cpu_flags.flags.PF;

	// CF is set if the index value (bits 7:0) >= operand size in bits
	state.cpu->cpu_flags.flags.CF = ( index_pos >= size_in_bits );
	// ZF is set if the result is zero
	state.cpu->cpu_flags.flags.ZF = ( res == 0 );
	// OF, SF, AF, PF are cleared
	state.cpu->cpu_flags.flags.OF = 0;
	state.cpu->cpu_flags.flags.SF = 0;
	state.cpu->cpu_flags.flags.AF = 0;
	state.cpu->cpu_flags.flags.PF = 0;

	// Log flag changes if any occurred
	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_ZF != state.cpu->cpu_flags.flags.ZF ) state.log_flag_change ( effect, "ZF", old_ZF, state.cpu->cpu_flags.flags.ZF );
	// Only log cleared flags if they were previously non-zeo
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
	if ( old_SF != state.cpu->cpu_flags.flags.SF ) state.log_flag_change ( effect, "SF", old_SF, state.cpu->cpu_flags.flags.SF );
	if ( old_AF != state.cpu->cpu_flags.flags.AF ) state.log_flag_change ( effect, "AF", old_AF, state.cpu->cpu_flags.flags.AF );
	if ( old_PF != state.cpu->cpu_flags.flags.PF ) state.log_flag_change ( effect, "PF", old_PF, state.cpu->cpu_flags.flags.PF );
}

void andn ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	x86_reg dst = ops [ 0 ].reg;
	const auto src1 = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	const auto src2 = helpers::get_src<uint64_t> ( &instr, 2, state, op_size );
	const auto res = ~src1 & src2;
	state.set_reg ( dst, res, op_size, effect );
	state.update_flags_and ( ~src1, src2, op_size, effect );
}

void bextr ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;

	x86_reg dst = ops [ 0 ].reg;
	auto src = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	auto control = helpers::get_src<uint64_t> ( &instr, 2, state, op_size );

	uint64_t operand_mask = ( op_size == 8 ) ? 0xFFFFFFFFFFFFFFFFULL : ( 1ULL << ( op_size * 8 ) ) - 1;
	uint64_t src_val = src & operand_mask;
	uint64_t control_val = control;

	uint8_t start = control_val & 0xFF;
	uint8_t len = ( control_val >> 8 ) & 0xFF;
	uint64_t res = 0;

	if ( len == 0 ) {
		res = 0;
	}
	else {
		uint64_t result_mask = 0;
		int bits_in_operand = op_size * 8;
		if ( len >= bits_in_operand ) {
			result_mask = operand_mask;
		}
		else {
			result_mask = ( 1ULL << len ) - 1;
		}
		if ( start < bits_in_operand ) {
			res = ( src_val >> start ) & result_mask;
		}
		else {
			res = 0;
		}
	}

	state.set_reg ( dst, res, op_size, effect );

	uint64_t old_ZF = state.cpu->cpu_flags.flags.ZF;
	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;
	uint64_t old_SF = state.cpu->cpu_flags.flags.SF;
	uint64_t old_AF = state.cpu->cpu_flags.flags.AF;
	uint64_t old_PF = state.cpu->cpu_flags.flags.PF;

	state.cpu->cpu_flags.flags.ZF = ( res == 0 );
	state.cpu->cpu_flags.flags.CF = 0;
	state.cpu->cpu_flags.flags.OF = 0;

	if ( old_ZF != state.cpu->cpu_flags.flags.ZF ) state.log_flag_change ( effect, "ZF", old_ZF, state.cpu->cpu_flags.flags.ZF );
	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
	if ( old_SF != state.cpu->cpu_flags.flags.SF ) state.log_flag_change ( effect, "SF", old_SF, state.cpu->cpu_flags.flags.SF );
	if ( old_AF != state.cpu->cpu_flags.flags.AF ) state.log_flag_change ( effect, "AF", old_AF, state.cpu->cpu_flags.flags.AF );
	if ( old_PF != state.cpu->cpu_flags.flags.PF ) state.log_flag_change ( effect, "PF", old_PF, state.cpu->cpu_flags.flags.PF );
}

void popcnt ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	x86_reg dst = ops [ 0 ].reg;
	auto src = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	uint64_t val = static_cast< uint64_t >( src );
	uint64_t result = __popcnt64 ( val );
	state.set_reg ( dst, result, op_size, effect );
	state.cpu->cpu_flags.flags.ZF = result == 0;
	state.cpu->cpu_flags.flags.CF = 0;
	state.cpu->cpu_flags.flags.OF = 0;
	state.cpu->cpu_flags.flags.SF = 0;
	state.cpu->cpu_flags.flags.PF = 0;
	state.cpu->cpu_flags.flags.AF = 0;
}

void bswap ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	x86_reg dst = ops [ 0 ].reg;
	auto cur = state.get_reg ( dst, op_size );
	uint64_t val = static_cast< uint64_t >( cur );
	if ( op_size == 4 ) val = _byteswap_ulong ( static_cast< uint32_t >( val ) );
	else if ( op_size == 8 ) val = _byteswap_uint64 ( val );
	state.set_reg ( dst, val, op_size, effect );
}

void setb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.CF; } );
}

void setnp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return ~state.cpu->cpu_flags.flags.PF; } );
}

void sets ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF; } );
}

void setnl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF; } );
}

void seto ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.OF; } );
}

void setbe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.CF | state.cpu->cpu_flags.flags.ZF; } );
}

void setz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.ZF; } );
}

void setnb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return ~state.cpu->cpu_flags.flags.CF; } );
}

void setno ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return ~state.cpu->cpu_flags.flags.OF; } );
}


void setp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.PF; } );
}

void setle ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.ZF | ( state.cpu->cpu_flags.flags.SF ^ state.cpu->cpu_flags.flags.OF ); } );
}

void setnle ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.ZF && ( state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF ); } );
}

void setns ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return ~state.cpu->cpu_flags.flags.SF; } );
}

void setl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF != state.cpu->cpu_flags.flags.OF; } );
}

void setnbe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return ~state.cpu->cpu_flags.flags.CF & ~state.cpu->cpu_flags.flags.ZF; } );
}

void setnz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_setcc ( instr, state, effect, [ ] ( const auto& state ) { return ~state.cpu->cpu_flags.flags.ZF; } );
}

void rol ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;
	x86_reg dst = ops [ 0 ].reg;
	auto src_count = helpers::get_src<uint64_t> ( &instr, 1, state, 1 );
	auto cur = state.get_reg ( dst, op_size );

	uint64_t val = cur;
	uint64_t count_val = src_count;
	uint8_t size_in_bits = op_size * 8;
	uint64_t mask = ( op_size == 8 ) ? 0xFFFFFFFFFFFFFFFFULL : ( 1ULL << size_in_bits ) - 1;
	uint64_t current_val = val & mask;

	uint8_t count_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t rot = count_val & count_mask;

	uint64_t final_result = current_val;
	uint64_t final_cf = state.cpu->cpu_flags.flags.CF;

	if ( rot > 0 ) {
		uint64_t temp_val = current_val;
		uint64_t temp_cf = 0;

		for ( uint8_t i = 0; i < rot; ++i ) {
			uint64_t msb = ( temp_val >> ( size_in_bits - 1 ) ) & 1;
			temp_cf = msb;
			temp_val = ( ( temp_val << 1 ) | msb ) & mask;
		}
		final_result = temp_val;
		final_cf = temp_cf;
	}

	state.set_reg ( dst, final_result, op_size, effect );

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;

	uint8_t count_raw = count_val & 0xFF;
	if ( count_raw != 0 ) {
		state.cpu->cpu_flags.flags.CF = final_cf;

		if ( count_raw == 1 ) {
			uint64_t result_msb = ( final_result >> ( size_in_bits - 1 ) ) & 1;
			state.cpu->cpu_flags.flags.OF = result_msb ^ final_cf;
		}

		if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
	}
}

void ror ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;

	x86_reg dst = ops [ 0 ].reg;
	auto src_count = helpers::get_src<uint64_t> ( &instr, 1, state, 1 );
	auto cur = state.get_reg ( dst, op_size );

	uint64_t val = cur;
	uint64_t count_val = src_count;
	uint8_t size_in_bits = op_size * 8;
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t current_val = val & mask;
	uint8_t count_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t rot = count_val & count_mask;

	uint64_t final_result = current_val;
	uint64_t final_cf = state.cpu->cpu_flags.flags.CF;

	if ( rot > 0 ) {
		uint64_t temp_val = current_val;
		uint64_t temp_cf = 0;

		for ( uint8_t i = 0; i < rot; ++i ) {
			uint64_t lsb = temp_val & 1;
			temp_cf = lsb;
			temp_val = ( temp_val >> 1 ) | ( lsb << ( size_in_bits - 1 ) );
		}
		final_result = temp_val;
		final_cf = temp_cf;
	}

	state.set_reg ( dst, final_result, op_size, effect );

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;

	uint8_t count_raw = count_val & 0xFF;
	if ( count_raw != 0 ) {
		state.cpu->cpu_flags.flags.CF = final_cf;
		if ( count_raw == 1 ) {
			uint64_t result_msb = ( final_result >> ( size_in_bits - 1 ) ) & 1;
			uint64_t result_msb_minus_1 = 0;
			if ( size_in_bits > 1 ) {
				result_msb_minus_1 = ( final_result >> ( size_in_bits - 2 ) ) & 1;
			}
			state.cpu->cpu_flags.flags.OF = result_msb ^ result_msb_minus_1;
		}

		if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
	}
}

void rcl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;
	x86_reg dst = ops [ 0 ].reg;
	auto src_count = helpers::get_src<uint64_t> ( &instr, 1, state, 1 );
	auto cur = state.get_reg ( dst, op_size );

	uint64_t val = cur;
	uint64_t count_val = src_count;
	uint8_t size_in_bits = op_size * 8;
	uint64_t mask = ( op_size == 8 ) ? 0xFFFFFFFFFFFFFFFFULL : ( 1ULL << size_in_bits ) - 1;

	// --- Count masking like Rust version (MOD size_in_bits) ---
	uint8_t count_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t rot = count_val & count_mask;
	// ---

	// Promote to 128 bits conceptually (only lower 64 + carry needed)
	uint64_t current_val = val & mask;
	uint64_t current_cf = state.cpu->cpu_flags.flags.CF; // Use boolean/int directly

	// Iterative loop based on Rust logic
	for ( uint8_t i = 0; i < rot; ++i ) {
		uint64_t msb = ( current_val >> ( size_in_bits - 1 ) ) & 1; // Bit rotating out
		// Perform the shift and bring in carry
		current_val = ( ( current_val << 1 ) | current_cf ) & mask;
		// Update carry for next step
		current_cf = msb;
	}

	uint64_t final_result = current_val;
	uint64_t final_cf = current_cf; // CF after last iteration

	// --- Update State ---
	state.set_reg ( dst, final_result, op_size, effect );

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;

	state.cpu->cpu_flags.flags.CF = final_cf; // Set CF based on loop result

	// OF logic from previous C++ version (only count_raw=1 matters)
	uint8_t count_raw = count_val & 0xFF; // Get original raw count for OF check
	if ( count_raw == 1 ) {
		uint64_t result_msb = ( final_result >> ( size_in_bits - 1 ) ) & 1;
		state.cpu->cpu_flags.flags.OF = result_msb ^ final_cf;
	}
	else {
		state.cpu->cpu_flags.flags.OF = 0; // Undefined for count > 1
	}

	// Log changes
	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
}
void rcr ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;

	x86_reg dst = ops [ 0 ].reg;
	auto src_count = helpers::get_src<uint64_t> ( &instr, 1, state, 1 );
	auto cur = state.get_reg ( dst, op_size );

	uint64_t val = cur;
	uint64_t count_val = src_count;
	uint8_t size_in_bits = op_size * 8;
	uint64_t mask = ( op_size == 8 ) ? 0xFFFFFFFFFFFFFFFFULL : ( 1ULL << size_in_bits ) - 1;
	uint64_t original_val = val & mask; 
	uint8_t count_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t rot = count_val & count_mask;

	uint64_t current_val = original_val;
	uint64_t current_cf = state.cpu->cpu_flags.flags.CF;

	for ( uint8_t i = 0; i < rot; ++i ) {
		uint64_t lsb = current_val & 1;
		current_val = ( current_val >> 1 ) | ( current_cf << ( size_in_bits - 1 ) );
		current_cf = lsb;
	}

	uint64_t final_result = current_val & mask;
	state.set_reg ( dst, final_result, op_size, effect );

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;

	uint8_t cnt_mod_size_plus_1 = count_val % ( size_in_bits + 1 );
	uint64_t final_cf;
	if ( cnt_mod_size_plus_1 == 0 ) {
		final_cf = ( original_val >> ( size_in_bits - 1 ) ) & 1;
		final_cf = ( original_val >> ( cnt_mod_size_plus_1 - 1 ) ) & 1;
	}
	else if ( cnt_mod_size_plus_1 == 1 ) {
		final_cf = original_val & 1;
	}
	else {
		final_cf = ( original_val >> ( cnt_mod_size_plus_1 - 1 ) ) & 1;
	}
	state.cpu->cpu_flags.flags.CF = final_cf;

	uint8_t count_raw = count_val & 0xFF;
	if ( count_raw == 1 ) {
		uint64_t result_msb = ( final_result >> ( size_in_bits - 1 ) ) & 1;
		uint64_t result_msb_minus_1 = 0;
		if ( size_in_bits > 1 ) {
			result_msb_minus_1 = ( final_result >> ( size_in_bits - 2 ) ) & 1;
			state.cpu->cpu_flags.flags.OF = result_msb ^ result_msb_minus_1;
		}
		else {
			state.cpu->cpu_flags.flags.OF = result_msb ^ final_cf;
		}
	}
	else {
		state.cpu->cpu_flags.flags.OF = 0;
	}

	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
}

void bt ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	auto src1 = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	auto src2 = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	uint64_t val = static_cast< uint64_t >( src1 );
	uint64_t bit_idx = src2 & ( ( op_size * 8 ) - 1 );
	state.cpu->cpu_flags.flags.CF = ( val >> bit_idx ) & 1;
	effect.push_to_changes ( state,std::format ( "Bit {} of {:#x} tested, CF={}", bit_idx, src1, ( char ) state.cpu->cpu_flags.flags.CF ) );
}

void bts ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	auto src1 = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	auto src2 = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		uint64_t value = static_cast< uint64_t >( src1 );
		uint64_t bit_idx = src2 & ( op_size * 8 - 1 );
		uint64_t original_bit = ( value >> bit_idx ) & 1;
		uint64_t result = value | ( 1ULL << bit_idx );

		uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
		state.cpu->cpu_flags.flags.CF = original_bit;

		state.set_reg ( dst, result, op_size, effect );

		if ( old_CF != state.cpu->cpu_flags.flags.CF ) {
			state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		}

		effect.push_to_changes ( state,std::format ( "BTS: Bit {} set in {:#x}, CF={}", bit_idx, src1, original_bit ) );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		int64_t addr = 0;
		if ( ops [ 0 ].mem.base == X86_REG_RSP ) {
			addr = state.cpu->rsp_offset;
		}
		else if ( ops [ 0 ].mem.base != X86_REG_INVALID ) {
			addr = state.get_reg ( ops [ 0 ].mem.base );
		}
		if ( ops [ 0 ].mem.index != X86_REG_INVALID ) {
			addr += state.get_reg ( ops [ 0 ].mem.index ) * ops [ 0 ].mem.scale;
		}
		addr += ops [ 0 ].mem.disp;

		uint64_t value = static_cast< uint64_t >( src1 );
		uint64_t bit_idx = src2 & ( op_size * 8 - 1 );
		uint64_t original_bit = ( value >> bit_idx ) & 1;
		uint64_t result = value | ( 1ULL << bit_idx );

		uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
		state.cpu->cpu_flags.flags.CF = original_bit;

		state.set_memory ( addr, result, 8, effect );
		effect.modified_mem.insert ( addr );

		if ( old_CF != state.cpu->cpu_flags.flags.CF ) {
			state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		}

		effect.push_to_changes ( state,std::format ( "[{:016x}h] = {:x}h (bit {} set, CF={})", addr, result, bit_idx, original_bit ) );
	}
}

void cli ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	effect.push_to_changes ( state,"Interrupt Flag cleared (IF=0)" );
}

void btr ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;
	const auto src = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	const auto bit_idx = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );

	uint64_t value = src;
	int64_t index = bit_idx & ( op_size * 8 - 1 );
	uint64_t mask = 1ULL << index;

	uint64_t old_cf = state.cpu->cpu_flags.flags.CF;
	state.cpu->cpu_flags.flags.CF = ( value & mask ) != 0;
	if ( old_cf != state.cpu->cpu_flags.flags.CF ) {
		state.log_flag_change ( effect, "CF", old_cf, state.cpu->cpu_flags.flags.CF );
	}

	uint64_t new_value = value & ~mask;

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, new_value, op_size, effect );
		effect.modified_regs.insert ( ops [ 0 ].reg );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		int64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		state.set_memory ( addr, new_value, 8, effect );
		state.log_stack_change ( effect, addr, src, new_value );
		effect.modified_mem.insert ( addr );
	}

	effect.push_to_changes ( state,std::format ( "BTR: bit {} reset, value 0x{:x} -> 0x{:x}, CF={}",
														 index, value, new_value, ( char ) state.cpu->cpu_flags.flags.CF ) );
}

void cwd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto ax = state.get_reg ( X86_REG_AX, 2 );
	int16_t ax_val = static_cast< int16_t >( ax );
	int32_t eax_val = static_cast< int32_t >( ax_val );
	uint16_t dx_val = ( ax_val < 0 ) ? 0xFFFF : 0;
	state.set_reg ( X86_REG_EAX, eax_val, 4, effect );
	state.set_reg ( X86_REG_DX, dx_val, 2, effect );
}

void btc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	auto src = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		auto cur = state.get_reg ( dst, op_size );
		uint64_t val = cur;
		int64_t bit_pos = src % ( op_size * 8 );
		state.cpu->cpu_flags.flags.CF = ( val >> bit_pos ) & 1;
		val ^= ( 1ULL << bit_pos );
		state.set_reg ( dst, val, op_size, effect );
		effect.push_to_changes ( state,std::format ( "CF={}", ( char ) state.cpu->cpu_flags.flags.CF ) );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		int64_t addr = 0;
		if ( ops [ 0 ].mem.base == X86_REG_RSP ) addr = state.cpu->rsp_offset;
		else if ( ops [ 0 ].mem.base != X86_REG_INVALID ) addr = state.get_reg ( ops [ 0 ].mem.base );
		addr += ops [ 0 ].mem.disp;
		auto cur = state.get_memory ( addr, op_size );
		uint64_t val = cur;
		uint64_t bit_pos = src % ( op_size * 8 );
		state.cpu->cpu_flags.flags.CF = ( val >> bit_pos ) & 1;
		val ^= ( 1ULL << bit_pos );
		state.set_memory ( addr, val, 8, effect );
		effect.modified_mem.insert ( addr );
		effect.push_to_changes ( state,std::format ( "[{:016x}h] = {:x}h, CF={}", addr, val, ( char ) state.cpu->cpu_flags.flags.CF ) );
	}
}

void bsr(capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect) {
    const cs_x86_op* ops = instr.operands();
    // BSR dest_reg, src_reg/mem
    // dest_reg must be 16, 32, or 64-bit.
    // src_operand must be the same size as dest_reg.

    x86_reg dst_reg = ops[0].reg;
    uint8_t op_size = ops[0].size; // Should be 2, 4, or 8
    uint64_t src_val = helpers::get_src<uint64_t>(&instr, 1, state, op_size);
    if (state.exit_due_to_critical_error) return;

    // Mask src_val to the operand size, though get_src should ideally handle this.
    GET_OPERAND_MASK(operand_mask, op_size);
    src_val &= operand_mask;

    uint64_t old_zf = state.cpu->cpu_flags.flags.ZF;

    if (src_val == 0) {
        state.cpu->cpu_flags.flags.ZF = 1; // Source is zero, set ZF
        // Destination register is undefined (Intel) / unchanged (AMD).
        // We'll follow the common behavior of leaving it unchanged.
        effect.push_to_changes(state, "BSR: Source is 0, ZF=1, destination unchanged.");
    } else {
        state.cpu->cpu_flags.flags.ZF = 0; // Source is non-zero, clear ZF
        unsigned long index = 0UL;
        // _BitScanReverse for 16/32-bit, _BitScanReverse64 for 64-bit.
        bool found = false;
        if (op_size == 8) found = _BitScanReverse64(&index, src_val);
        else if (op_size == 4) found = _BitScanReverse(&index, static_cast<uint32_t>(src_val));
        else if (op_size == 2) found = _BitScanReverse(&index, static_cast<uint16_t>(src_val));
        // 'found' should always be true here because we checked src_val != 0
        state.set_reg(dst_reg, static_cast<uint64_t>(index), op_size, effect);
    }

    if (old_zf != state.cpu->cpu_flags.flags.ZF) state.log_flag_change(effect, "ZF", old_zf, state.cpu->cpu_flags.flags.ZF);
    // Other flags (CF, OF, SF, AF, PF) are undefined after BSR.
    // For simplicity in emulation, we might choose to leave them, or explicitly clear them.
    // Let's clear them to denote undefined behavior for those not explicitly set.
    uint64_t old_cf = state.cpu->cpu_flags.flags.CF; state.cpu->cpu_flags.flags.CF = 0; if (old_cf != 0) state.log_flag_change(effect, "CF", old_cf, 0);
    uint64_t old_of = state.cpu->cpu_flags.flags.OF; state.cpu->cpu_flags.flags.OF = 0; if (old_of != 0) state.log_flag_change(effect, "OF", old_of, 0);
    uint64_t old_sf = state.cpu->cpu_flags.flags.SF; state.cpu->cpu_flags.flags.SF = 0; if (old_sf != 0) state.log_flag_change(effect, "SF", old_sf, 0);
    uint64_t old_af = state.cpu->cpu_flags.flags.AF; state.cpu->cpu_flags.flags.AF = 0; if (old_af != 0) state.log_flag_change(effect, "AF", old_af, 0);
    uint64_t old_pf = state.cpu->cpu_flags.flags.PF; state.cpu->cpu_flags.flags.PF = 0; if (old_pf != 0) state.log_flag_change(effect, "PF", old_pf, 0);
}

void cbw ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto al = state.get_reg ( X86_REG_AL, 1 );
	int8_t al_val = static_cast< int8_t >( al );
	int16_t ax_val = static_cast< int16_t >( al_val );
	state.set_reg ( X86_REG_AX, ax_val, 2, effect );
}

void cqo ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto rax = state.get_reg ( X86_REG_RAX, 8 );
	uint64_t rax_val = rax;
	uint64_t rdx_val = ( rax_val < 0 ) ? 0xFFFFFFFFFFFFFFFFULL : 0;
	state.set_reg ( X86_REG_RAX, rax_val, 8, effect );
	state.set_reg ( X86_REG_RDX, rdx_val, 8, effect );
}

void cwde ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto ax = state.get_reg ( X86_REG_AX, 2 );
	int16_t ax_val = static_cast< int16_t > ( ax );
	int32_t eax_val = static_cast< int32_t > ( ax_val );
	state.set_reg ( X86_REG_EAX, eax_val, 4, effect );
}

void cld ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.cpu->cpu_flags.flags.DF = 0;
}
void clc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.cpu->cpu_flags.flags.CF = 0;
}

void clui ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.cpu->cpu_flags.flags.IF = 0;
}

void cmc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.cpu->cpu_flags.flags.CF ^= 1;
}

void stc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.cpu->cpu_flags.flags.CF = 1;
}

void tzcnt(capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect) {
    const cs_x86_op* ops = instr.operands();
    // TZCNT dest_reg, src_reg/mem
    // dest_reg must be 16, 32, or 64-bit.
    // src_operand must be the same size as dest_reg.

    x86_reg dst_reg = ops[0].reg;
    uint8_t op_size = ops[0].size; // Should be 2, 4, or 8

    if (op_size != 2 && op_size != 4 && op_size != 8) {
        effect.push_to_changes(state, std::format("TZCNT: Invalid operand size {} for destination register.", op_size));
        state.exit_due_to_critical_error = true;
        return;
    }

    uint64_t src_val = helpers::get_src<uint64_t>(&instr, 1, state, op_size);
    if (state.exit_due_to_critical_error) return;

    GET_OPERAND_MASK(operand_mask, op_size);
    src_val &= operand_mask; // Ensure src_val is masked to operand size

    uint64_t result_count = 0;
    uint8_t size_in_bits = op_size * 8;

    uint64_t old_cf = state.cpu->cpu_flags.flags.CF;
    uint64_t old_zf = state.cpu->cpu_flags.flags.ZF;

    if (src_val == 0) {
        result_count = size_in_bits;
        state.cpu->cpu_flags.flags.CF = 1; // Source is zero, CF = 1
    } else {
        result_count = static_cast<uint64_t>(std::countr_zero(src_val));
        state.cpu->cpu_flags.flags.CF = 0; // Source is non-zero, CF = 0
    }
    state.cpu->cpu_flags.flags.ZF = (result_count == 0); // ZF = 1 if result is 0, else 0

    state.set_reg(dst_reg, result_count, op_size, effect);

    if (old_cf != state.cpu->cpu_flags.flags.CF) state.log_flag_change(effect, "CF", old_cf, state.cpu->cpu_flags.flags.CF);
    if (old_zf != state.cpu->cpu_flags.flags.ZF) state.log_flag_change(effect, "ZF", old_zf, state.cpu->cpu_flags.flags.ZF);

    // OF, SF, AF, PF are undefined (cleared)
    uint64_t old_of = state.cpu->cpu_flags.flags.OF; state.cpu->cpu_flags.flags.OF = 0; if (old_of != 0) state.log_flag_change(effect, "OF", old_of, 0);
    uint64_t old_sf = state.cpu->cpu_flags.flags.SF; state.cpu->cpu_flags.flags.SF = 0; if (old_sf != 0) state.log_flag_change(effect, "SF", old_sf, 0);
    uint64_t old_af = state.cpu->cpu_flags.flags.AF; state.cpu->cpu_flags.flags.AF = 0; if (old_af != 0) state.log_flag_change(effect, "AF", old_af, 0);
    uint64_t old_pf = state.cpu->cpu_flags.flags.PF; state.cpu->cpu_flags.flags.PF = 0; if (old_pf != 0) state.log_flag_change(effect, "PF", old_pf, 0);
}


void bsf ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint8_t op_size = ops [ 0 ].size;

	if ( op_size != 2 && op_size != 4 && op_size != 8 ) {
		effect.push_to_changes ( state, std::format ( "BSF: Invalid operand size {} for destination register.", op_size ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t src_val = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	if ( state.exit_due_to_critical_error ) return;

	uint64_t operand_mask = ( op_size == 8 ) ? UINT64_MAX : ( ( 1ULL << ( op_size * 8 ) ) - 1 );
	src_val &= operand_mask;

	uint64_t old_zf = state.cpu->cpu_flags.flags.ZF;

	if ( src_val == 0 ) {
		state.cpu->cpu_flags.flags.ZF = 1;
		effect.push_to_changes ( state, "BSF: Source is 0, ZF=1, destination unchanged." );
	}
	else {
		unsigned long index = 0;
		uint8_t size_in_bits = op_size * 8;
		while ( index < size_in_bits && ( src_val & ( 1ULL << index ) ) == 0 ) {
			++index;
		}
		state.set_reg ( dst_reg, static_cast< uint64_t > ( index ), op_size, effect );
		state.cpu->cpu_flags.flags.ZF = 0;
	}

	if ( old_zf != state.cpu->cpu_flags.flags.ZF ) {
		state.log_flag_change ( effect, "ZF", old_zf, state.cpu->cpu_flags.flags.ZF );
	}

	uint64_t old_cf = state.cpu->cpu_flags.flags.CF;
	state.cpu->cpu_flags.flags.CF = 0;
	if ( old_cf != 0 ) state.log_flag_change ( effect, "CF", old_cf, 0 );

	uint64_t old_of = state.cpu->cpu_flags.flags.OF;
	state.cpu->cpu_flags.flags.OF = 0;
	if ( old_of != 0 ) state.log_flag_change ( effect, "OF", old_of, 0 );

	uint64_t old_sf = state.cpu->cpu_flags.flags.SF;
	state.cpu->cpu_flags.flags.SF = 0;
	if ( old_sf != 0 ) state.log_flag_change ( effect, "SF", old_sf, 0 );

	uint64_t old_af = state.cpu->cpu_flags.flags.AF;
	state.cpu->cpu_flags.flags.AF = 0;
	if ( old_af != 0 ) state.log_flag_change ( effect, "AF", old_af, 0 );

	uint64_t old_pf = state.cpu->cpu_flags.flags.PF;
	state.cpu->cpu_flags.flags.PF = 0;
	if ( old_pf != 0 ) state.log_flag_change ( effect, "PF", old_pf, 0 );
}

void helpers::bind_bit ( ) {
	BIND ( bzhi );
	BIND ( andn );
	BIND ( bextr );
	BIND ( ror );
	BIND ( popcnt );
	BIND ( bswap );
	BIND ( tzcnt );
	BIND ( bsr );
	BIND ( setb );
	BIND ( setnp );
	BIND ( sets );
	BIND ( rcr );
	BIND ( setnl );
	BIND ( seto );
	BIND ( setbe );
	BIND ( setz );
	BIND ( setnb );
	BIND ( setno );
	BIND ( rol );
	BIND ( rcl );
	BIND ( bt );
	BIND ( bts );
	BIND ( setp );
	BIND ( setle );
	BIND ( setnle );
	BIND ( setns );
	BIND ( setl );
	BIND ( setnbe );
	BIND ( setnz );
	BIND ( cli );
	BIND ( clc );
	BIND ( cmc );
	BIND ( stc );
	BIND ( clui );
	BIND ( cld );
	BIND ( btr );
	BIND ( cwd );
	BIND ( btc );
	BIND ( cbw );
	BIND ( cqo );
	BIND ( cwde );
	BIND ( bsf );
}
#include "pch.hpp"
void and_ ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_binary_op ( instr, state, effect,
			[ ] ( uint64_t a, uint64_t b ) { return a & b; },
			&EmulationContext::update_flags_and
	);
}

void or_ ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_binary_op ( instr, state, effect,
			[ ] ( uint64_t a, uint64_t b ) { return a | b; },
			&EmulationContext::update_flags_or
	);
}

void xor_ ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_binary_op ( instr, state, effect,
			[ ] ( uint64_t a, uint64_t b ) { return a ^ b; },
			&EmulationContext::update_flags_xor
	);
}

void not_ ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_unary_op ( instr, state, effect,
			[ ] ( uint64_t a ) { return ~a; },
			NO_FLAG_HANDLER
	);
}

void shl_sal_common ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect, bool is_sal ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	if ( op_size == 0 || ( op_size != 1 && op_size != 2 && op_size != 4 && op_size != 8 ) ) {
		effect.push_to_changes ( state, std::format ( "{}: Invalid operand size {}", is_sal ? "SAL" : "SHL", op_size ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t val_operand = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	uint64_t count_operand = helpers::get_src<uint64_t> ( &instr, 1, state, 1 ); // Count is usually CL or imm8

	if ( state.exit_due_to_critical_error ) return;

	GET_OPERAND_MASK ( operand_mask, op_size );
	uint64_t original_val_masked = val_operand & operand_mask; // Value to operate on

	uint8_t count_raw = count_operand & 0xFF;
	uint8_t size_in_bits = op_size * 8;
	uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F; // Or (size_in_bits -1) for some interpretations, but 31/63 is common.
	// Intel manual states "The count is masked to 5 bits (or 6 bits if in 64-bit mode and REX.W is used)."
	uint8_t effective_count = count_raw & count_limit_mask;

	uint64_t result = original_val_masked; // Initialize
	if ( effective_count > 0 && effective_count < size_in_bits ) { // Shift count > 0 and < operand size
		result = ( original_val_masked << effective_count ) & operand_mask;
	}
	else if ( effective_count >= size_in_bits ) { // If count >= operand size, result is 0 (for SHL/SAL)
		result = 0;
	}
	// If effective_count is 0, result remains original_val_masked

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, result, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( state.exit_due_to_critical_error ) return;
		state.set_memory ( addr, result, op_size, effect );
		// effect.modified_mem and push_to_changes are handled by set_memory
	}
	else {
		state.exit_due_to_critical_error = true; // Should not happen with valid Capstone decoding
		return;
	}

	state.update_flags_shl ( original_val_masked, count_raw, op_size, effect ); // Pass raw count for flag logic if it needs it for OF with count=1
}

void shl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	shl_sal_common ( instr, state, effect, false );
}

void sal ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	shl_sal_common ( instr, state, effect, true ); // SAL is an alias for SHL
}

void shr ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	if ( op_size == 0 || ( op_size != 1 && op_size != 2 && op_size != 4 && op_size != 8 ) ) {
		effect.push_to_changes ( state, std::format ( "SHR: Invalid operand size {}", op_size ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t val_operand = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	uint64_t count_operand = helpers::get_src<uint64_t> ( &instr, 1, state, 1 );

	if ( state.exit_due_to_critical_error ) return;

	GET_OPERAND_MASK ( operand_mask, op_size );
	uint64_t original_val_masked = val_operand & operand_mask; // Use this for operations and flag updates

	uint8_t count_raw = count_operand & 0xFF;
	uint8_t size_in_bits = op_size * 8;
	uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t effective_count = count_raw & count_limit_mask;

	uint64_t result = original_val_masked; // Initialize
	if ( effective_count > 0 && effective_count < size_in_bits ) {
		result = ( original_val_masked >> effective_count ); // No further mask needed for SHR
	}
	else if ( effective_count >= size_in_bits ) { // If count >= operand size, result is 0
		result = 0;
	}
	// If effective_count is 0, result remains original_val_masked

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, result, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( state.exit_due_to_critical_error ) return;
		state.set_memory ( addr, result, op_size, effect );
	}
	else {
		state.exit_due_to_critical_error = true;
		return;
	}
	state.update_flags_shr ( original_val_masked, count_raw, op_size, effect );
}

void shld ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	uint8_t op_size = ops [ 0 ].size;
	uint8_t size_in_bits = op_size * 8;

	auto dest_emu = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	auto src_reg_emu = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	auto count_emu = helpers::get_src<uint64_t> ( &instr, 2, state, 1 );

	uint64_t value0 = dest_emu;     
	uint64_t value1 = src_reg_emu;  
	uint64_t pcounter = count_emu;	
	uint64_t original_dest = value0;

	uint64_t counter;
	if ( size_in_bits == 64 ) {
		counter = pcounter % 64;
	}
	else {
		counter = pcounter % 32;
		counter = pcounter % size_in_bits;
	}

	uint64_t final_result = value0; // Initialize result
	uint64_t final_cf = state.cpu->cpu_flags.flags.CF; // Default CF

	if ( counter == 0 ) {
		if ( ( pcounter & 0xFF ) == 1 ) {
			state.cpu->cpu_flags.flags.OF = 0;
			state.log_flag_change ( effect, "OF", state.cpu->cpu_flags.flags.OF, 0 );
		}
	}
	else if ( counter > size_in_bits ) {
		effect.push_to_changes ( state,"SHLD: Undefined behavior (count > size), result set to 0." );
		final_result = 0;
		state.update_flags_shl ( original_dest, 0, op_size, effect ); // Use count 0 for flags? Or set directly?
		state.cpu->cpu_flags.flags.ZF = 1; state.cpu->cpu_flags.flags.SF = 0; state.cpu->cpu_flags.flags.PF = 1; state.cpu->cpu_flags.flags.CF = 0; state.cpu->cpu_flags.flags.OF = 0; state.cpu->cpu_flags.flags.AF = 0;
		final_cf = 0; // Set CF to 0
	}
	else {
		GET_OPERAND_MASK ( operand_mask, op_size );
		uint64_t temp_result = value0 & operand_mask;

		final_cf = ( temp_result >> ( size_in_bits - counter ) ) & 1;

		for ( uint64_t i = size_in_bits - 1; i >= counter; --i ) {
			bool bit = ( temp_result >> ( i - counter ) ) & 1;
			temp_result = ( temp_result & ~( 1ULL << i ) ) | ( static_cast< uint64_t >( bit ) << i );
		}
		for ( uint64_t i = 0; i < counter; ++i ) {
			bool bit = ( value1 >> ( i + size_in_bits - counter ) ) & 1;
			temp_result = ( temp_result & ~( 1ULL << i ) ) | ( static_cast< uint64_t > ( bit ) << i );
		}
		final_result = temp_result & operand_mask;

		if ( ( pcounter & 0xFF ) == 1 ) {
			uint64_t original_msb = ( original_dest >> ( size_in_bits - 1 ) ) & 1;
			uint64_t result_msb = ( final_result >> ( size_in_bits - 1 ) ) & 1;
			state.cpu->cpu_flags.flags.OF = original_msb ^ result_msb;
		}
		else {
			state.cpu->cpu_flags.flags.OF = 0;
		}

		state.cpu->cpu_flags.flags.SF = ( final_result >> ( size_in_bits - 1 ) ) & 1;
		state.cpu->cpu_flags.flags.ZF = ( final_result == 0 );
		state.cpu->cpu_flags.flags.PF = std::popcount ( static_cast< uint8_t >( final_result & 0xFF ) ) % 2 == 0;
		state.cpu->cpu_flags.flags.AF = 0;
	}

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, final_result, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		int64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		state.set_memory ( addr, final_result, op_size, effect );
		effect.modified_mem.insert ( addr );
		effect.push_to_changes ( state,std::format ( "[{:016x}h] = {:x}h", addr, final_result ) );
	}
	else {
		return;
	}

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;
	state.cpu->cpu_flags.flags.CF = final_cf;

	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );

}

void shrd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	uint8_t size_in_bits = op_size * 8;

	auto dest_emu = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	auto src_reg_emu = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	auto count_emu = helpers::get_src<uint64_t> ( &instr, 2, state, 1 );

	uint64_t value0 = dest_emu;     
	uint64_t value1 = src_reg_emu;  
	uint64_t pcounter = count_emu;	
	uint64_t original_dest = value0;

	uint64_t counter;
	if ( size_in_bits == 64 ) {
		counter = pcounter % 64;
	}
	else {
		counter = pcounter % size_in_bits;
	}

	uint64_t final_result = value0; 
	uint64_t final_cf = state.cpu->cpu_flags.flags.CF;

	if ( counter == 0 ) {
		if ( ( pcounter & 0xFF ) == 1 ) {
			uint64_t original_msb = ( original_dest >> ( size_in_bits - 1 ) ) & 1;
			state.cpu->cpu_flags.flags.OF = original_msb;
			state.log_flag_change ( effect, "OF", state.cpu->cpu_flags.flags.OF, state.cpu->cpu_flags.flags.OF );
		}

	}
	else if ( counter >= size_in_bits ) {
		effect.push_to_changes ( state,"SHRD: Undefined behavior (count >= size), result set to 0." );
		final_result = 0;
		state.update_flags_shr ( original_dest, 0, op_size, effect );
		state.cpu->cpu_flags.flags.ZF = 1; state.cpu->cpu_flags.flags.SF = 0; state.cpu->cpu_flags.flags.PF = 1; state.cpu->cpu_flags.flags.CF = 0; state.cpu->cpu_flags.flags.OF = 0; state.cpu->cpu_flags.flags.AF = 0;
		final_cf = 0;
	}
	else {
		GET_OPERAND_MASK ( operand_mask, op_size );
		uint64_t temp_result = value0 & operand_mask;

		final_cf = ( temp_result >> ( counter - 1 ) ) & 1;

		for ( uint64_t i = 0; i <= ( size_in_bits - 1 - counter ); ++i ) {
			bool bit = ( temp_result >> ( i + counter ) ) & 1;
			temp_result = ( temp_result & ~( 1ULL << i ) ) | ( static_cast< uint64_t >( bit ) << i );
		}

		for ( uint64_t i = size_in_bits - counter; i < size_in_bits; ++i ) {
			bool bit = ( value1 >> ( i + counter - size_in_bits ) ) & 1;
			temp_result = ( temp_result & ~( 1ULL << i ) ) | ( static_cast< uint64_t > ( bit ) << i );
		}
		final_result = temp_result & operand_mask;

		if ( ( pcounter & 0xFF ) == 1 ) {
			uint64_t original_msb = ( original_dest >> ( size_in_bits - 1 ) ) & 1;
			uint64_t result_msb = ( final_result >> ( size_in_bits - 1 ) ) & 1;
			state.cpu->cpu_flags.flags.OF = original_msb ^ result_msb;
		}
		else {
			state.cpu->cpu_flags.flags.OF = 0;
		}

		state.cpu->cpu_flags.flags.SF = ( final_result >> ( size_in_bits - 1 ) ) & 1;
		state.cpu->cpu_flags.flags.ZF = ( final_result == 0 );
		state.cpu->cpu_flags.flags.PF = std::popcount ( static_cast< uint8_t >( final_result & 0xFF ) ) % 2 == 0;
	}

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, final_result, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		int64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		state.set_memory ( addr, final_result, op_size, effect );
		effect.modified_mem.insert ( addr );
		effect.push_to_changes ( state,std::format ( "[{:016x}h] = {:x}h", addr, final_result ) );
	}
	else {
		return;
	}

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;
	state.cpu->cpu_flags.flags.CF = final_cf;

	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
}

void sar ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	if ( op_size == 0 || ( op_size != 1 && op_size != 2 && op_size != 4 && op_size != 8 ) ) {
		effect.push_to_changes ( state, std::format ( "SAR: Invalid operand size {}", op_size ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t val_operand = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	uint64_t count_operand = helpers::get_src<uint64_t> ( &instr, 1, state, 1 );

	if ( state.exit_due_to_critical_error ) return;

	GET_OPERAND_MASK ( operand_mask, op_size );
	uint64_t original_val_masked = val_operand & operand_mask; // Value as it exists in op_size

	uint8_t count_raw = count_operand & 0xFF;
	uint8_t size_in_bits = op_size * 8;
	uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t effective_count = count_raw & count_limit_mask;

	uint64_t result = original_val_masked; // Initialize
	if ( effective_count > 0 ) {
		// For SAR, we need to treat the original_val_masked as signed for the shift.
		// Convert to int64_t after proper sign extension from its original op_size.
		int64_t signed_val_for_shift = helpers::sign_extend ( original_val_masked, op_size );

		if ( effective_count < size_in_bits ) {
			result = ( static_cast< uint64_t > ( signed_val_for_shift >> effective_count ) ) & operand_mask;
		}
		else { // If count >= size_in_bits, result is all 0s or all 1s based on original sign bit
			if ( ( signed_val_for_shift >> ( size_in_bits - 1 ) ) & 1 ) { // Check sign bit of original op_size value
				result = operand_mask; // All 1s
			}
			else {
				result = 0; // All 0s
			}
		}
	}
	// If effective_count is 0, result remains original_val_masked

	if ( ops [ 0 ].type == X86_OP_REG ) {
		state.set_reg ( ops [ 0 ].reg, result, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( state.exit_due_to_critical_error ) return;
		state.set_memory ( addr, result, op_size, effect );
	}
	else {
		state.exit_due_to_critical_error = true;
		return;
	}
	state.update_flags_sar ( original_val_masked, count_raw, op_size, effect );
}

void cmovo ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.OF; } );
}

void cmovnl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF; } );
}

void cmovbe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.CF || state.cpu->cpu_flags.flags.ZF; } );
}

void cmovz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.ZF; } );
}

void cmovle ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.ZF || ( state.cpu->cpu_flags.flags.SF != state.cpu->cpu_flags.flags.OF ); } );
}

void cmovl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF != state.cpu->cpu_flags.flags.OF; } );
}

void cmovnp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.PF; } );
}

void cmovns ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.SF; } );
}

void cmovp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.PF; } );
}

void cmovnb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.CF; } );
}

void cmovno ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.OF; } );
}

void cmovs ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF; } );
}

void cmovnz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.ZF; } );
}

void cmovnbe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return !state.cpu->cpu_flags.flags.ZF && !state.cpu->cpu_flags.flags.CF; } );
}

void cmovb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.CF; } );
}

void cmovnle ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	helpers::handle_cmovcc ( instr, state, effect, [ ] ( const auto& state ) { return state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF; } );
}

// defined for heaven's gate memes
void bound ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) < 2 || ops [ 0 ].type != X86_OP_REG || ops [ 1 ].type != X86_OP_MEM ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	uint8_t op_size = ops [ 0 ].size;
	x86_reg index_reg = ops [ 0 ].reg;
	const cs_x86_op& mem_op = ops [ 1 ];

	if ( op_size != 2 && op_size != 4 ) {
		effect.push_to_changes ( state,std::format ( "BOUND: Invalid operand size {} (must be 2 or 4)", op_size ) );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	uint64_t bounds_addr = helpers::calculate_mem_addr ( mem_op, instr, state );

	int32_t signed_index = 0;
	int32_t signed_lower_bound = 0;
	int32_t signed_upper_bound = 0;

	if ( op_size == 2 ) {
		signed_index = static_cast< int16_t >( state.get_reg ( index_reg, op_size ) );
		signed_lower_bound = static_cast< int16_t >( state.get_memory ( bounds_addr, op_size ) );
		signed_upper_bound = static_cast< int16_t >( state.get_memory ( bounds_addr + op_size, op_size ) );
	}
	else {
		signed_index = static_cast< int32_t >( state.get_reg ( index_reg, op_size ) );
		signed_lower_bound = static_cast< int32_t >( state.get_memory ( bounds_addr, op_size ) );
		signed_upper_bound = static_cast< int32_t >( state.get_memory ( bounds_addr + op_size, op_size ) );
	}

	if ( signed_index < signed_lower_bound || signed_index > signed_upper_bound ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ARRAY_BOUNDS_EXCEEDED, instr.ip ( ) );
		throw ex;
	}

	if ( state.options.enable_logging ) {
		effect.push_to_changes ( state,std::format ( "BOUND check passed: {} <= {} <= {}", signed_lower_bound, signed_index, signed_upper_bound ) );
	}
}

#include <random>
void rdrand ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	static std::mt19937 gen ( std::random_device {}( ) );
	const cs_x86_op* ops = instr.operands ( );

	if ( instr.operand_count ( ) != 1 || ops [ 0 ].type != X86_OP_REG ) {
		state.exit_due_to_critical_error = true;
		return;
	}

	x86_reg dst_reg = ops [ 0 ].reg;
	uint8_t op_size = ops [ 0 ].size;

	if ( op_size != 2 && op_size != 4 && op_size != 8 ) {
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t rand_val;

	if ( op_size == 2 ) {
		std::uniform_int_distribution<uint16_t> dist;
		uint16_t rand_val_16 = dist ( gen );
		rand_val = static_cast< uint64_t >( rand_val_16 );
	}
	else if ( op_size == 4 ) {
		std::uniform_int_distribution<uint32_t> dist;
		uint32_t rand_val_32 = dist ( gen );
		rand_val = static_cast< uint64_t >( rand_val_32 );
	}
	else if ( op_size == 8 ) {
		std::uniform_int_distribution<uint64_t> dist;
		rand_val = dist ( gen );
	}

	state.set_reg ( dst_reg, rand_val, op_size, effect );

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF;
	uint64_t old_OF = state.cpu->cpu_flags.flags.OF;
	uint64_t old_SF = state.cpu->cpu_flags.flags.SF;
	uint64_t old_ZF = state.cpu->cpu_flags.flags.ZF;
	uint64_t old_AF = state.cpu->cpu_flags.flags.AF;
	uint64_t old_PF = state.cpu->cpu_flags.flags.PF;

	state.cpu->cpu_flags.flags.CF = 1;
	state.cpu->cpu_flags.flags.OF = 0;
	state.cpu->cpu_flags.flags.SF = 0;
	state.cpu->cpu_flags.flags.ZF = 0;
	state.cpu->cpu_flags.flags.AF = 0;
	state.cpu->cpu_flags.flags.PF = 0;

	if ( old_CF != 1 ) state.log_flag_change ( effect, "CF", old_CF, 1 );
	if ( old_OF != 0 ) state.log_flag_change ( effect, "OF", old_OF, 0 );
	if ( old_SF != 0 ) state.log_flag_change ( effect, "SF", old_SF, 0 );
	if ( old_ZF != 0 ) state.log_flag_change ( effect, "ZF", old_ZF, 0 );
	if ( old_AF != 0 ) state.log_flag_change ( effect, "AF", old_AF, 0 );
	if ( old_PF != 0 ) state.log_flag_change ( effect, "PF", old_PF, 0 );
}

void helpers::bind_logical ( ) {
	BIND ( and_ );
	BIND ( or_ );
	BIND ( xor_ );
	BIND ( not_ );
	BIND ( shl );
	BIND ( shld );
	BIND ( shr );
	BIND ( shrd );
	BIND ( sar );
	BIND ( sal );
	BIND ( cmovo );
	BIND ( cmovnl );
	BIND ( cmovbe );
	BIND ( cmovz );
	BIND ( cmovle );
	BIND ( cmovl );
	BIND ( cmovnp );
	BIND ( cmovns );
	BIND ( cmovp );
	BIND ( cmovnb );
	BIND ( cmovno );
	BIND ( cmovs );
	BIND ( cmovnz );
	BIND ( cmovnbe );
	BIND ( cmovb );
	BIND ( cmovnle );
	BIND ( bound );
	BIND ( rdrand );


}
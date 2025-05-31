#include "pch.hpp"

namespace mp = boost::multiprecision;
using int128_t = mp::int128_t;
using uint128_t = mp::uint128_t;

void add ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	uint64_t dst_val = helpers::get_operand_value<uint64_t> ( instr, 0, state, effect );
	uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1, state, effect );
	uint64_t result = dst_val + src_val;
	helpers::set_dst_value<uint64_t> ( instr, 0, result, state, effect );
	GET_OPERAND_MASK ( operand_mask, op_size );
	state.update_flags_add ( dst_val & operand_mask, src_val & operand_mask, op_size, effect );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg full_dst_reg = state.to_64bit_reg ( ops [ 0 ].reg );
		if ( full_dst_reg == X86_REG_RSP ) {
			state.stack_allocated -= ( src_val & operand_mask );
		}
	}
}

void sub ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	if ( op_size == 0 ) op_size = 8;

	uint64_t dst_val = helpers::get_operand_value<uint64_t> ( instr, 0, state, effect );
	uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1, state, effect );
	uint64_t result = dst_val - src_val;

	helpers::set_dst_value<uint64_t> ( instr, 0, result, state, effect );

	GET_OPERAND_MASK ( operand_mask, op_size );
	state.update_flags_sub ( dst_val & operand_mask, src_val & operand_mask, op_size, effect );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg full_dst_reg = state.to_64bit_reg ( ops [ 0 ].reg );
		if ( full_dst_reg == X86_REG_RSP ) {
			state.stack_allocated += ( src_val & operand_mask );
		}
	}
}
void inc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		auto cur = state.get_reg ( dst, op_size );
		uint64_t result = cur + 1;
		state.set_reg ( dst, result, op_size, effect );
		state.update_flags_inc ( cur, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( addr == 0 ) {
			return;
		}
		auto cur = state.get_memory ( addr, op_size );
		uint64_t result = cur + 1;
		if ( state.is_within_stack_bounds ( addr, op_size ) ) {
			state.set_stack ( addr, result, effect, op_size );
		}
		else {
			state.set_memory ( addr, result, op_size, effect );
		}
		state.update_flags_inc ( cur, op_size, effect );
		effect.modified_mem.insert ( addr );
	}
}

void dec ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		auto cur = state.get_reg ( dst, op_size );
		uint64_t result = cur - 1;
		state.set_reg ( dst, result, op_size, effect );
		state.update_flags_dec ( cur, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( addr == 0 ) {
			return;
		}
		auto cur = state.get_memory ( addr, op_size );
		uint64_t result = cur - 1;
		if ( state.is_within_stack_bounds ( addr, op_size ) ) {
			state.set_stack ( addr, result, effect, op_size );
		}
		else {
			state.set_memory ( addr, result, op_size, effect );
		}
		state.update_flags_dec ( cur, op_size, effect );
		effect.modified_mem.insert ( addr );
	}
}

void mul ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	auto src_val = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );

	x86_reg low_reg, high_reg;
	uint64_t mask = ( 1ULL << ( op_size * 8 ) ) - 1;
	if ( op_size == 8 ) mask = 0xFFFFFFFFFFFFFFFFULL;

	switch ( op_size ) {
		case 1: low_reg = X86_REG_AL; high_reg = X86_REG_AH; break;
		case 2: low_reg = X86_REG_AX; high_reg = X86_REG_DX; break;
		case 4: low_reg = X86_REG_EAX; high_reg = X86_REG_EDX; break;
		case 8: low_reg = X86_REG_RAX; high_reg = X86_REG_RDX; break;
		default: return;
	}

	uint64_t acc_val = state.get_reg ( low_reg, op_size );

	uint128_t full_res = uint128_t ( acc_val ) * uint128_t ( src_val );

	uint64_t low_res = static_cast< uint64_t >( full_res & mask );
	uint64_t high_res = 0;
	if ( op_size < 8 ) {
		high_res = static_cast< uint64_t > ( ( full_res >> ( op_size * 8 ) ) & mask );
	}
	else {
		high_res = static_cast< uint64_t > ( full_res >> 64 );
	}

	state.set_reg ( low_reg, low_res, op_size, effect );
	state.set_reg ( high_reg, high_res, op_size, effect );

	uint64_t old_CF = state.cpu->cpu_flags.flags.CF, old_OF = state.cpu->cpu_flags.flags.OF;
	state.cpu->cpu_flags.flags.CF = state.cpu->cpu_flags.flags.OF = ( high_res != 0 );
	state.cpu->cpu_flags.flags.SF = 0;
	state.cpu->cpu_flags.flags.ZF = 0;
	state.cpu->cpu_flags.flags.PF = 0;
	state.cpu->cpu_flags.flags.AF = 0;
	if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
	if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );

}

void imul ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	const auto op_count = instr.operand_count ( );

	if ( op_count == 1 ) {
		uint8_t op_size = ops [ 0 ].size ? ops [ 0 ].size : 8;
		auto src_val_raw = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );

		x86_reg low_reg, high_reg;
		int bits = op_size * 8;

		switch ( op_size ) {
			case 1: low_reg = X86_REG_AL; high_reg = X86_REG_AH; break;
			case 2: low_reg = X86_REG_AX; high_reg = X86_REG_DX; break;
			case 4: low_reg = X86_REG_EAX; high_reg = X86_REG_EDX; break;
			case 8: low_reg = X86_REG_RAX; high_reg = X86_REG_RDX; break;
			default: return;
		}

		int64_t acc_signed = static_cast< int64_t >( state.get_reg ( low_reg, op_size ) );
		int64_t src_signed = static_cast< int64_t >( src_val_raw );
		if ( op_size < 8 ) {
			acc_signed = helpers::sign_extend ( static_cast< uint64_t > ( acc_signed ), op_size );
			src_signed = helpers::sign_extend ( static_cast< uint64_t > ( src_signed ), op_size );
		}

		int128_t full_res = int128_t ( acc_signed ) * int128_t ( src_signed );

		uint64_t low_res = static_cast< uint64_t > ( full_res & 0xFFFFFFFFFFFFFFFF );
		uint64_t high_res = static_cast< uint64_t > ( full_res >> 64 );

		state.set_reg ( low_reg, low_res, op_size, effect );
		state.set_reg ( high_reg, high_res, op_size, effect );

		bool overflow = false;
		int128_t stored_val_sign_extended = helpers::sign_extend ( static_cast< uint128_t >( low_res ), op_size );
		if ( stored_val_sign_extended != full_res ) {
			overflow = true;
		}

		uint64_t old_CF = state.cpu->cpu_flags.flags.CF, old_OF = state.cpu->cpu_flags.flags.OF;
		state.cpu->cpu_flags.flags.CF = state.cpu->cpu_flags.flags.OF = overflow;
		if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );

	}
	else if ( op_count == 2 && ops [ 0 ].type == X86_OP_REG ) {
		uint8_t op_size = ops [ 0 ].size ? ops [ 0 ].size : ( ops [ 1 ].size ? ops [ 1 ].size : 8 );
		x86_reg dst = ops [ 0 ].reg;
		int bits = op_size * 8;

		uint64_t cur_raw = state.get_reg ( dst, op_size );
		uint64_t src_raw = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );

		int64_t cur_signed = static_cast< int64_t >( cur_raw );
		int64_t src_signed = static_cast< int64_t >( src_raw );
		if ( op_size < 8 ) {
			cur_signed = helpers::sign_extend ( static_cast< uint64_t > ( cur_signed ), op_size );
			src_signed = helpers::sign_extend ( static_cast< uint64_t > ( src_signed ), op_size );
		}

		int128_t full_res = int128_t ( cur_signed ) * int128_t ( src_signed );
		uint64_t low_res = static_cast< uint64_t > ( full_res & 0xFFFFFFFFFFFFFFFF );

		bool overflow = false;
		int128_t stored_val_sign_extended = helpers::sign_extend ( static_cast< uint128_t > ( low_res ), op_size );
		if ( stored_val_sign_extended != full_res ) {
			overflow = true;
		}

		state.set_reg ( dst, low_res, op_size, effect );

		uint64_t old_CF = state.cpu->cpu_flags.flags.CF, old_OF = state.cpu->cpu_flags.flags.OF;
		state.cpu->cpu_flags.flags.CF = state.cpu->cpu_flags.flags.OF = overflow;
		if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
	}
	else if ( op_count == 3 && ops [ 0 ].type == X86_OP_REG && ops [ 2 ].type == X86_OP_IMM ) {
		uint8_t op_size = ops [ 0 ].size ? ops [ 0 ].size : ( ops [ 1 ].size ? ops [ 1 ].size : 8 );
		x86_reg dst = ops [ 0 ].reg;
		int bits = op_size * 8;

		uint64_t src1_raw = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
		uint64_t imm_raw = helpers::get_src<uint64_t> ( &instr, 2, state, op_size );

		int64_t src1_signed = static_cast< int64_t >( src1_raw );
		int64_t imm_signed = static_cast< int64_t >( imm_raw );
		if ( op_size < 8 ) {
			src1_signed = helpers::sign_extend ( static_cast< uint64_t > ( src1_signed ), op_size );
			imm_signed = helpers::sign_extend ( static_cast< uint64_t > ( imm_signed ), op_size );
		}

		int128_t full_res = int128_t ( src1_signed ) * int128_t ( imm_signed );
		uint64_t low_res = static_cast< uint64_t > ( full_res & 0xFFFFFFFFFFFFFFFF );

		bool overflow = false;
		int128_t stored_val_sign_extended = helpers::sign_extend ( static_cast< uint128_t > ( low_res ), op_size );
		if ( stored_val_sign_extended != full_res ) {
			overflow = true;
		}

		state.set_reg ( dst, low_res, op_size, effect );

		uint64_t old_CF = state.cpu->cpu_flags.flags.CF, old_OF = state.cpu->cpu_flags.flags.OF;
		state.cpu->cpu_flags.flags.CF = state.cpu->cpu_flags.flags.OF = overflow;
		if ( old_CF != state.cpu->cpu_flags.flags.CF ) state.log_flag_change ( effect, "CF", old_CF, state.cpu->cpu_flags.flags.CF );
		if ( old_OF != state.cpu->cpu_flags.flags.OF ) state.log_flag_change ( effect, "OF", old_OF, state.cpu->cpu_flags.flags.OF );
	}
	else {
		state.exit_due_to_critical_error = true;
	}
}

namespace
{
	bool divide_unsigned_boost ( uint128_t dividend, uint64_t divisor, uint8_t op_size, uint64_t& quotient, uint64_t& remainder ) {
		if ( divisor == 0 ) return true;

		uint128_t q = dividend / divisor;
		uint128_t r = dividend % divisor;

		uint128_t max_quotient_val = 0;
		if ( op_size == 8 ) max_quotient_val = uint128_t ( 0xFFFFFFFFFFFFFFFFULL );
		else max_quotient_val = ( uint128_t ( 1 ) << ( op_size * 8 ) ) - 1;

		if ( q > max_quotient_val ) return true;

		quotient = static_cast< uint64_t >( q );
		remainder = static_cast< uint64_t >( r );
		return false;
	}

	bool divide_signed_boost ( int128_t dividend, int64_t divisor_raw, uint8_t op_size, int64_t& quotient, int64_t& remainder ) {
		int bits = op_size * 8;
		int64_t divisor = helpers::sign_extend ( static_cast< uint64_t >( divisor_raw ), op_size );

		if ( divisor == 0 ) return true;

		int bits_dividend = bits * 2;
		if ( bits_dividend > 128 ) bits_dividend = 128;

		int128_t min_dividend = -( int128_t ( 1 ) << ( bits_dividend - 1 ) );
		if ( dividend == min_dividend && divisor == -1 ) return true;

		int128_t q = dividend / divisor;
		int128_t r = dividend % divisor;

		int128_t min_quotient = -( int128_t ( 1 ) << ( bits - 1 ) );
		int128_t max_quotient = ( int128_t ( 1 ) << ( bits - 1 ) ) - 1;
		if ( q < min_quotient || q > max_quotient ) return true;

		quotient = static_cast< int64_t >( q );
		remainder = static_cast< int64_t >( r );
		return false;
	}
}


void _div ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) < 1 ) {
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t op_size = ops [ 0 ].size;
	if ( op_size != 1 && op_size != 2 && op_size != 4 && op_size != 8 ) {
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}

	uint64_t divisor_val = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );

	uint128_t dividend = 0;
	x86_reg quotient_reg = X86_REG_INVALID;
	x86_reg remainder_reg = X86_REG_INVALID;

	switch ( op_size ) {
		case 1:
			quotient_reg = X86_REG_AL; remainder_reg = X86_REG_AH;
			dividend = state.get_reg ( X86_REG_AX, 2 );
			break;
		case 2:
			quotient_reg = X86_REG_AX; remainder_reg = X86_REG_DX;
			dividend = ( uint128_t ( state.get_reg ( X86_REG_DX, 2 ) ) << 16 ) | state.get_reg ( X86_REG_AX, 2 );
			break;
		case 4:
			quotient_reg = X86_REG_EAX; remainder_reg = X86_REG_EDX;
			dividend = ( uint128_t ( state.get_reg ( X86_REG_EDX, 4 ) ) << 32 ) | state.get_reg ( X86_REG_EAX, 4 );
			break;
		case 8:
			quotient_reg = X86_REG_RAX; remainder_reg = X86_REG_RDX;
			dividend = ( uint128_t ( state.get_reg ( X86_REG_RDX, 8 ) ) << 64 ) | state.get_reg ( X86_REG_RAX, 8 );
			break;
	}

	uint64_t quotient_res = 0, remainder_res = 0;
	bool overflow = divide_unsigned_boost ( dividend, divisor_val, op_size, quotient_res, remainder_res );

	if ( overflow ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_INT_DIVIDE_BY_ZERO, instr.ip ( ) );
		throw ex;
	}

	state.set_reg ( quotient_reg, quotient_res, op_size, effect );
	state.set_reg ( remainder_reg, remainder_res, op_size, effect );
}

void idiv ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) < 1 ) {
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t op_size = ops [ 0 ].size;
	if ( op_size != 1 && op_size != 2 && op_size != 4 && op_size != 8 ) {
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}

	int64_t divisor_val_raw = helpers::get_src<int64_t> ( &instr, 0, state, op_size );

	int128_t dividend = 0;
	x86_reg quotient_reg = X86_REG_INVALID;
	x86_reg remainder_reg = X86_REG_INVALID;

	switch ( op_size ) {
		case 1:
		{
			quotient_reg = X86_REG_AL; remainder_reg = X86_REG_AH;
			int16_t ax_val = static_cast< int16_t >( state.get_reg ( X86_REG_AX, 2 ) );
			dividend = ax_val;
			break;
		}
		case 2:
		{
			quotient_reg = X86_REG_AX; remainder_reg = X86_REG_DX;
			uint16_t dx_val = static_cast< uint16_t >( state.get_reg ( X86_REG_DX, 2 ) );
			uint16_t ax_val = static_cast< uint16_t >( state.get_reg ( X86_REG_AX, 2 ) );
			int32_t dxax_val = ( static_cast< int32_t >( dx_val ) << 16 ) | ax_val;
			dividend = dxax_val;
			break;
		}
		case 4:
		{
			quotient_reg = X86_REG_EAX; remainder_reg = X86_REG_EDX;
			uint32_t edx_val = static_cast< uint32_t >( state.get_reg ( X86_REG_EDX, 4 ) );
			uint32_t eax_val = static_cast< uint32_t >( state.get_reg ( X86_REG_EAX, 4 ) );
			int64_t edxeax_val = ( static_cast< int64_t >( edx_val ) << 32 ) | eax_val;
			dividend = edxeax_val;
			break;
		}
		case 8:
		{
			quotient_reg = X86_REG_RAX; remainder_reg = X86_REG_RDX;
			uint64_t rdx_val = state.get_reg ( X86_REG_RDX, 8 );
			uint64_t rax_val = state.get_reg ( X86_REG_RAX, 8 );
			dividend = ( int128_t ( rdx_val ) << 64 ) | rax_val;
			break;
		}
	}

	int64_t quotient_res = 0, remainder_res = 0;
	bool overflow = divide_signed_boost ( dividend, divisor_val_raw, op_size, quotient_res, remainder_res );

	if ( overflow ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_INT_DIVIDE_BY_ZERO, instr.ip ( ) );
		throw ex;
	}

	state.set_reg ( quotient_reg, static_cast< uint64_t >( quotient_res ), op_size, effect );
	state.set_reg ( remainder_reg, static_cast< uint64_t >( remainder_res ), op_size, effect );
}

void cdq ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto eax = state.get_reg ( X86_REG_EAX, 4 );
	int32_t eax_val = static_cast< int32_t >( eax );
	uint32_t edx_val = ( eax_val < 0 ) ? 0xFFFFFFFF : 0;
	state.set_reg ( X86_REG_EDX, edx_val, 4, effect );
}

void cdqe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	auto eax = state.get_reg ( X86_REG_EAX, 4 );
	int32_t eax_val = static_cast< int32_t > ( eax );
	int64_t sign_extended = static_cast< int64_t > ( eax_val );
	state.set_reg ( X86_REG_RAX, sign_extended, 8, effect );
}

void adc ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;

	uint64_t src = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	uint64_t carry = state.cpu->cpu_flags.flags.CF;
	GET_OPERAND_MASK ( mask, op_size );
	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		auto cur = state.get_reg ( dst, op_size );

		uint64_t cur_val = cur & mask;
		uint64_t src_val = src & mask;
		uint64_t carry_val = carry;
		uint64_t result = cur_val + src_val + carry_val;
		state.set_reg ( dst, result & mask, op_size, effect );
		state.update_flags_adc ( cur_val, src_val, carry_val, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( addr == 0 ) {
			return;
		}
		auto cur = state.get_memory ( addr, op_size );
		uint64_t cur_val = cur & mask;
		uint64_t src_val = src & mask;
		uint64_t carry_val = carry;
		uint64_t result = cur_val + src_val + carry_val;
		if ( state.is_within_stack_bounds ( addr, op_size ) ) {
			state.set_stack ( addr, result & mask, effect, op_size );
		}
		else {
			state.set_memory ( addr, result & mask, op_size, effect );
		}
		state.update_flags_adc ( cur_val, src_val, carry_val, op_size, effect );
		effect.modified_mem.insert ( addr );
	}
}

void sbb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	uint64_t src = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	uint64_t borrow = state.cpu->cpu_flags.flags.CF;
	GET_OPERAND_MASK ( mask, op_size );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		auto cur = state.get_reg ( dst, op_size );
		uint64_t cur_val = cur & mask;
		uint64_t src_val = src & mask;
		uint64_t borrow_val = borrow;
		uint64_t result = cur_val - src_val - borrow_val;

		// Handle partial register writes (e.g., DH)
		uint8_t shift = state.get_access_shift ( dst, op_size );
		uint64_t access_mask = state.get_access_mask ( dst, op_size );
		x86_reg full_reg = state.to_64bit_reg ( dst );
		uint64_t old_full = state.get_reg ( full_reg, 8 );
		uint64_t new_full = ( old_full & ~access_mask ) | ( ( result << shift ) & access_mask );

		state.set_reg ( full_reg, new_full, 8, effect );
		state.update_flags_sub ( cur_val, src_val + borrow_val, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( addr == 0 ) {
			return;
		}
		auto cur = state.get_memory ( addr, op_size );
		uint64_t cur_val = cur & mask;
		uint64_t src_val = src & mask;
		uint64_t borrow_val = borrow;
		uint64_t result = cur_val - src_val - borrow_val;

		if ( state.is_within_stack_bounds ( addr, op_size ) ) {
			state.set_stack ( addr, result, effect, op_size );
		}
		else {
			state.set_memory ( addr, result, op_size, effect );
		}
		state.update_flags_sub ( cur_val, src_val + borrow_val, op_size, effect );
		effect.modified_mem.insert ( addr );
	}
}
void neg ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	GET_OPERAND_MASK ( mask, op_size );

	if ( ops [ 0 ].type == X86_OP_REG ) {
		x86_reg dst = ops [ 0 ].reg;
		auto cur = state.get_reg ( dst, op_size );

		int64_t val = cur & mask;
		int64_t result = -val;
		state.set_reg ( dst, result, op_size, effect );
		//state.update_flags_neg ( val, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( addr == 0 ) {
			return;
		}
		auto cur = state.get_memory ( addr, op_size );
		int64_t val = cur & mask;
		int64_t result = -val;
		if ( state.is_within_stack_bounds ( addr, op_size ) ) {
			state.set_stack ( addr, result, effect, op_size );
		}
		else {
			state.set_memory ( addr, result, op_size, effect );
		}
		//state.update_flags_neg ( val, op_size, effect );
		effect.modified_mem.insert ( addr );
	}
}

void xadd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	GET_OPERAND_MASK ( mask, op_size );

	if ( ops [ 0 ].type == X86_OP_REG && ops [ 1 ].type == X86_OP_REG ) {
		x86_reg dst_reg = ops [ 0 ].reg;
		x86_reg src_reg = ops [ 1 ].reg;
		auto dst_val = state.get_reg ( dst_reg, op_size );
		auto src_val = state.get_reg ( src_reg, op_size );

		uint64_t orig_dst = dst_val & mask;
		uint64_t orig_src = src_val & mask;
		uint64_t sum = orig_dst + orig_src;

		state.set_reg ( src_reg, orig_dst, op_size, effect );
		state.set_reg ( dst_reg, sum, op_size, effect );
		state.update_flags_add ( orig_dst, orig_src, op_size, effect );
	}
	else if ( ops [ 0 ].type == X86_OP_MEM && ops [ 1 ].type == X86_OP_REG ) {
		uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
		if ( addr == 0 ) {
			return;
		}
		x86_reg src_reg = ops [ 1 ].reg;
		auto mem_val = state.get_memory ( addr, op_size );
		auto reg_val = state.get_reg ( src_reg, op_size );

		uint64_t orig_mem = mem_val & mask;
		uint64_t orig_reg = reg_val & mask;
		uint64_t sum = orig_mem + orig_reg;

		state.set_reg ( src_reg, orig_mem, op_size, effect );
		if ( state.is_within_stack_bounds ( addr, op_size ) ) {
			state.set_stack ( addr, sum, effect, op_size );
		}
		else {
			state.set_memory ( addr, sum, op_size, effect );
		}
		state.update_flags_add ( orig_mem, orig_reg, op_size, effect );
		effect.modified_mem.insert ( addr );
	}
	else {
		state.exit_due_to_critical_error = true;
	}

}

void io_out ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	const auto op_count = instr.operand_count ( );

	std::println ( "io_out: Executing at IP=0x{:016x}", instr.ip ( ) );

	switch ( op_count ) {
		case 2:
			break;
		default:
			state.exit_due_to_critical_error = true;
			std::println ( "io_out: Invalid operand count {}", static_cast< int >( op_count ) );
			return;
	}

	uint8_t op_size = 0;
	uint64_t data_val = 0;
	x86_reg data_reg = X86_REG_INVALID;

	switch ( ops [ 1 ].type ) {
		case X86_OP_REG:
			data_reg = ops [ 1 ].reg;
			op_size = ops [ 1 ].size;
			switch ( data_reg ) {
				case X86_REG_AL:
					switch ( op_size ) {
						case 1:
							data_val = state.get_reg ( X86_REG_AL, 1 );
							std::println ( "io_out: AL=0x{:x}", data_val );
							break;
						default:
							state.exit_due_to_critical_error = true;
							std::println ( "io_out: Invalid size {} for AL", static_cast< int >( op_size ) );
							return;
					}
					break;
				case X86_REG_AX:
					switch ( op_size ) {
						case 2:
							data_val = state.get_reg ( X86_REG_AX, 2 );
							std::println ( "io_out: AX=0x{:x}", data_val );
							break;
						default:
							state.exit_due_to_critical_error = true;
							std::println ( "io_out: Invalid size {} for AX", static_cast< int >( op_size ) );
							return;
					}
					break;
				case X86_REG_EAX:
					switch ( op_size ) {
						case 4:
							data_val = state.get_reg ( X86_REG_EAX, 4 );
							std::println ( "io_out: EAX=0x{:x}", data_val );
							break;
						default:
							state.exit_due_to_critical_error = true;
							std::println ( "io_out: Invalid size {} for EAX", static_cast< int >( op_size ) );
							return;
					}
					break;
				default:
					state.exit_due_to_critical_error = true;
					std::println ( "io_out: Invalid data register {}", static_cast< int >( data_reg ) );
					return;
			}
			break;
		default:
			state.exit_due_to_critical_error = true;
			std::println ( "io_out: Invalid data operand type {}", static_cast< int >( ops [ 1 ].type ) );
			return;
	}

	uint16_t port_addr = 0;
	switch ( ops [ 0 ].type ) {
		case X86_OP_IMM:
			switch ( ops [ 0 ].size ) {
				case 1:
				case 2:
					port_addr = static_cast< uint16_t >( ops [ 0 ].imm );
					break;
				default:
					state.exit_due_to_critical_error = true;
					std::println ( "io_out: Invalid port address size {}", static_cast< int >( ops [ 0 ].size ) );
					return;
			}
			break;
		case X86_OP_REG:
			switch ( ops [ 0 ].reg ) {
				case X86_REG_DX:
					switch ( ops [ 0 ].size ) {
						case 2:
							port_addr = static_cast< uint16_t >( state.get_reg ( X86_REG_DX, 2 ) );
							break;
						default:
							state.exit_due_to_critical_error = true;
							std::println ( "io_out: Invalid size {} for DX", static_cast< int >( ops [ 0 ].size ) );
							return;
					}
					break;
				default:
					state.exit_due_to_critical_error = true;
					std::println ( "io_out: Invalid port register {}", static_cast< int >( ops [ 0 ].reg ) );
					return;
			}
			break;
		default:
			state.exit_due_to_critical_error = true;
			std::println ( "io_out: Invalid port operand type {}", static_cast< int >( ops [ 0 ].type ) );
			return;
	}

	uint64_t mask = 0;
	switch ( op_size ) {
		case 1:
			mask = 0xFF;
			break;
		case 2:
			mask = 0xFFFF;
			break;
		case 4:
			mask = 0xFFFFFFFF;
			break;
		default:
			state.exit_due_to_critical_error = true;
			std::println ( "io_out: Invalid operand size {}", static_cast< int >( op_size ) );
			return;
	}
	data_val &= mask;

	state.windows->io_ports [ port_addr ] = data_val;
	std::println ( "OUT: Port 0x{:04x} <- 0x{:x}", port_addr, data_val );
	std::println ( "RAX after OUT (unchanged): 0x{:x}", state.get_reg ( X86_REG_RAX, 8 ) );
}






void io_in ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	const auto op_count = instr.operand_count ( );

	if ( op_count != 2 ) {
		state.exit_due_to_critical_error = true;
		return;
	}

	if ( ops [ 0 ].type != X86_OP_REG ) {
		state.exit_due_to_critical_error = true;
		return;
	}

	x86_reg dest_reg = ops [ 0 ].reg;
	uint8_t op_size = ops [ 0 ].size;

	switch ( dest_reg ) {
		case X86_REG_AL:
			if ( op_size != 1 ) {
				state.exit_due_to_critical_error = true;
				return;
			}
			break;
		case X86_REG_AX:
			if ( op_size != 2 ) {
				state.exit_due_to_critical_error = true;
				return;
			}
			break;
		case X86_REG_EAX:
			if ( op_size != 4 ) {
				state.exit_due_to_critical_error = true;
				return;
			}
			break;
		default:
			state.exit_due_to_critical_error = true;
			return;
	}

	uint16_t port_addr = 0;
	if ( ops [ 1 ].type == X86_OP_IMM ) {
		if ( ops [ 1 ].size > 2 ) {
			state.exit_due_to_critical_error = true;
			return;
		}
		port_addr = static_cast< uint16_t >( ops [ 1 ].imm );
	}
	else if ( ops [ 1 ].type == X86_OP_REG && ops [ 1 ].reg == X86_REG_DX ) {
		port_addr = static_cast< uint16_t >( state.get_reg ( X86_REG_DX, 2 ) );
	}
	else {
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t data_val = state.windows->io_ports.count ( port_addr ) ? state.windows->io_ports [ port_addr ] : 0;

	uint64_t mask = 0;
	switch ( op_size ) {
		case 1:
			mask = 0xFF;
			data_val &= mask;
			state.set_reg ( X86_REG_AL, data_val, 1, effect );
			break;
		case 2:
			mask = 0xFFFF;
			data_val &= mask;
			state.set_reg ( X86_REG_AX, data_val, 2, effect );
			break;
		case 4:
			mask = 0xFFFFFFFF;
			data_val &= mask;
			state.set_reg ( X86_REG_EAX, data_val, 4, effect );
			break;
		default:
			state.exit_due_to_critical_error = true;
			return;
	}

	std::println ( "IN: 0x{:X} -> Port 0x{:04X}", data_val, port_addr );
}

void outx ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint8_t op_size = 0;
	const char* size_suffix = "";

	switch ( instr.mnemonic ( ) ) {
		case X86_INS_OUTSB:
			op_size = 1;
			size_suffix = "BYTE";
			break;
		case X86_INS_OUTSW:
			op_size = 2;
			size_suffix = "WORD";
			break;
		case X86_INS_OUTSD:
			op_size = 4;
			size_suffix = "DWORD";
			break;
		default:
			effect.push_to_changes ( state, std::format ( "OUTS: Unexpected instruction ID {} for outs_generic handler", instr.mnemonic ( ) ) );
			state.exit_due_to_critical_error = true;
			return;
	}

	bool is_rep = instr.is_rep ( );
	uint16_t port_addr = static_cast< uint16_t >( state.get_reg ( X86_REG_DX, 2 ) ); // Port is in DX
	uint64_t rsi_val = state.get_reg ( X86_REG_RSI, 8 ); // Source address is in RSI (64-bit mode)
	bool df = state.cpu->cpu_flags.flags.DF != 0; // Direction Flag
	int64_t step = df ? -static_cast< int64_t >( op_size ) : static_cast< int64_t >( op_size );

	uint64_t count = 1;
	uint64_t initial_rcx = 0; // For logging REP case

	if ( is_rep ) {
		initial_rcx = state.get_reg ( X86_REG_RCX, 8 );
		count = initial_rcx;

		if ( count == 0 ) { // If RCX is 0, REP has no effect
			if ( state.options.enable_logging ) {
				effect.push_to_changes ( state, std::format ( "REP OUTS{}: RCX is 0, no I/O operation. Port=0x{:04x}",
																 size_suffix, port_addr ) );
			}
			return;
		}
		if ( state.options.enable_logging ) {
			effect.push_to_changes ( state, std::format ( "REP OUTS{}: Count = {} ({:x}h), Port=0x{:04x}, Initial RSI=0x{:016x}",
															 size_suffix, count, count, port_addr, rsi_val ) );
		}
	}
	else {
		if ( state.options.enable_logging ) {
			effect.push_to_changes ( state, std::format ( "OUTS{}: Port=0x{:04x}, RSI=0x{:016x}",
															 size_suffix, port_addr, rsi_val ) );
		}
	}

	uint64_t current_rsi = rsi_val;
	GET_OPERAND_MASK ( operand_mask, op_size );

	for ( uint64_t i = 0; i < count; ++i ) {
		if ( state.exit_due_to_critical_error ) {
			effect.push_to_changes ( state, "OUTS: Exiting due to critical error during REP loop." );
			break;
		}

		uint64_t data_to_send = 0;
		try {
			data_to_send = state.get_memory ( current_rsi, op_size );
		}
		catch ( const GuestExceptionInfo& /* e */ ) {
			state.set_reg ( X86_REG_RSI, current_rsi, 8, effect );
			if ( is_rep ) {
				state.set_reg ( X86_REG_RCX, count - i, 8, effect );
				if ( state.options.enable_logging ) {
					effect.push_to_changes ( state, std::format ( "  REP OUTS{}: Fault at [0x{:016x}]. Updated RSI=0x{:016x}, RCX={}",
																	 size_suffix, current_rsi, current_rsi, count - i ) );
				}
			}
			else {
				if ( state.options.enable_logging ) {
					effect.push_to_changes ( state, std::format ( "  OUTS{}: Fault at [0x{:016x}]. Updated RSI=0x{:016x}",
																	 size_suffix, current_rsi, current_rsi ) );
				}
			}
			throw;
		}

		state.windows->io_ports [ port_addr ] = data_to_send & operand_mask;

		if ( state.options.enable_logging ) {
			effect.push_to_changes ( state, std::format ( "  I/O Write: Port 0x{:04x} <- 0x{:x} (from [0x{:016x}], {} bytes)",
															 port_addr, data_to_send & operand_mask, current_rsi, op_size ) );
		}

		current_rsi += step; // Update RSI for the next iteration or for after a single operation
	}

	state.set_reg ( X86_REG_RSI, current_rsi, 8, effect );

	if ( is_rep && initial_rcx > 0 ) { // Check initial_rcx to ensure RCX is only zeroed if REP actually ran
		state.set_reg ( X86_REG_RCX, 0, 8, effect );
	}

	if ( state.options.enable_logging ) {
		if ( is_rep && initial_rcx > 0 ) {
			effect.push_to_changes ( state, std::format ( "  Final REP OUTS{} state: RSI=0x{:016x}, RCX=0",
															 size_suffix, current_rsi ) );
		}
		else if ( !is_rep ) {
			effect.push_to_changes ( state, std::format ( "  Final OUTS{} state: RSI=0x{:016x}",
															 size_suffix, current_rsi ) );
		}
	}
}

void helpers::bind_arithmetic ( ) {
	BIND ( add );
	BIND ( sub );
	BIND ( inc );
	BIND ( dec );
	BIND ( mul );
	BIND ( imul );
	BIND2 ( div, _div );
	BIND ( idiv );
	BIND ( cdq );
	BIND ( cdqe );
	BIND ( adc );
	BIND ( sbb );
	BIND ( neg );
	BIND ( xadd );

	BIND ( io_in );
	BIND ( io_out );
	BIND ( outx );
}
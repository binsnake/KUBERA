// --- START OF FILE flags.cpp ---

#include "pch.hpp"
#include <cfenv>
void EmulationContext::update_flags_add ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	const auto ua = a & mask;
	const auto ub = b & mask;
	const auto res = ( ua + ub ) & mask;

	int64_t sa = static_cast< int64_t >( a << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	int64_t sb = static_cast< int64_t >( b << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;
	flags.CF = ( res < ua );
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( ua & 0xF ) + ( ub & 0xF ) ) > 0xF;
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.OF = ( ( sa > 0 && sb > 0 && sres < 0 ) || ( sa < 0 && sb < 0 && sres > 0 ) );

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_adc ( uint64_t dst, uint64_t src, uint64_t carry, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	const auto udst = dst & mask;
	const auto usrc = src & mask;
	const auto ucarry = carry & 1;

	const auto temp_res = udst + usrc;
	const auto res = ( temp_res + ucarry ) & mask;

	int64_t sdst = static_cast< int64_t >( udst << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	int64_t ssrc = static_cast< int64_t >( usrc << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	flags.CF = ( temp_res < udst ) || ( ( temp_res + ucarry ) < temp_res ); // Check carry out from dst+src OR from (dst+src)+carry
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( ( udst & 0xF ) + ( usrc & 0xF ) ) > 0xF ) || ( ( ( temp_res & 0xF ) + ucarry ) > 0xF ); // Check carry out of bit 3
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;

	// OF Check: Check sign change when it shouldn't happen
	// Overflow if (dst >= 0 && src >= 0 && res < 0) or (dst < 0 && src < 0 && res >= 0) considering carry
	bool dst_sign = ( sdst >= 0 );
	bool src_sign = ( ssrc >= 0 );
	bool res_sign = ( sres >= 0 );
	flags.OF = ( dst_sign == src_sign ) && ( dst_sign != res_sign );

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_sub ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	const auto ua = a & mask;
	const auto ub = b & mask;
	const auto res = ( ua - ub ) & mask;

	const auto sa = static_cast< int64_t >( ua << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	const auto sb = static_cast< int64_t >( ub << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	const auto sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	flags.CF = ( ua < ub );
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( ( ua ^ ub ^ res ) & 0x10 ) != 0 );
	flags.SF = ( sres < 0 );
	flags.OF = ( ( sa >= 0 && sb < 0 && sres < 0 ) || ( sa < 0 && sb >= 0 && sres >= 0 ) );


	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_shl ( uint64_t val, uint64_t raw_count, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t uval = val & mask;
	uint8_t size_in_bits = op_size * 8;

	uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t effective_count = static_cast< uint8_t >( raw_count & count_limit_mask );

	if ( raw_count == 0 ) { // Per Intel: "If the count is 0, flags are not affected."
		return;
	}

	uint64_t res = uval;
	if ( effective_count > 0 ) {
		if ( effective_count < size_in_bits ) {
			res = ( uval << effective_count ) & mask;
		}
		else {
			res = 0;
		}
	}
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	if ( effective_count == 0 ) {
		flags.CF = 0;
	}
	else if ( effective_count <= size_in_bits ) {
		flags.CF = ( uval >> ( size_in_bits - effective_count ) ) & 1;
	}
	else {
		flags.CF = 0;
	}

	flags.SF = ( res >> ( size_in_bits - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( static_cast< uint8_t >( res & 0xFF ) ) % 2 == 0;
	flags.AF = 0;

	if ( ( raw_count & 0xFF ) == 1 ) {
		flags.OF = ( ( res >> ( size_in_bits - 1 ) ) & 1 ) != flags.CF;
	}
	else {
		flags.OF = 0;
	}

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF && flags.AF == 0 && old_AF != 0 ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_sar ( uint64_t val, uint64_t raw_count, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t uval_masked = val & mask;
	uint8_t size_in_bits = op_size * 8;

	uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t effective_count = static_cast< uint8_t >( raw_count & count_limit_mask );

	if ( raw_count == 0 ) {
		return;
	}

	int64_t sval_extended = helpers::sign_extend ( uval_masked, op_size );

	uint64_t res = uval_masked;
	if ( effective_count > 0 ) {
		if ( effective_count < size_in_bits ) {
			res = static_cast< uint64_t > ( sval_extended >> effective_count ) & mask;
		}
		else {
			if ( ( sval_extended >> ( size_in_bits - 1 ) ) & 1 ) {
				res = mask;
			}
			else {
				res = 0;
			}
		}
	}
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	if ( effective_count == 0 ) {
		flags.CF = 0;
	}
	else if ( effective_count <= size_in_bits ) {
		flags.CF = ( sval_extended >> ( effective_count - 1 ) ) & 1;
	}
	else {
		flags.CF = ( sval_extended >> ( size_in_bits - 1 ) ) & 1;
	}

	flags.OF = 0;
	flags.SF = ( res >> ( size_in_bits - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( static_cast< uint8_t >( res & 0xFF ) ) % 2 == 0;
	flags.AF = 0;

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF && flags.AF == 0 && old_AF != 0 ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_inc ( uint64_t val, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t uval = static_cast< uint64_t >( val ) & mask;
	uint64_t res = ( uval + 1 ) & mask;

	int64_t sval = static_cast< int64_t >( uval << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	// OF is set if result sign is opposite operand sign, specifically for positive -> negative overflow
	flags.OF = ( sval >= 0 && sres < 0 );
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( uval & 0xF ) + 1 ) > 0xF;
	// INC does not affect CF

	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_dec ( uint64_t val, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t uval = static_cast< uint64_t >( val ) & mask;
	uint64_t res = ( uval - 1 ) & mask;

	int64_t sval = static_cast< int64_t >( uval << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	// OF is set if result sign is opposite operand sign, specifically for negative -> positive overflow
	flags.OF = ( sval < 0 && sres >= 0 );
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( uval & 0xF ) < 1 ); // Borrow from bit 4
	// DEC does not affect CF

	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_mul ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	const auto ua = a & mask;
	const auto ub = b & mask;
	uint64_t res_low, res_high;

	uint128_t full_res_128 = uint128_t ( ua ) * uint128_t ( ub );

	// 2. Create a mask for the operand size (works for 1, 2, 4 bytes)
	//    For op_size 8, we need the full 64 bits, so use a specific mask.
	uint128_t mask_128 = 0;
	int shift_amount = op_size * 8;

	if ( op_size == 8 ) {
		mask_128 = 0xFFFFFFFFFFFFFFFFULL; // Mask for 64 bits
	}
	else {
		mask_128 = ( uint128_t ( 1 ) << shift_amount ) - 1; // Mask for op_size*8 bits
	}

	// 3. Extract the lower part using the mask
	res_low = static_cast< uint64_t >( full_res_128 & mask_128 );

	// 4. Extract the higher part by shifting down and then masking
	res_high = static_cast< uint64_t >( ( full_res_128 >> shift_amount ) & mask_128 );
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_OF = flags.OF;
	// For unsigned MUL, CF and OF are set if the upper half of the full result is non-zero
	flags.CF = ( res_high != 0 );
	flags.OF = flags.CF;

	// SF, ZF, PF, AF are undefined after MUL
	flags.SF = 0;
	flags.ZF = 0;
	flags.PF = 0;
	flags.AF = 0;

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	// Log undefined flags being cleared if needed for debugging, though not strictly necessary
	log_flag_change ( effect, "SF", 1, 0 ); // Assume old value could be 1
	log_flag_change ( effect, "ZF", 1, 0 );
	log_flag_change ( effect, "PF", 1, 0 );
	log_flag_change ( effect, "AF", 1, 0 );
}

void EmulationContext::update_flags_div ( uint64_t dividend, uint64_t divisor, uint8_t op_size, InstructionEffect& effect ) {
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_OF = flags.OF, old_SF = flags.SF, old_ZF = flags.ZF, old_AF = flags.AF, old_PF = flags.PF;

	if ( divisor == 0 ) {
		effect.push_to_changes ( "Division by zero occurred (flags undefined)" );
	}
	effect.push_to_changes ( "Flags (CF, OF, SF, ZF, AF, PF) are undefined after DIV/IDIV" );
}

void EmulationContext::update_flags_and ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t res = ( a & b ) & mask;
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_CF = flags.CF, old_OF = flags.OF;
	int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	flags.SF = sres < 0;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;

	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
}

void EmulationContext::update_flags_or ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t res = ( a | b ) & mask;
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_CF = flags.CF, old_OF = flags.OF;
	int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	flags.SF = sres < 0;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;

	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
}

void EmulationContext::update_flags_xor ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t res = ( a ^ b ) & mask;
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_CF = flags.CF, old_OF = flags.OF;
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;
	// AF is undefined
	flags.AF = 0; // Explicitly clear

	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
}

void EmulationContext::update_flags_not ( uint64_t val, uint8_t op_size, InstructionEffect& effect ) {
	// NOT doesnt affect flags, no changes needed
}

void EmulationContext::update_flags_shr ( uint64_t val, uint64_t raw_count, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t uval = val & mask;
	uint8_t size_in_bits = op_size * 8;

	uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t effective_count = static_cast< uint8_t >( raw_count & count_limit_mask );

	if ( raw_count == 0 ) {
		return;
	}

	uint64_t res = uval;
	if ( effective_count > 0 ) {
		if ( effective_count < size_in_bits ) {
			res = uval >> effective_count;
		}
		else {
			res = 0;
		}
	}
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_CF = flags.CF, old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_OF = flags.OF, old_AF = flags.AF;

	if ( effective_count == 0 ) {
		flags.CF = 0;
	}
	else if ( effective_count <= size_in_bits ) {
		flags.CF = ( uval >> ( effective_count - 1 ) ) & 1;
	}
	else {
		flags.CF = 0;
	}

	flags.SF = ( res >> ( size_in_bits - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( static_cast< uint8_t >( res & 0xFF ) ) % 2 == 0;
	flags.AF = 0;

	if ( ( raw_count & 0xFF ) == 1 ) {
		flags.OF = ( uval >> ( size_in_bits - 1 ) ) & 1;
	}
	else {
		flags.OF = 0;
	}

	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
	if ( old_AF != flags.AF && flags.AF == 0 && old_AF != 0 ) log_flag_change ( effect, "AF", old_AF, flags.AF );
}

void EmulationContext::update_flags_test ( uint64_t a, uint64_t b, uint8_t op_size, InstructionEffect& effect ) {
	GET_OPERAND_MASK ( mask, op_size );
	uint64_t res = ( a & b ) & mask;
	auto& flags = cpu->cpu_flags.flags;
	uint64_t old_PF = flags.PF, old_ZF = flags.ZF, old_SF = flags.SF, old_CF = flags.CF, old_OF = flags.OF;
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;
	// AF is undefined
	flags.AF = 0; // Explicitly clear

	if ( old_PF != flags.PF ) log_flag_change ( effect, "PF", old_PF, flags.PF );
	if ( old_ZF != flags.ZF ) log_flag_change ( effect, "ZF", old_ZF, flags.ZF );
	if ( old_SF != flags.SF ) log_flag_change ( effect, "SF", old_SF, flags.SF );
	if ( old_CF != flags.CF ) log_flag_change ( effect, "CF", old_CF, flags.CF );
	if ( old_OF != flags.OF ) log_flag_change ( effect, "OF", old_OF, flags.OF );
}

void EmulationContext::log_mxcsr_flag_change ( InstructionEffect& effect, const char* flag_name, uint32_t old_val, uint32_t new_val ) {
	if ( !options.enable_logging || old_val == new_val ) return;
	effect.push_to_changes ( std::format ( "MXCSR.{} : {} -> {}", flag_name, old_val, new_val ) );
}

template<std::floating_point T>
void EmulationContext::update_mxcsr_arithmetic ( T a, T b, T result, InstructionEffect& effect ) {
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_flags = *(uint32_t*)&mxcsr;
	mxcsr.IE = 0; mxcsr.DE = 0; mxcsr.ZE = 0; mxcsr.OE = 0; mxcsr.UE = 0; mxcsr.PE = 0; // Clear status flags

	bool is_a_denormal = std::fpclassify ( a ) == FP_SUBNORMAL;
	bool is_b_denormal = std::fpclassify ( b ) == FP_SUBNORMAL;
	bool is_result_denormal = std::fpclassify ( result ) == FP_SUBNORMAL;
	bool is_a_nan = std::isnan ( a );
	bool is_b_nan = std::isnan ( b );
	bool is_result_nan = std::isnan ( result );
	bool is_a_inf = std::isinf ( a );
	bool is_b_inf = std::isinf ( b );
	bool is_result_inf = std::isinf ( result );
	bool is_a_zero = ( a == 0.0 ); // Use 0.0 for generic float/double
	bool is_b_zero = ( b == 0.0 );
	bool is_result_zero = ( result == 0.0 );

	// --- Determine Exceptions ---
	// Invalid Operation (IE) - Needs refinement for specific ops (e.g., 0*inf, inf/inf, 0/0, sqrt(-ve))
	if ( is_a_nan || is_b_nan ) { // Basic NaN check
		// TODO: Check for SNaN specifically if possible
		mxcsr.IE = 1;
	}
	// Check for division-specific IE cases
	if constexpr ( std::is_same_v<decltype( a / b ), T> ) { // Check applies if division is the context
		if ( is_a_zero && is_b_zero ) mxcsr.IE = 1; // 0/0
		if ( is_a_inf && is_b_inf ) mxcsr.IE = 1; // inf/inf
	}
	// Check for multiplication-specific IE case
	if constexpr ( std::is_same_v<decltype( a * b ), T> ) {
		if ( ( is_a_zero && is_b_inf ) || ( is_a_inf && is_b_zero ) ) mxcsr.IE = 1; // 0 * inf
	}


	// Denormal Operand (DE) - if DAZ=0
	if ( !mxcsr.DAZ && ( is_a_denormal || is_b_denormal ) ) {
		mxcsr.DE = 1;
	}

	// Divide by Zero (ZE) - Specific to division
	if constexpr ( std::is_same_v<decltype( a / b ), T> ) {
		if ( is_b_zero && !is_a_zero && !is_a_nan ) { // x/0 where x is finite non-zero
			mxcsr.ZE = 1;
			if ( mxcsr.IE && is_a_inf ) { } // Let inf/0 be IE if IE already set
			else mxcsr.IE = 0; // ZE overrides 0/0 IE if it wasn't inf/0 etc.
		}
	}

	// Overflow (OE) - Result is Inf, but operands were finite
	if ( is_result_inf && !is_a_inf && !is_b_inf ) {
		mxcsr.OE = 1;
	}

	// Underflow (UE) - Result is tiny (zero/denormal) AND inexact
	// Inexact check is tricky without higher precision. Use fenv for approximation.
	std::feclearexcept ( FE_ALL_EXCEPT );
	volatile T dummy_result = a + b; // Re-perform op to potentially set fenv flags (example for add)
	// Replace above with the actual operation type context if possible, or pass operation type
	bool inexact = ( std::fetestexcept ( FE_INEXACT ) != 0 );
	bool underflow_occurred = ( std::fetestexcept ( FE_UNDERFLOW ) != 0 ); // Use fenv underflow

	if ( underflow_occurred ) { // Rely on fenv for underflow detection
		mxcsr.UE = 1;
		// If UE is set, PE (inexact) must also be set according to SSE rules
		inexact = true;
	}

	// Precision (PE) / Inexact
	if ( inexact ) {
		mxcsr.PE = 1;
	}
	// Handle FZ (Flush-to-Zero): If UE=1 and UM=1 and FZ=1, result becomes signed zero, PE=1.
	if ( mxcsr.UE && mxcsr.UM && mxcsr.FZ ) {
		// The handler should have already set the result register to zero if FZ active.
		mxcsr.PE = 1; // Ensure PE is set if FZ triggered by underflow
	}
	// Handle DAZ (Denormals-Are-Zero): If DAZ=1, denormal inputs are treated as zero.
	// This should ideally be handled *before* the operation in the main handler.

	if ( mxcsr.IE != ( ( old_flags >> 0 ) & 1 ) ) log_mxcsr_flag_change ( effect, "IE", ( old_flags >> 0 ) & 1, mxcsr.IE );
	if ( mxcsr.DE != ( ( old_flags >> 1 ) & 1 ) ) log_mxcsr_flag_change ( effect, "DE", ( old_flags >> 1 ) & 1, mxcsr.DE );
	if ( mxcsr.ZE != ( ( old_flags >> 2 ) & 1 ) ) log_mxcsr_flag_change ( effect, "ZE", ( old_flags >> 2 ) & 1, mxcsr.ZE );
	if ( mxcsr.OE != ( ( old_flags >> 3 ) & 1 ) ) log_mxcsr_flag_change ( effect, "OE", ( old_flags >> 3 ) & 1, mxcsr.OE );
	if ( mxcsr.UE != ( ( old_flags >> 4 ) & 1 ) ) log_mxcsr_flag_change ( effect, "UE", ( old_flags >> 4 ) & 1, mxcsr.UE );
	if ( mxcsr.PE != ( ( old_flags >> 5 ) & 1 ) ) log_mxcsr_flag_change ( effect, "PE", ( old_flags >> 5 ) & 1, mxcsr.PE );
}
// Explicit instantiations (optional but can improve compile times/visibility)
template void EmulationContext::update_mxcsr_arithmetic<float> ( float, float, float, InstructionEffect& );
template void EmulationContext::update_mxcsr_arithmetic<double> ( double, double, double, InstructionEffect& );


// --- Templated Compare Updater ---
template<std::floating_point T>
void EmulationContext::update_flags_for_compare ( T a, T b, bool is_unordered_quiet, InstructionEffect& effect ) {
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_rflags = get_eflags ( );
	uint32_t old_mxcsr_flags = *(uint32_t*)&mxcsr;

	bool is_nan_a = std::isnan ( a );
	bool is_nan_b = std::isnan ( b );
	bool unordered = is_nan_a || is_nan_b;

	// Placeholder: Check for SNaN if needed
	bool is_sNaN_a = false;
	bool is_sNaN_b = false;
	bool signal_ie = ( is_sNaN_a || is_sNaN_b );

	// Clear flags
	auto& flags = cpu->cpu_flags.flags;
	flags.ZF = 0; flags.PF = 0; flags.CF = 0; flags.OF = 0; flags.SF = 0; flags.AF = 0;
	mxcsr.IE = 0;

	if ( unordered ) {
		flags.ZF = 1;
		flags.PF = 1;
		flags.CF = 1;
		// UCOMISS/UCOMISD (is_unordered_quiet = true): IE=0 for QNaN operands. IE=1 if SNaN operand.
		// COMISS/COMISD   (is_unordered_quiet = false): IE=1 for any NaN operand (QNaN or SNaN).
		if ( signal_ie || !is_unordered_quiet ) {
			mxcsr.IE = 1;
		}
	}
	else { // Ordered compare
		flags.ZF = ( a == b );
		flags.PF = 0;
		flags.CF = ( a < b );
		// mxcsr.IE remains 0 for ordered
	}

	if ( flags.ZF != ( ( old_rflags >> 6 ) & 1 ) ) log_flag_change ( effect, "ZF", ( old_rflags >> 6 ) & 1, flags.ZF );
	if ( flags.PF != ( ( old_rflags >> 2 ) & 1 ) ) log_flag_change ( effect, "PF", ( old_rflags >> 2 ) & 1, flags.PF );
	if ( flags.CF != ( ( old_rflags >> 0 ) & 1 ) ) log_flag_change ( effect, "CF", ( old_rflags >> 0 ) & 1, flags.CF );
	if ( ( ( old_rflags >> 11 ) & 1 ) != 0 ) log_flag_change ( effect, "OF", ( old_rflags >> 11 ) & 1, 0 );
	if ( ( ( old_rflags >> 7 ) & 1 ) != 0 ) log_flag_change ( effect, "SF", ( old_rflags >> 7 ) & 1, 0 );
	if ( ( ( old_rflags >> 4 ) & 1 ) != 0 ) log_flag_change ( effect, "AF", ( old_rflags >> 4 ) & 1, 0 );
	if ( mxcsr.IE != ( ( old_mxcsr_flags >> 0 ) & 1 ) ) log_mxcsr_flag_change ( effect, "IE", ( old_mxcsr_flags >> 0 ) & 1, mxcsr.IE );
}
// Explicit instantiations
template void EmulationContext::update_flags_for_compare<float> ( float, float, bool, InstructionEffect& );
template void EmulationContext::update_flags_for_compare<double> ( double, double, bool, InstructionEffect& );

// --- Conversion Updaters ---
template<std::floating_point F, typename I>
void EmulationContext::update_mxcsr_conversion_float_to_int ( F src, I dst, bool is_truncate, InstructionEffect& effect ) {
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_flags = *(uint32_t*)&mxcsr;
	mxcsr.IE = 0; mxcsr.PE = 0; // Clear relevant status flags

	std::feclearexcept ( FE_ALL_EXCEPT );
	// Re-perform conversion concept to check flags (actual result 'dst' is passed in)
	if constexpr ( std::is_same_v<I, int32_t> ) {
		volatile int32_t temp_dst = is_truncate ? static_cast< int32_t >( src ) : static_cast< int32_t >( std::lrintf ( src ) ); // Or lrint
	}
	else { // int64_t
		volatile int64_t temp_dst = is_truncate ? static_cast< int64_t >( src ) : std::lrint ( src ); // Or lrintf
	}
	int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_INEXACT );

	if ( fenv_excepts & FE_INVALID ) {
		mxcsr.IE = 1; // Set Invalid Operation (NaN, Inf, Overflow)
	}
	// Precision (Inexact) flag is set if the result was rounded (or truncated and different)
	// Note: FE_INEXACT might be set by fenv even for valid conversions if rounding occurred.
	// A more precise check compares the converted int back to the original float.
	if ( static_cast< F >( dst ) != src ) {
		mxcsr.PE = 1;
	}
	// Ensure PE is set if IE is set
	if ( mxcsr.IE ) {
		mxcsr.PE = 1;
	}


	// Log changes
	if ( mxcsr.IE != ( ( old_flags >> 0 ) & 1 ) ) log_mxcsr_flag_change ( effect, "IE", ( old_flags >> 0 ) & 1, mxcsr.IE );
	if ( mxcsr.PE != ( ( old_flags >> 5 ) & 1 ) ) log_mxcsr_flag_change ( effect, "PE", ( old_flags >> 5 ) & 1, mxcsr.PE );
}
// Explicit Instantiations
template void EmulationContext::update_mxcsr_conversion_float_to_int<float, int32_t> ( float, int32_t, bool, InstructionEffect& );
template void EmulationContext::update_mxcsr_conversion_float_to_int<float, int64_t> ( float, int64_t, bool, InstructionEffect& );
template void EmulationContext::update_mxcsr_conversion_float_to_int<double, int32_t> ( double, int32_t, bool, InstructionEffect& );
template void EmulationContext::update_mxcsr_conversion_float_to_int<double, int64_t> ( double, int64_t, bool, InstructionEffect& );


template<typename I, std::floating_point F>
void EmulationContext::update_mxcsr_conversion_int_to_float ( I src, F dst, InstructionEffect& effect ) {
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_flags = *(uint32_t*)&mxcsr;
	mxcsr.PE = 0; // Clear PE (only relevant flag)

	// Check for inexact conversion
	// Compare the float result back to the original integer
	if ( static_cast< I >( dst ) != src ) {
		mxcsr.PE = 1;
	}

	// Log change
	if ( mxcsr.PE != ( ( old_flags >> 5 ) & 1 ) ) log_mxcsr_flag_change ( effect, "PE", ( old_flags >> 5 ) & 1, mxcsr.PE );
}
// Explicit Instantiations
template void EmulationContext::update_mxcsr_conversion_int_to_float<int32_t, float> ( int32_t, float, InstructionEffect& );
template void EmulationContext::update_mxcsr_conversion_int_to_float<int64_t, float> ( int64_t, float, InstructionEffect& );
template void EmulationContext::update_mxcsr_conversion_int_to_float<int32_t, double> ( int32_t, double, InstructionEffect& );
template void EmulationContext::update_mxcsr_conversion_int_to_float<int64_t, double> ( int64_t, double, InstructionEffect& );


void EmulationContext::update_mxcsr_conversion ( float src, double dst, InstructionEffect& effect ) {
	// float -> double is always exact, no flags set typically (unless SNaN source -> IE)
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_flags = *(uint32_t*)&mxcsr;
	mxcsr.IE = 0; // Clear relevant flags
	// TODO: Check if src is SNaN -> set IE=1
	if ( mxcsr.IE != ( ( old_flags >> 0 ) & 1 ) ) log_mxcsr_flag_change ( effect, "IE", ( old_flags >> 0 ) & 1, mxcsr.IE );
}

void EmulationContext::update_mxcsr_conversion ( double src, float dst, InstructionEffect& effect ) {
	// double -> float can be inexact, overflow, underflow
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_flags = *( uint32_t* ) &mxcsr;
	mxcsr.IE = 0; mxcsr.OE = 0; mxcsr.UE = 0; mxcsr.PE = 0; // Clear relevant flags

	std::feclearexcept ( FE_ALL_EXCEPT );
	volatile float temp_dst = static_cast< float >( src ); // Re-perform conversion
	int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT );

	if ( fenv_excepts & FE_INVALID ) mxcsr.IE = 1;   // NaN/Inf source?
	if ( fenv_excepts & FE_OVERFLOW ) mxcsr.OE = 1;
	if ( fenv_excepts & FE_UNDERFLOW ) mxcsr.UE = 1;
	if ( fenv_excepts & FE_INEXACT ) mxcsr.PE = 1;

	// Ensure PE is set if OE or UE occurred
	if ( mxcsr.OE || mxcsr.UE ) mxcsr.PE = 1;
	// Handle FZ (Flush-to-Zero): If UE=1 and UM=1 and FZ=1, result becomes signed zero, PE=1.
	if ( mxcsr.UE && mxcsr.UM && mxcsr.FZ ) {
		// Handler should have set result register to zero
		mxcsr.PE = 1;
	}

	// Log changes
	if ( mxcsr.IE != ( ( old_flags >> 0 ) & 1 ) ) log_mxcsr_flag_change ( effect, "IE", ( old_flags >> 0 ) & 1, mxcsr.IE );
	if ( mxcsr.OE != ( ( old_flags >> 3 ) & 1 ) ) log_mxcsr_flag_change ( effect, "OE", ( old_flags >> 3 ) & 1, mxcsr.OE );
	if ( mxcsr.UE != ( ( old_flags >> 4 ) & 1 ) ) log_mxcsr_flag_change ( effect, "UE", ( old_flags >> 4 ) & 1, mxcsr.UE );
	if ( mxcsr.PE != ( ( old_flags >> 5 ) & 1 ) ) log_mxcsr_flag_change ( effect, "PE", ( old_flags >> 5 ) & 1, mxcsr.PE );
}


// --- SQRT Updater ---
template<std::floating_point T>
void EmulationContext::update_mxcsr_sqrt ( T src, T result, InstructionEffect& effect ) {
	auto& mxcsr = cpu->cpu_flags.mxcsr;
	uint32_t old_flags = *(uint32_t*)&mxcsr;
	mxcsr.IE = 0; mxcsr.DE = 0; mxcsr.PE = 0; // Clear relevant flags

	bool is_src_denormal = std::fpclassify ( src ) == FP_SUBNORMAL;
	bool is_src_nan = std::isnan ( src );
	// TODO: Check for SNaN

	if ( is_src_nan ) {
		mxcsr.IE = 1;
	}
	else if ( src < 0.0 ) { // Domain error (sqrt of negative)
		mxcsr.IE = 1;
	}

	if ( !mxcsr.DAZ && is_src_denormal ) { // Denormal source operand
		mxcsr.DE = 1;
	}

	// Check for inexact result (only possible for denormal sqrt?)
	// float exact_res_sq = result * result;
	// if (exact_res_sq != src) mxcsr.PE = 1;

	// Log changes
	if ( mxcsr.IE != ( ( old_flags >> 0 ) & 1 ) ) log_mxcsr_flag_change ( effect, "IE", ( old_flags >> 0 ) & 1, mxcsr.IE );
	if ( mxcsr.DE != ( ( old_flags >> 1 ) & 1 ) ) log_mxcsr_flag_change ( effect, "DE", ( old_flags >> 1 ) & 1, mxcsr.DE );
	if ( mxcsr.PE != ( ( old_flags >> 5 ) & 1 ) ) log_mxcsr_flag_change ( effect, "PE", ( old_flags >> 5 ) & 1, mxcsr.PE );
}
// Explicit Instantiations
template void EmulationContext::update_mxcsr_sqrt<float> ( float, float, InstructionEffect& );
template void EmulationContext::update_mxcsr_sqrt<double> ( double, double, InstructionEffect& );
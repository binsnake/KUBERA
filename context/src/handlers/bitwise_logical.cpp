#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;

enum class RotateSide : bool {
	RIGHT = 0,
	LEFT = 1,
};

enum class RotateCarry : bool {
	WITHOUT = 0,
	WITH = 1,
};

template <RotateSide side, RotateCarry rot_carry, typename Func>
void rotate ( const iced::Instruction& instr, KUBERA& context, Func rotate_op ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_count = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t val = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t current_val = val & mask;
	const uint8_t size_in_bits = static_cast< uint8_t >( op_size * 8 );
	const uint8_t count_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	uint8_t rot = src_count & count_mask;
	if constexpr ( side == RotateSide::LEFT ) {
		rot = rot % size_in_bits;
	}
	else if constexpr ( rot_carry == RotateCarry::WITH ) {
		rot = ( op_size == 1 ) ? rot % 9 : ( op_size == 2 ) ? rot % 17 : rot % size_in_bits;
	}

	uint64_t final_result = current_val;
	uint64_t final_cf = context.get_flags ( ).CF;

	if ( rot != 0 ) {
		auto [result, cf] = rotate_op ( current_val, rot, size_in_bits, final_cf );
		final_result = result & mask;
		final_cf = cf;
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, final_result, context );

	auto& flags = context.get_flags ( );
	if ( rot != 0 ) {
		flags.CF = final_cf;
		if ( rot == 1 ) {
			flags.OF = rotate_op ( final_result, rot, size_in_bits, final_cf ).second;
		}
	}
}

/// ROL-Rotate Left
/// Rotates the destination operand left by the number of bits specified in the second operand, updating flags.
void handlers::rol ( const iced::Instruction& instr, KUBERA& context ) {
	rotate<RotateSide::LEFT, RotateCarry::WITHOUT> ( instr, context, [ ] ( uint64_t val, uint8_t rot, uint8_t size_in_bits, uint64_t cf )
	{
		uint64_t temp_val = val;
		uint64_t temp_cf = 0;
		for ( uint8_t i = 0; i < rot; ++i ) {
			temp_cf = ( temp_val >> ( size_in_bits - 1 ) ) & 1;
			temp_val = ( ( temp_val << 1 ) | temp_cf );
		}
		return std::make_pair ( temp_val, temp_val & 1 );
	} );
}

/// ROR-Rotate Right
/// Rotates the destination operand right by the number of bits specified in the second operand, updating flags.
void handlers::ror ( const iced::Instruction& instr, KUBERA& context ) {
	rotate<RotateSide::RIGHT, RotateCarry::WITHOUT> ( instr, context, [ ] ( uint64_t val, uint8_t rot, uint8_t size_in_bits, uint64_t cf )
	{
		uint64_t temp_val = val;
		uint64_t temp_cf = 0;
		for ( uint8_t i = 0; i < rot; ++i ) {
			temp_cf = temp_val & 1;
			temp_val = ( temp_val >> 1 ) | ( temp_cf << ( size_in_bits - 1 ) );
		}
		uint64_t msb = ( temp_val >> ( size_in_bits - 1 ) ) & 1;
		uint64_t msb_minus_1 = ( size_in_bits > 1 ) ? ( temp_val >> ( size_in_bits - 2 ) ) & 1 : temp_cf;
		return std::make_pair ( temp_val, msb ^ msb_minus_1 );
	} );
}

/// RCL-Rotate Left Through Carry
/// Rotates the destination operand left through the carry flag by the number of bits specified in the second operand, updating flags.
void handlers::rcl ( const iced::Instruction& instr, KUBERA& context ) {
	rotate<RotateSide::LEFT, RotateCarry::WITH> ( instr, context, [ ] ( uint64_t val, uint8_t rot, uint8_t size_in_bits, uint64_t cf )
	{
		uint64_t temp_val = val;
		uint64_t temp_cf = cf;
		for ( uint8_t i = 0; i < rot; ++i ) {
			uint64_t msb = ( temp_val >> ( size_in_bits - 1 ) ) & 1;
			temp_val = ( ( temp_val << 1 ) | temp_cf );
			temp_cf = msb;
		}
		return std::make_pair ( temp_val, temp_val >> ( size_in_bits - 1 ) );
	} );
}

/// RCR-Rotate Right Through Carry
/// Rotates the destination operand right through the carry flag by the number of bits specified in the second operand, updating flags.
void handlers::rcr ( const iced::Instruction& instr, KUBERA& context ) {
	rotate<RotateSide::RIGHT, RotateCarry::WITH> ( instr, context, [ ] ( uint64_t val, uint8_t rot, uint8_t size_in_bits, uint64_t cf )
	{
		uint64_t temp_val = val;
		uint64_t temp_cf = cf;
		for ( uint8_t i = 0; i < rot; ++i ) {
			uint64_t lsb = temp_val & 1;
			temp_val = ( temp_val >> 1 ) | ( temp_cf << ( size_in_bits - 1 ) );
			temp_cf = lsb;
		}
		uint64_t msb = ( temp_val >> ( size_in_bits - 1 ) ) & 1;
		uint64_t msb_minus_1 = ( size_in_bits > 1 ) ? ( temp_val >> ( size_in_bits - 2 ) ) & 1 : temp_cf;
		return std::make_pair ( temp_val, msb ^ msb_minus_1 );
	} );
}

/// AND-Logical AND
/// Performs a bitwise AND of the first and second operands, stores the result in the first operand, and updates flags.
void handlers::and_ ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t res = ( a & b ) & mask;
	const int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );

	auto& flags = context.get_flags ( );
	flags.SF = sres < 0;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;
	flags.AF = 0;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// OR-Logical OR
/// Performs a bitwise OR of the first and second operands, stores the result in the first operand, and updates flags.
void handlers::or_ ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t res = ( a | b ) & mask;
	const int64_t sres = static_cast< int64_t >( res << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );

	auto& flags = context.get_flags ( );
	flags.SF = sres < 0;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;
	flags.AF = 0;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// XOR-Logical Exclusive OR
/// Performs a bitwise XOR of the first and second operands, stores the result in the first operand, and updates flags.
void handlers::xor_ ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t res = ( a ^ b ) & mask;

	auto& flags = context.get_flags ( );
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.CF = 0;
	flags.OF = 0;
	flags.AF = 0;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// NOT-Logical NOT
/// Performs a bitwise NOT on the destination operand and stores the result without affecting flags.
void handlers::not_ ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t res = ( ~a ) & mask;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// SHL/SAL-Shift Left
/// Shifts the destination operand left by the number of bits specified in the second operand, stores the result, and updates flags (SHL and SAL are identical).
void handlers::shl ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t val_operand = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t count_operand = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t uval = val_operand & mask;
	const uint8_t size_in_bits = static_cast< uint8_t >( op_size * 8 );
	const uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	const uint8_t count_raw = count_operand & 0xFF;
	const uint8_t effective_count = count_raw & count_limit_mask;

	uint64_t res = uval;
	if ( effective_count > 0 && effective_count < size_in_bits ) {
		res = ( uval << effective_count ) & mask;
	}
	else if ( effective_count >= size_in_bits ) {
		res = 0;
	}

	auto& flags = context.get_flags ( );
	if ( count_raw != 0 ) {
		flags.CF = ( effective_count <= size_in_bits ) ? ( uval >> ( size_in_bits - effective_count ) ) & 1 : 0;
		flags.SF = ( res >> ( size_in_bits - 1 ) ) & 1;
		flags.ZF = ( res == 0 );
		flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
		flags.AF = 0;
		flags.OF = ( count_raw == 1 ) ? ( ( uval >> ( size_in_bits - 1 ) ) & 1 ) ^ flags.CF : 0;
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// SHL/SAL-Shift Left
/// Shifts the destination operand left by the number of bits specified in the second operand, stores the result, and updates flags (SHL and SAL are identical).
void handlers::sal ( const iced::Instruction& instr, KUBERA& context ) {
	shl ( instr, context );
}

/// SHR-Shift Right
/// Shifts the destination operand right by the number of bits specified in the second operand, stores the result, and updates flags.
void handlers::shr ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t val_operand = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t count_operand = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t uval = val_operand & mask;
	const uint8_t size_in_bits = static_cast< uint8_t >( op_size * 8 );
	const uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	const uint8_t count_raw = count_operand & 0xFF;
	const uint8_t effective_count = count_raw & count_limit_mask;

	uint64_t res = uval;
	if ( effective_count > 0 && effective_count < size_in_bits ) {
		res = uval >> effective_count;
	}
	else if ( effective_count >= size_in_bits ) {
		res = 0;
	}

	auto& flags = context.get_flags ( );
	if ( count_raw != 0 ) {
		flags.CF = ( effective_count <= size_in_bits ) ? ( uval >> ( effective_count - 1 ) ) & 1 : 0;
		flags.SF = ( res >> ( size_in_bits - 1 ) ) & 1;
		flags.ZF = ( res == 0 );
		flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
		flags.AF = 0;
		flags.OF = ( count_raw == 1 ) ? ( uval >> ( size_in_bits - 1 ) ) & 1 : 0;
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

template <typename Func>
void double_shift ( const iced::Instruction& instr, KUBERA& context, Func shift_op ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t dest = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t src = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t count = helpers::get_operand_value<uint64_t> ( instr, 2u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t value0 = dest & mask;
	const uint64_t value1 = src & mask;
	const uint8_t size_in_bits = static_cast< uint8_t >( op_size * 8 );
	const uint8_t count_raw = count & 0xFF;
	const uint8_t counter = ( op_size == 8 ) ? ( count % 64 ) : ( count % size_in_bits );

	uint64_t final_result = value0;
	uint64_t final_cf = context.get_flags ( ).CF;

	if ( counter != 0 && counter <= size_in_bits ) {
		auto [result, cf] = shift_op ( value0, value1, counter, size_in_bits );
		final_result = result & mask;
		final_cf = cf;
	}

	auto& flags = context.get_flags ( );
	if ( count_raw != 0 ) {
		flags.CF = final_cf;
		flags.SF = ( final_result >> ( size_in_bits - 1 ) ) & 1;
		flags.ZF = ( final_result == 0 );
		flags.PF = std::popcount ( final_result & 0xFF ) % 2 == 0;
		flags.AF = 0;
		if ( count_raw == 1 ) {
			flags.OF = shift_op ( value0, value0, 1, size_in_bits ).second;
		}
		else {
			flags.OF = 0;
		}
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, final_result, context );
}

/// SHLD-Double Precision Shift Left
/// Shifts the destination operand left by the number of bits specified, filling low bits with the source operand, and updates flags.
void handlers::shld ( const iced::Instruction& instr, KUBERA& context ) {
	double_shift ( instr, context, [ ] ( uint64_t value0, uint64_t value1, uint8_t counter, uint8_t size_in_bits )
	{
		uint64_t temp_result = value0;
		uint64_t final_cf = ( temp_result >> ( size_in_bits - counter ) ) & 1;
		temp_result = ( temp_result << counter ) | ( value1 >> ( size_in_bits - counter ) );
		uint64_t original_msb = ( value0 >> ( size_in_bits - 1 ) ) & 1;
		uint64_t result_msb = ( temp_result >> ( size_in_bits - 1 ) ) & 1;
		return std::make_pair ( temp_result, original_msb ^ result_msb );
	} );
}

/// SHRD-Double Precision Shift Right
/// Shifts the destination operand right by the number of bits specified, filling high bits with the source operand, and updates flags.
void handlers::shrd ( const iced::Instruction& instr, KUBERA& context ) {
	double_shift ( instr, context, [ ] ( uint64_t value0, uint64_t value1, uint8_t counter, uint8_t size_in_bits )
	{
		uint64_t temp_result = value0;
		uint64_t final_cf = ( temp_result >> ( counter - 1 ) ) & 1;
		temp_result = ( temp_result >> counter ) | ( value1 << ( size_in_bits - counter ) );
		uint64_t original_msb = ( value0 >> ( size_in_bits - 1 ) ) & 1;
		uint64_t result_msb = ( temp_result >> ( size_in_bits - 1 ) ) & 1;
		return std::make_pair ( temp_result, original_msb ^ result_msb );
	} );
}

/// SAR-Shift Arithmetic Right
/// Shifts the destination operand right arithmetically by the number of bits specified, preserving the sign bit, stores the result, and updates flags.
void handlers::sar ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t val_operand = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t count_operand = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t uval = val_operand & mask;
	const int64_t signed_val = static_cast< int64_t >( uval << ( 64 - op_size * 8 ) ) >> ( 64 - op_size * 8 );
	const uint8_t size_in_bits = static_cast< uint8_t >( op_size * 8 );
	const uint8_t count_limit_mask = ( op_size == 8 ) ? 0x3F : 0x1F;
	const uint8_t count_raw = count_operand & 0xFF;
	const uint8_t effective_count = count_raw & count_limit_mask;

	uint64_t res = uval;
	if ( effective_count > 0 ) {
		if ( effective_count < size_in_bits ) {
			res = static_cast< uint64_t > ( signed_val >> effective_count ) & mask;
		}
		else {
			res = ( signed_val < 0 ) ? mask : 0;
		}
	}

	auto& flags = context.get_flags ( );
	if ( count_raw != 0 ) {
		flags.CF = ( effective_count <= size_in_bits ) ? ( uval >> ( effective_count - 1 ) ) & 1 : 0;
		flags.SF = ( res >> ( size_in_bits - 1 ) ) & 1;
		flags.ZF = ( res == 0 );
		flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
		flags.AF = 0;
		flags.OF = ( count_raw == 1 ) ? 0 : 0;
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}
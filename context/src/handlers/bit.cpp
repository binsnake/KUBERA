#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;

/// BZHI-Bit Zero High
/// Zeros the high bits of the source operand starting from the index in the second operand, stores the result in the destination, and updates flags.
void handlers::bzhi ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t index_reg_val = helpers::get_operand_value<uint64_t> ( instr, 2u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t src_val = src & mask;
	const uint8_t index_pos = index_reg_val & 0xFF;
	const size_t size_in_bits = instr.op0_bit_width ( );

	uint64_t temp_mask = 0;
	if ( index_pos != 0 && index_pos < size_in_bits ) {
		temp_mask = ( 1ULL << index_pos ) - 1;
	}
	else if ( index_pos >= size_in_bits ) {
		temp_mask = mask;
	}

	const uint64_t res = src_val & temp_mask;
	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );

	auto& flags = context.get_flags ( );
	flags.CF = ( index_pos >= size_in_bits );
	flags.ZF = ( res == 0 );
	flags.OF = 0;
	flags.SF = 0;
	flags.AF = 0;
	flags.PF = 0;
}

/// ANDN-Logical AND NOT
/// Performs a bitwise AND of the inverted first source operand with the second source operand, stores the result in the destination, and updates flags.
void handlers::andn ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src1 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t src2 = helpers::get_operand_value<uint64_t> ( instr, 2u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t res = ( ~src1 & src2 ) & mask;

	auto& flags = context.get_flags ( );
	flags.ZF = ( res == 0 );
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.OF = 0;
	flags.CF = 0;
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = 0;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// BEXTR-Bit Field Extract
/// Extracts a bit field from the first source operand based on the start and length in the second source operand, stores the result in the destination, and updates flags.
void handlers::bextr ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t control = helpers::get_operand_value<uint64_t> ( instr, 2u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t src_val = src & mask;
	const uint8_t start = control & 0xFF;
	const uint8_t len = ( control >> 8 ) & 0xFF;
	const size_t bits_in_operand = instr.op0_bit_width ( );

	uint64_t res = 0;
	if ( len != 0 ) {
		uint64_t result_mask = ( len >= bits_in_operand ) ? mask : ( ( 1ULL << len ) - 1 );
		if ( start < bits_in_operand ) {
			res = ( src_val >> start ) & result_mask;
		}
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );

	auto& flags = context.get_flags ( );
	flags.ZF = ( res == 0 );
	flags.CF = 0;
	flags.OF = 0;
	flags.SF = 0;
	flags.PF = 0;
	flags.AF = 0;
}

/// POPCNT-Population Count
/// Counts the number of 1 bits in the source operand, stores the count in the destination, and updates flags.
void handlers::popcnt ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t val = src & mask;
	const uint64_t result = __popcnt64 ( val );

	helpers::set_operand_value<uint64_t> ( instr, 0u, result, context );

	auto& flags = context.get_flags ( );
	flags.ZF = ( result == 0 );
	flags.CF = 0;
	flags.OF = 0;
	flags.SF = 0;
	flags.PF = 0;
	flags.AF = 0;
}

/// BSWAP-Byte Swap
/// Reverses the byte order of the destination operand and stores the result.
void handlers::bswap ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	uint64_t val = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	if ( op_size == 4 ) val = _byteswap_ulong ( static_cast< uint32_t >( val ) );
	else if ( op_size == 8 ) val = _byteswap_uint64 ( val );

	helpers::set_operand_value<uint64_t> ( instr, 0u, val, context );
}

/// BT-Bit Test
/// Tests the bit at the index specified in the second operand in the first operand and sets the CF flag to the bit value.
void handlers::bt ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src1 = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t src2 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t val = src1 & mask;
	const uint64_t bit_idx = src2 & ( op_size * 8 - 1 );

	auto& flags = context.get_flags ( );
	flags.CF = ( val >> bit_idx ) & 1;
}

template <typename Func>
void bit_test_and_modify ( const iced::Instruction& instr, KUBERA& context, Func modify_op ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src1 = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t src2 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t val = src1 & mask;
	const uint64_t bit_idx = src2 & ( op_size * 8 - 1 );
	const uint64_t original_bit = ( val >> bit_idx ) & 1;
	const uint64_t result = modify_op ( val, bit_idx );

	auto& flags = context.get_flags ( );
	flags.CF = original_bit;

	helpers::set_operand_value<uint64_t> ( instr, 0u, result, context );
}

/// BTS-Bit Test and Set
/// Tests the bit at the index specified in the second operand in the first operand, sets the CF flag to the bit value, and sets the bit to 1 in the first operand.
void handlers::bts ( const iced::Instruction& instr, KUBERA& context ) {
	bit_test_and_modify ( instr, context, [ ] ( uint64_t val, uint64_t bit_idx )
	{
		return val | ( 1ULL << bit_idx );
	} );
}

/// BTR-Bit Test and Reset
/// Tests the bit at the index specified in the second operand in the first operand, sets the CF flag to the bit value, and clears the bit to 0 in the first operand.
void handlers::btr ( const iced::Instruction& instr, KUBERA& context ) {
	bit_test_and_modify ( instr, context, [ ] ( uint64_t val, uint64_t bit_idx )
	{
		return val & ~( 1ULL << bit_idx );
	} );
}

/// BTC-Bit Test and Complement
/// Tests the bit at the index specified in the second operand in the first operand, sets the CF flag to the bit value, and complements the bit in the first operand.
void handlers::btc ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src1 = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t src2 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t val = src1 & mask;
	const uint64_t bit_idx = src2 & ( op_size * 8 - 1 );
	const uint64_t original_bit = ( val >> bit_idx ) & 1;
	const uint64_t result = val ^ ( 1ULL << bit_idx );

	auto& flags = context.get_flags ( );
	flags.CF = original_bit;

	helpers::set_operand_value<uint64_t> ( instr, 0u, result, context );
}

/// BSR-Bit Scan Reverse
/// Scans the source operand for the most significant set bit, stores its index in the destination, and sets ZF if the source is zero.
void handlers::bsr ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t val = src_val & mask;

	auto& flags = context.get_flags ( );
	if ( val == 0 ) {
		flags.ZF = 1;
	}
	else {
		flags.ZF = 0;
		unsigned long index = 0;
		if ( op_size == 8 ) _BitScanReverse64 ( &index, val );
		else if ( op_size == 4 ) _BitScanReverse ( &index, static_cast< uint32_t >( val ) );
		else if ( op_size == 2 ) _BitScanReverse ( &index, static_cast< uint16_t >( val ) );

		helpers::set_operand_value<uint64_t> ( instr, 0u, static_cast< uint64_t >( index ), context );
	}
}

/// TZCNT-Count Trailing Zeros
/// Counts the number of trailing zero bits in the source operand, stores the count in the destination, and updates CF and ZF flags.
void handlers::tzcnt ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t val = src_val & mask;
	const uint8_t size_in_bits = static_cast<uint8_t>(op_size * 8);

	uint64_t result_count = ( val == 0 ) ? size_in_bits : std::countr_zero ( val );

	auto& flags = context.get_flags ( );
	flags.CF = ( val == 0 );
	flags.ZF = ( result_count == 0 );

	helpers::set_operand_value<uint64_t> ( instr, 0u, result_count, context );
}

/// BSF-Bit Scan Forward
/// Scans the source operand for the least significant set bit, stores its index in the destination, and sets ZF if the source is zero.
void handlers::bsf ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t val = src_val & mask;

	auto& flags = context.get_flags ( );
	if ( val == 0 ) {
		flags.ZF = 1; // Source is zero, destination unchanged
	}
	else {
		flags.ZF = 0;
		unsigned long index = 0;
		if ( op_size == 8 ) _BitScanForward64 ( &index, val );
		else if ( op_size == 4 ) _BitScanForward ( &index, static_cast< uint32_t >( val ) );
		else if ( op_size == 2 ) _BitScanForward ( &index, static_cast< uint16_t >( val ) );
		helpers::set_operand_value<uint64_t> ( instr, 0u, static_cast< uint64_t >( index ), context );
	}
}
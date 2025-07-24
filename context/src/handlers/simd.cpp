#include <context/emulator.hpp>
#include <bit>
#include <cfenv>
#include "helpers.hpp"

using namespace kubera;

/// VPXOR - Vector Packed XOR
/// Performs a bitwise XOR of two source XMM/YMM/ZMM registers or a register and memory, storing the result in the destination register, without affecting flags.
void handlers::vpxor ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	if ( op_size != 16 && op_size != 32 && op_size != 64 ) {
		// !TODO(exception)
		return;
	}

	const uint512_t src1_val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	const uint512_t src2_val = helpers::get_operand_value<uint512_t> ( instr, 2u, context );
	const uint512_t result = src1_val ^ src2_val;

	helpers::set_operand_value<uint512_t> ( instr, 0u, result, context );
}

/// VPCMPEQW - Vector Packed Compare Equal Word
/// Compares 16-bit words in two source XMM/YMM/ZMM registers or a register and memory, setting each word in the destination to 0xFFFF if equal or 0 if not equal, without affecting flags.
void handlers::vpcmpeqw ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	if ( op_size != 16 && op_size != 32 && op_size != 64 ) {
		// !TODO(exception)
		return;
	}

	const int num_elements = static_cast< int >( op_size / sizeof ( uint16_t ) );
	const uint512_t src1_val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	const uint512_t src2_val = helpers::get_operand_value<uint512_t> ( instr, 2u, context );
	uint512_t result = 0;

	for ( int i = 0; i < num_elements; ++i ) {
		const uint16_t element1 = static_cast< uint16_t > ( ( src1_val >> ( i * 16 ) ) & 0xFFFF );
		const uint16_t element2 = static_cast< uint16_t > ( ( src2_val >> ( i * 16 ) ) & 0xFFFF );
		if ( element1 == element2 ) {
			result |= ( uint512_t ( 0xFFFF ) << ( i * 16 ) );
		}
	}

	helpers::set_operand_value<uint512_t> ( instr, 0u, result, context );
}

/// VPMOVMSKB - Vector Move Mask Byte
/// Extracts the most significant bit of each byte in the source XMM/YMM/ZMM register, storing the resulting mask in a general-purpose register, without affecting flags.
void handlers::vpmovmskb ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t src_size = instr.op1_size ( );
	const size_t dst_size = instr.op0_size ( );
	if ( ( src_size != 16 && src_size != 32 && src_size != 64 ) ||
			( dst_size != 4 && dst_size != 8 ) ||
			instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op1_kind ( ) != OpKindSimple::Register ) {
		// !TODO(exception)
		return;
	}

	const uint512_t src_val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	const int num_bytes = static_cast< int >( src_size );
	uint64_t result = 0;

	for ( int i = 0; i < num_bytes; ++i ) {
		const uint8_t byte_val = static_cast< uint8_t > ( ( src_val >> ( i * 8 ) ) & 0xFF );
		if ( byte_val >> 7 ) {
			result |= ( 1ULL << i );
		}
	}

	helpers::set_operand_value<uint64_t> ( instr, 0u, result, context );
}

/// VZEROUPPER - Zero Upper Bits of YMM Registers
/// Zeroes the upper 128 bits of all YMM registers (YMM0-YMM15), preserving the lower 128 bits, without affecting flags.
void handlers::vzeroupper ( const iced::Instruction& instr, KUBERA& context ) {
	for ( int i = 0; i < 16; ++i ) {
		const Register ymm_reg = static_cast< Register > ( static_cast< int > ( Register::YMM0 ) + i );
		const uint256_t ymm_val = context.get_ymm_raw ( ymm_reg );
		const uint128_t lower_val = static_cast< uint128_t > ( ymm_val & uint256_t ( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ) );
		context.set_ymm_raw ( ymm_reg, lower_val );
	}
}

/// VINSERTF128 - Vector Insert Float 128
/// Inserts a 128-bit value from an XMM register or memory into the lower or upper 128 bits of a YMM register, based on an immediate, without affecting flags.
void handlers::vinsertf128 ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t dst_size = instr.op0_size ( );
	if ( dst_size != 32 ||
			instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op1_kind ( ) != OpKindSimple::Register ||
			( instr.op2_kind ( ) != OpKindSimple::Register && instr.op2_kind ( ) != OpKindSimple::Memory ) ||
			instr.op3_kind ( ) != OpKindSimple::Immediate ) {
		// !TODO(exception)
		return;
	}

	const uint256_t src1_val = helpers::get_operand_value<uint256_t> ( instr, 1u, context );
	const uint128_t src2_val = helpers::get_operand_value<uint128_t> ( instr, 2u, context );
	const uint8_t imm = static_cast< uint8_t >( instr.immediate ( ) );
	uint256_t result;

	if ( ( imm & 0x01 ) == 0 ) { // Insert into lower 128 bits
		result = ( src1_val & uint256_t ( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ) ) | static_cast< uint256_t >( src2_val );
	}
	else { // Insert into upper 128 bits
		result = ( static_cast< uint256_t >( src2_val ) << 128 ) | ( src1_val & uint256_t ( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ) );
	}

	helpers::set_operand_value<uint256_t> ( instr, 0u, result, context );
}

/// VMOVUPS - Vector Move Unaligned Packed Single-Precision
/// Moves unaligned 128-bit (XMM), 256-bit (YMM), or 512-bit (ZMM) data between registers or memory, without affecting flags.
void handlers::vmovups ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_kind ( ) == OpKindSimple::Memory ? instr.op1_size ( ) : instr.op0_size ( );
	if ( op_size != 16 && op_size != 32 && op_size != 64 ) {
		// !TODO(exception)
		return;
	}

	const uint512_t val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	helpers::set_operand_value<uint512_t> ( instr, 0u, val, context );
}

/// VMOVAPS - Vector Move Aligned Packed Single-Precision
/// Moves aligned 128-bit (XMM), 256-bit (YMM), or 512-bit (ZMM) data between registers or memory, requiring alignment, without affecting flags.
void handlers::vmovaps ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_kind ( ) == OpKindSimple::Memory ? instr.op1_size ( ) : instr.op0_size ( );
	if ( op_size != 16 && op_size != 32 && op_size != 64 ) {
		// !TODO(exception)
		return;
	}

	if ( instr.op1_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		if ( addr % op_size != 0 ) {
			// !TODO(exception)
			return;
		}
	}
	if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		if ( addr % op_size != 0 ) {
			// !TODO(exception)
			return;
		}
	}

	const uint512_t val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	helpers::set_operand_value<uint512_t> ( instr, 0u, val, context );
}

/// VMOVDQU - Vector Move Unaligned Double Quadword
/// Moves unaligned 128-bit (XMM), 256-bit (YMM), or 512-bit (ZMM) data between registers or memory, without affecting flags.
void handlers::vmovdqu ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_kind ( ) == OpKindSimple::Memory ? instr.op1_size ( ) : instr.op0_size ( );
	if ( op_size != 16 && op_size != 32 && op_size != 64 ) {
		// !TODO(exception)
		return;
	}

	const uint512_t val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	helpers::set_operand_value<uint512_t> ( instr, 0u, val, context );
}

/// MOVDQU - Move Unaligned Double Quadword
/// Moves unaligned 128-bit (XMM) data between registers or memory, without affecting flags.
void handlers::movdqu ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_kind ( ) == OpKindSimple::Memory ? instr.op1_size ( ) : instr.op0_size ( );
	if ( op_size != 16 ) {
		// !TODO(exception)
		return;
	}

	const uint512_t val = helpers::get_operand_value<uint512_t> ( instr, 1u, context );
	helpers::set_operand_value<uint512_t> ( instr, 0u, val, context );
}

/// PUNPCKLQDQ - Unpack Low Quadwords
/// Interleaves the low 64-bit quadwords of the source and destination XMM registers, storing the result in the destination, without affecting flags.
void handlers::punpcklqdq ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op1_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 16 || instr.op1_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			instr.op1_reg ( ) < Register::XMM0 || instr.op1_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const uint128_t v1 = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t v2 = context.get_xmm_raw ( instr.op1_reg ( ) );
	const uint64_t lo1 = static_cast< uint64_t >( v1 );
	const uint64_t lo2 = static_cast< uint64_t >( v2 );
	const uint128_t result = ( static_cast< uint128_t >( lo2 ) << 64 ) | lo1;

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// MOVLHPS - Move Low to High Packed Single-Precision
/// Moves the low 64 bits of the source XMM register to the high 64 bits of the destination XMM register, preserving the low 64 bits, without affecting flags.
void handlers::movlhps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op1_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 16 || instr.op1_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			instr.op1_reg ( ) < Register::XMM0 || instr.op1_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
	const uint64_t dst_low = static_cast< uint64_t >( dst_val );
	const uint64_t src_low = static_cast< uint64_t >( src_val );
	const uint128_t result = ( static_cast< uint128_t >( src_low ) << 64 ) | (dst_low & 0xFFFFFFFFFFFFFFFF);

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// PSRLDQ - Shift Right Logical Double Quadword
/// Shifts the destination XMM register right by the specified number of bytes (immediate), filling with zeros, without affecting flags.
void handlers::psrldq ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op1_kind ( ) != OpKindSimple::Immediate ||
			instr.op0_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const uint8_t shift_amount = static_cast< uint8_t >( instr.immediate ( ) );
	const uint128_t val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t result = ( shift_amount > 15 ) ? 0 : ( val >> ( shift_amount * 8 ) );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// MOVHLPS - Move High to Low Packed Single-Precision
/// Moves the high 64 bits of the source XMM register to the low 64 bits of the destination XMM register, preserving the high 64 bits of the destination, without affecting flags.
void handlers::movhlps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op1_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 16 || instr.op1_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			instr.op1_reg ( ) < Register::XMM0 || instr.op1_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
	const uint128_t result = ( dst_val & ( uint128_t ( 0xFFFFFFFFFFFFFFFF ) << 64 ) ) | static_cast< uint128_t >( src_val >> 64 );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// UNPCKLPS - Unpack Low Packed Single-Precision
/// Interleaves the low 32-bit single-precision floats from the source and destination XMM registers or memory, storing the result in the destination XMM register, without affecting flags.
void handlers::unpcklps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			( instr.op1_kind ( ) != OpKindSimple::Register && instr.op1_kind ( ) != OpKindSimple::Memory ) ||
			instr.op0_size ( ) != 16 || instr.op1_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = helpers::get_operand_value<uint128_t> ( instr, 1u, context );
	const uint32_t dst0 = static_cast< uint32_t >( dst_val );
	const uint32_t dst1 = static_cast< uint32_t >( dst_val >> 32 );
	const uint32_t src0 = static_cast< uint32_t >( src_val );
	const uint32_t src1 = static_cast< uint32_t >( src_val >> 32 );
	const uint128_t result = static_cast< uint128_t >( dst0 ) |
		( static_cast< uint128_t >( src0 ) << 32 ) |
		( static_cast< uint128_t >( dst1 ) << 64 ) |
		( static_cast< uint128_t >( src1 ) << 96 );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// MINSS - Minimum Scalar Single-Precision
/// Stores the minimum of two single-precision floats from the destination XMM register (bits 31:0) and source (XMM or memory) in the destination, modifying MXCSR flag IE for signaling NaNs.
void handlers::minss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float dst_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );
	float result;

	if ( std::isnan ( dst_val ) || std::isnan ( src_val ) ) {
		mxcsr.IE = 1;
		result = src_val;
		// !TODO(exception)
	}
	else if ( dst_val == 0.0f && src_val == 0.0f ) {
		mxcsr.IE = 0;
		result = std::signbit ( dst_val ) ? dst_val : src_val;
	}
	else {
		mxcsr.IE = 0;
		result = ( dst_val < src_val ) ? dst_val : src_val;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// MAXSS - Maximum Scalar Single-Precision
/// Stores the maximum of two single-precision floats from the destination XMM register (bits 31:0) and source (XMM or memory) in the destination, modifying MXCSR flag IE for signaling NaNs.
void handlers::maxss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float dst_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );
	float result;

	if ( std::isnan ( dst_val ) || std::isnan ( src_val ) ) {
		mxcsr.IE = 1;
		result = src_val;
		// !TODO(exception)
	}
	else if ( dst_val == 0.0f && src_val == 0.0f ) {
		mxcsr.IE = 0;
		result = std::signbit ( src_val ) ? dst_val : src_val;
	}
	else {
		mxcsr.IE = 0;
		result = ( dst_val > src_val ) ? dst_val : src_val;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// ANDPS - Bitwise AND Packed Single-Precision
/// Performs a bitwise AND on 128-bit XMM registers or a register and memory, storing the result in the destination XMM register, without affecting flags.
void handlers::andps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			( instr.op1_kind ( ) != OpKindSimple::Register && instr.op1_kind ( ) != OpKindSimple::Memory ) ) {
		// !TODO(exception)
		return;
	}

	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = helpers::get_operand_value<uint128_t> ( instr, 1u, context );
	const uint128_t result = dst_val & src_val;

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// ORPS - Bitwise OR Packed Single-Precision
/// Performs a bitwise OR on 128-bit XMM registers or a register and memory, storing the result in the destination XMM register, without affecting flags.
void handlers::orps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			( instr.op1_kind ( ) != OpKindSimple::Register && instr.op1_kind ( ) != OpKindSimple::Memory ) ) {
		// !TODO(exception)
		return;
	}

	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = helpers::get_operand_value<uint128_t> ( instr, 1u, context );
	const uint128_t result = dst_val | src_val;

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// XORPS - Bitwise XOR Packed Single-Precision
/// Performs a bitwise XOR on 128-bit XMM registers or a register and memory, storing the result in the destination XMM register, zeroing if source equals destination, without affecting flags.
void handlers::xorps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 16 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			( instr.op1_kind ( ) != OpKindSimple::Register && instr.op1_kind ( ) != OpKindSimple::Memory ) ) {
		// !TODO(exception)
		return;
	}

	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = helpers::get_operand_value<uint128_t> ( instr, 1u, context );
	const uint128_t result = ( instr.op1_kind ( ) == OpKindSimple::Register &&
													 instr.op1_reg ( ) == instr.op0_reg ( ) ) ? 0 : ( dst_val ^ src_val );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// COMISD - Compare Scalar Double-Precision Ordered
/// Compares two double-precision floats from the first XMM register (bits 63:0) and source (XMM or memory), setting EFLAGS (ZF, PF, CF based on comparison; OF, SF, AF cleared) and MXCSR IE for signaling NaNs.
void handlers::comisd ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 8 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const double src1 = context.get_xmm_double ( instr.op0_reg ( ) );
	const double src2 = helpers::get_operand_value<double> ( instr, 1u, context );
	auto& flags = context.get_flags ( );
	auto& mxcsr = context.get_mxcsr ( );

	flags.ZF = 0;
	flags.PF = 0;
	flags.CF = 0;
	flags.OF = 0;
	flags.SF = 0;
	flags.AF = 0;

	if ( std::isnan ( src1 ) || std::isnan ( src2 ) ) {
		mxcsr.IE = 1;
		flags.ZF = 1;
		flags.PF = 1;
		flags.CF = 1;
		// !TODO(exception)
		return;
	}

	if ( src1 == src2 ) {
		flags.ZF = 1;
	}
	else if ( src1 < src2 ) {
		flags.CF = 1;
	}
}

/// MULSD - Multiply Scalar Double-Precision
/// Multiplies a double-precision float from the destination XMM register (bits 63:0) with a source (XMM or memory), storing the result in the destination, modifying MXCSR flags (IE, DE, OE, UE, PE).
void handlers::mulsd ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 8 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const double dst_val = context.get_xmm_double ( instr.op0_reg ( ) );
	const double src_val = helpers::get_operand_value<double> ( instr, 1u, context );
	const double result = dst_val * src_val;
	auto& mxcsr = context.get_mxcsr ( );

	mxcsr.IE = ( std::isnan ( dst_val ) || std::isnan ( src_val ) ||
							( std::fpclassify ( dst_val ) == FP_ZERO && std::isinf ( src_val ) ) ||
							( std::isinf ( dst_val ) && std::fpclassify ( src_val ) == FP_ZERO ) ) ? 1 : 0;
	mxcsr.DE = ( std::fpclassify ( dst_val ) == FP_SUBNORMAL || std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = ( std::isinf ( result ) && !std::isinf ( dst_val ) && !std::isinf ( src_val ) ) ? 1 : 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( dst_val ) != FP_SUBNORMAL &&
							std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = ( !std::isinf ( result ) && !std::isnan ( result ) && std::fpclassify ( result ) != FP_ZERO ) ? 1 : 0;

	if ( mxcsr.IE || mxcsr.OE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_double ( instr.op0_reg ( ), result );
}

/// MOVSS - Move Scalar Single-Precision
/// Moves a single-precision float between XMM registers, from memory to XMM, or from XMM to memory, without affecting flags.
void handlers::movss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( ( instr.op0_kind ( ) != OpKindSimple::Register && instr.op0_kind ( ) != OpKindSimple::Memory ) ||
			instr.op0_size ( ) != 4 ||
			( instr.op0_kind ( ) == OpKindSimple::Register &&
			 ( instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) ) ||
			( instr.op1_kind ( ) != OpKindSimple::Register && instr.op1_kind ( ) != OpKindSimple::Memory ) ||
			( instr.op1_kind ( ) == OpKindSimple::Register &&
			 ( instr.op1_reg ( ) < Register::XMM0 || instr.op1_reg ( ) > Register::XMM31 ) ) ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );

	if ( instr.op0_kind ( ) == OpKindSimple::Register ) {
		context.set_xmm_float ( instr.op0_reg ( ), src_val );
	}
	else if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
		if ( context.is_within_stack_bounds ( addr, 4 ) ) {
			context.set_stack<uint32_t> ( addr, std::bit_cast< uint32_t >( src_val ) );
		}
		else {
			context.set_memory<uint32_t> ( addr, std::bit_cast< uint32_t >( src_val ) );
		}
	}
}

/// ROUNDSS - Round Scalar Single-Precision
/// Rounds a single-precision float from the source (XMM or memory) to a single-precision float using the specified rounding mode, storing in the destination XMM register (bits 31:0), modifying MXCSR flags (IE, DE, OE, UE, PE).
void handlers::roundss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			instr.op2_kind ( ) != OpKindSimple::Immediate ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	const uint8_t imm = static_cast< uint8_t >( instr.immediate ( ) );
	auto& mxcsr = context.get_mxcsr ( );

	int round_mode;
	switch ( imm & 0x07 ) {
		case 0: round_mode = FE_TONEAREST; break; // Round to nearest, ties to even
		case 1: round_mode = FE_DOWNWARD; break; // Round down
		case 2: round_mode = FE_UPWARD; break; // Round up
		case 3: round_mode = FE_TOWARDZERO; break; // Round toward zero
		default: round_mode = mxcsr.RC; break; // Use MXCSR rounding control
	}

	std::fesetround ( round_mode );
	std::feclearexcept ( FE_ALL_EXCEPT );
	const float result = std::nearbyintf ( src_val );
	const int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT );

	mxcsr.IE = ( fenv_excepts & FE_INVALID || std::isnan ( src_val ) ) ? 1 : 0;
	mxcsr.DE = ( std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = ( fenv_excepts & FE_OVERFLOW ) ? 1 : 0;
	mxcsr.UE = ( fenv_excepts & FE_UNDERFLOW ) ? 1 : 0;
	mxcsr.PE = ( fenv_excepts & FE_INEXACT ) ? 1 : 0;

	if ( mxcsr.IE || mxcsr.OE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// RCPSS - Reciprocal Scalar Single-Precision
/// Computes an approximate reciprocal of a single-precision float from the source (XMM or memory), storing in the destination XMM register (bits 31:0), modifying MXCSR flags (IE, DE, PE).
void handlers::rcpss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	if ( src_val == 0.0f || std::isnan ( src_val ) || std::isinf ( src_val ) ) {
		mxcsr.IE = 1;
		// !TODO(exception)
		return;
	}

	const float result = 1.0f / src_val;
	mxcsr.IE = 0;
	mxcsr.DE = ( std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = 1; // RCPSS is always approximate

	if ( mxcsr.IE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// RSQRTSS - Reciprocal Square Root Scalar Single-Precision
/// Computes an approximate reciprocal square root of a single-precision float from the source (XMM or memory), storing in the destination XMM register (bits 31:0), modifying MXCSR flags (IE, DE, PE).
void handlers::rsqrtss ( const iced::Instruction& instr, KUBERA& context ) {
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	if ( src_val < 0.0f || std::isnan ( src_val ) ) {
		mxcsr.IE = 1;
		// !TODO(exception)
		return;
	}

	const float result = src_val == 0.0f ? std::numeric_limits<float>::infinity ( ) : 1.0f / std::sqrt ( src_val );
	mxcsr.IE = 0;
	mxcsr.DE = ( std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = 1; // RSQRTSS is always approximate

	if ( mxcsr.IE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// PINSRB - Insert Byte
/// Inserts a byte from a 32-bit general-purpose register or memory into a specified byte position in the destination XMM register, selected by an immediate, without affecting flags.
void handlers::pinsrb ( const iced::Instruction& instr, KUBERA& context ) {
	const uint8_t imm = static_cast< uint8_t >( instr.immediate ( ) );
	if ( imm > 15 ) {
		// !TODO(exception)
		return;
	}

	const uint32_t src_val = helpers::get_operand_value<uint32_t> ( instr, 1u, context );
	const uint8_t byte_val = static_cast< uint8_t >( src_val );
	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t mask = ~( uint128_t ( 0xFF ) << ( imm * 8 ) );
	const uint128_t result = ( dst_val & mask ) | ( static_cast< uint128_t >( byte_val ) << ( imm * 8 ) );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// PINSRD - Insert Doubleword
/// Inserts a 32-bit doubleword from a 32-bit general-purpose register or memory into a specified doubleword position in the destination XMM register, selected by an immediate, without affecting flags.
void handlers::pinsrd ( const iced::Instruction& instr, KUBERA& context ) {
	const uint8_t imm = static_cast< uint8_t >( instr.immediate ( ) );
	if ( imm > 3 ) {
		// !TODO(exception)
		return;
	}

	const uint32_t src_val = helpers::get_operand_value<uint32_t> ( instr, 1u, context );
	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t mask = ~( uint128_t ( 0xFFFFFFFF ) << ( imm * 32 ) );
	const uint128_t result = ( dst_val & mask ) | ( static_cast< uint128_t >( src_val ) << ( imm * 32 ) );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// PINSRQ - Insert Quadword
/// Inserts a 64-bit quadword from a 64-bit general-purpose register or memory into a specified quadword position in the destination XMM register, selected by an immediate, without affecting flags.
void handlers::pinsrq ( const iced::Instruction& instr, KUBERA& context ) {
	const uint8_t imm = static_cast< uint8_t >( instr.immediate ( ) );
	if ( imm > 1 ) {
		// !TODO(exception)
		return;
	}

	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t mask = ~( uint128_t ( 0xFFFFFFFFFFFFFFFF ) << ( imm * 64 ) );
	const uint128_t result = ( dst_val & mask ) | ( static_cast< uint128_t >( src_val ) << ( imm * 64 ) );

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

// Helper function for packed addition
template<typename T>
static void padd ( const iced::Instruction& instr, KUBERA& context, size_t elem_size ) {
	const uint128_t dst_val = context.get_xmm_raw ( instr.op0_reg ( ) );
	const uint128_t src_val = helpers::get_operand_value<uint128_t> ( instr, 1u, context );
	const int num_elements = static_cast<int>(16 / elem_size);
	uint128_t result = 0;

	for ( int i = 0; i < num_elements; ++i ) {
		const T dst_elem = static_cast< T > ( ( dst_val >> ( i * elem_size * 8 ) ) & ( ( 1ULL << ( elem_size * 8 ) ) - 1 ) );
		const T src_elem = static_cast< T > ( ( src_val >> ( i * elem_size * 8 ) ) & ( ( 1ULL << ( elem_size * 8 ) ) - 1 ) );
		const T sum = dst_elem + src_elem;
		result |= static_cast< uint128_t > ( sum ) << ( i * elem_size * 8 );
	}

	context.set_xmm_raw ( instr.op0_reg ( ), result );
}

/// PADDB - Packed Add Bytes
/// Adds 16 packed 8-bit integers from the source (XMM or memory) to the destination XMM register, storing the result in the destination, without affecting flags.
void handlers::paddb ( const iced::Instruction& instr, KUBERA& context ) {
	padd<uint8_t> ( instr, context, 1 );
}

/// PADDW - Packed Add Words
/// Adds 8 packed 16-bit integers from the source (XMM or memory) to the destination XMM register, storing the result in the destination, without affecting flags.
void handlers::paddw ( const iced::Instruction& instr, KUBERA& context ) {
	padd<uint16_t> ( instr, context, 2 );
}

/// PADDD - Packed Add Doublewords
/// Adds 4 packed 32-bit integers from the source (XMM or memory) to the destination XMM register, storing the result in the destination, without affecting flags.
void handlers::paddd ( const iced::Instruction& instr, KUBERA& context ) {
	padd<uint32_t> ( instr, context, 4 );
}

/// PADDQ - Packed Add Quadwords
/// Adds 2 packed 64-bit integers from the source (XMM or memory) to the destination XMM register, storing the result in the destination, without affecting flags.
void handlers::paddq ( const iced::Instruction& instr, KUBERA& context ) {
	padd<uint64_t> ( instr, context, 8 );
}
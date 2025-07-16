#include <context/emulator.hpp>
#include <bit>
#include <numeric>
#include <cfenv>
#include "helpers.hpp"

using namespace kubera;

/// ADDSS - Add Scalar Single-Precision
/// Adds a single-precision float from the source (XMM or memory) to the destination XMM register (bits 31:0), storing the result in the destination, modifying MXCSR flags (IE, DE, ZE, OE, UE, PE).
void handlers::addss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float dst_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	const float result = dst_val + src_val;
	auto& mxcsr = context.get_mxcsr ( );

	mxcsr.IE = ( std::isnan ( dst_val ) || std::isnan ( src_val ) || std::isinf ( dst_val ) || std::isinf ( src_val ) ) ? 1 : 0;
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

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// SUBSS - Subtract Scalar Single-Precision
/// Subtracts a single-precision float from the source (XMM or memory) from the destination XMM register (bits 31:0), storing the result in the destination, modifying MXCSR flags (IE, DE, OE, UE, PE).
void handlers::subss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float dst_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	const float result = dst_val - src_val;
	auto& mxcsr = context.get_mxcsr ( );

	mxcsr.IE = ( std::isnan ( dst_val ) || std::isnan ( src_val ) || std::isinf ( dst_val ) || std::isinf ( src_val ) ) ? 1 : 0;
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

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// MULSS - Multiply Scalar Single-Precision
/// Multiplies a single-precision float from the source (XMM or memory) with the destination XMM register (bits 31:0), storing the result in the destination, modifying MXCSR flags (IE, DE, OE, UE, PE).
void handlers::mulss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float dst_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	const float result = dst_val * src_val;
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

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// DIVSS - Divide Scalar Single-Precision
/// Divides the destination XMM register (bits 31:0) by a single-precision float from the source (XMM or memory), storing the result in the destination, modifying MXCSR flags (IE, DE, ZE, OE, UE, PE).
void handlers::divss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float dst_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	const float result = dst_val / src_val;
	auto& mxcsr = context.get_mxcsr ( );

	mxcsr.IE = ( std::isnan ( dst_val ) || std::isnan ( src_val ) || std::isinf ( dst_val ) || std::isinf ( src_val ) ) ? 1 : 0;
	mxcsr.DE = ( std::fpclassify ( dst_val ) == FP_SUBNORMAL || std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = ( src_val == 0 ) ? 1 : 0;
	mxcsr.OE = ( std::isinf ( result ) && !std::isinf ( dst_val ) && !std::isinf ( src_val ) ) ? 1 : 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( dst_val ) != FP_SUBNORMAL &&
							std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = ( !std::isinf ( result ) && !std::isnan ( result ) && std::fpclassify ( result ) != FP_ZERO ) ? 1 : 0;

	if ( mxcsr.IE || mxcsr.ZE || mxcsr.OE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// SQRTSS - Square Root Scalar Single-Precision
/// Computes the square root of a single-precision float from the source (XMM or memory), storing the result in the destination XMM register (bits 31:0), modifying MXCSR flags (IE, DE, PE).
void handlers::sqrtss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	if ( std::signbit ( src_val ) || std::isnan ( src_val ) ) {
		mxcsr.IE = 1;
		// !TODO(exception)
		return;
	}

	const float result = std::sqrt ( src_val );
	mxcsr.IE = 0;
	mxcsr.DE = ( std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = ( !std::isinf ( result ) && !std::isnan ( result ) && std::fpclassify ( result ) != FP_ZERO ) ? 1 : 0;

	if ( mxcsr.IE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// SQRTSD - Square Root Scalar Double-Precision
/// Computes the square root of a double-precision float from the source (XMM or memory), storing the result in the destination XMM register (bits 63:0), modifying MXCSR flags (IE, DE, PE).
void handlers::sqrtsd ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 8 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const double src_val = helpers::get_operand_value<double> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	if ( std::signbit ( src_val ) || std::isnan ( src_val ) ) {
		mxcsr.IE = 1;
		// !TODO(exception)
		return;
	}

	const double result = std::sqrt ( src_val );
	mxcsr.IE = 0;
	mxcsr.DE = ( std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = ( !std::isinf ( result ) && !std::isnan ( result ) && std::fpclassify ( result ) != FP_ZERO ) ? 1 : 0;

	if ( mxcsr.IE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_double ( instr.op0_reg ( ), result );
}

/// COMISS - Compare Scalar Single-Precision Ordered
/// Compares two single-precision floats, setting EFLAGS (ZF, PF, CF based on comparison; OF, SF, AF cleared), signaling an invalid operation for signaling NaNs.
void handlers::comiss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float src1 = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src2 = helpers::get_operand_value<float> ( instr, 1u, context );
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

/// UCOMISS - Compare Scalar Single-Precision Unordered
/// Compares two single-precision floats, setting EFLAGS (ZF, PF, CF based on comparison; OF, SF, AF cleared), without signaling for NaNs.
void handlers::ucomiss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float src1 = context.get_xmm_float ( instr.op0_reg ( ) );
	const float src2 = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& flags = context.get_flags ( );

	flags.ZF = 0;
	flags.PF = 0;
	flags.CF = 0;
	flags.OF = 0;
	flags.SF = 0;
	flags.AF = 0;

	if ( std::isnan ( src1 ) || std::isnan ( src2 ) ) {
		flags.ZF = 1;
		flags.PF = 1;
		flags.CF = 1;
	}
	else if ( src1 == src2 ) {
		flags.ZF = 1;
	}
	else if ( src1 < src2 ) {
		flags.CF = 1;
	}
}

/// CMPSS - Compare Scalar Single-Precision
/// Compares two single-precision floats using a predicate (immediate), storing 0xFFFFFFFF or 0 in the destination XMM register (bits 31:0), modifying MXCSR IE for signaling NaNs.
void handlers::cmpss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			instr.op2_kind ( ) != OpKindSimple::Immediate ) {
		// !TODO(exception)
		return;
	}

	const float op1_val = context.get_xmm_float ( instr.op0_reg ( ) );
	const float op2_val = helpers::get_operand_value<float> ( instr, 1u, context );
	const uint8_t predicate = static_cast< uint8_t >( instr.immediate ( ) ) & 0x07;
	auto& mxcsr = context.get_mxcsr ( );

	bool result = false;
	if ( std::isnan ( op1_val ) || std::isnan ( op2_val ) ) {
		mxcsr.IE = 1;
		switch ( predicate ) {
			case 3: result = true; break; // UNORDERED
			case 4: case 5: case 6: result = true; break; // NEQ, NLT, NLE
			case 7: result = false; break; // ORDERED
			default: result = false; break; // EQ, LT, LE
		}
	}
	else {
		switch ( predicate ) {
			case 0: result = ( op1_val == op2_val ); break; // EQ
			case 1: result = ( op1_val < op2_val ); break; // LT
			case 2: result = ( op1_val <= op2_val ); break; // LE
			case 3: result = false; break; // UNORDERED
			case 4: result = ( op1_val != op2_val ); break; // NEQ
			case 5: result = !( op1_val < op2_val ); break; // NLT
			case 6: result = !( op1_val <= op2_val ); break; // NLE
			case 7: result = true; break; // ORDERED
		}
	}

	if ( mxcsr.IE ) {
		// !TODO(exception)
		return;
	}

	const uint32_t mask = result ? 0xFFFFFFFF : 0x00000000;
	context.set_xmm_float ( instr.op0_reg ( ), std::bit_cast< float >( mask ) );
}

/// CVTSS2SI - Convert Scalar Single-Precision to Signed Integer
/// Converts a single-precision float to a 32/64-bit signed integer with rounding, storing in a general-purpose register, modifying MXCSR flags (IE, PE).
void handlers::cvtss2si ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			( instr.op0_size ( ) != 4 && instr.op0_size ( ) != 8 ) ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );
	const int64_t indefinite_int = ( instr.op0_size ( ) == 8 ) ? INT64_MIN : INT32_MIN;
	int64_t result;

	std::fesetround ( mxcsr.RC );
	std::feclearexcept ( FE_ALL_EXCEPT );
	if ( instr.op0_size ( ) == 4 ) {
		result = static_cast< int64_t >( std::lrintf ( src_val ) );
	}
	else {
		result = std::lrint ( src_val );
	}
	const int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_INEXACT );

	if ( fenv_excepts & FE_INVALID || std::isnan ( src_val ) || std::isinf ( src_val ) ||
			( instr.op0_size ( ) == 4 && ( result > INT32_MAX || result < INT32_MIN ) ) ||
			( instr.op0_size ( ) == 8 && ( src_val > static_cast< float >( INT64_MAX ) || src_val < static_cast< float > ( INT64_MIN ) ) ) ) {
		mxcsr.IE = 1;
		result = indefinite_int;
		// !TODO(exception)
	}
	else {
		mxcsr.IE = 0;
		mxcsr.PE = ( fenv_excepts & FE_INEXACT ) ? 1 : 0;
	}

	helpers::set_operand_value<int64_t> ( instr, 0u, result, context );
}

/// CVTTSS2SI - Convert Scalar Single-Precision to Signed Integer with Truncation
/// Converts a single-precision float to a 32/64-bit signed integer with truncation, storing in a general-purpose register, modifying MXCSR flags (IE, PE).
void handlers::cvttss2si ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			( instr.op0_size ( ) != 4 && instr.op0_size ( ) != 8 ) ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );
	const int64_t indefinite_int = ( instr.op0_size ( ) == 8 ) ? INT64_MIN : INT32_MIN;
	int64_t result;

	std::feclearexcept ( FE_ALL_EXCEPT );
	if ( instr.op0_size ( ) == 4 ) {
		result = static_cast< int32_t >( src_val );
	}
	else {
		result = static_cast< int64_t >( src_val );
	}
	const int fenv_excepts = std::fetestexcept ( FE_INVALID );

	if ( fenv_excepts & FE_INVALID || std::isnan ( src_val ) || std::isinf ( src_val ) ||
			( instr.op0_size ( ) == 4 && ( src_val >= 2147483648.0f || src_val < -2147483648.0f ) ) ||
			( instr.op0_size ( ) == 8 && ( src_val >= static_cast< float > ( INT64_MAX ) || src_val <= static_cast< float > ( INT64_MIN ) ) ) ) {
		mxcsr.IE = 1;
		result = indefinite_int;
		// !TODO(exception)
	}
	else {
		mxcsr.IE = 0;
		mxcsr.PE = 0; // Truncation does not set PE
	}

	helpers::set_operand_value<int64_t> ( instr, 0u, result, context );
}

/// CVTSI2SS - Convert Signed Integer to Scalar Single-Precision
/// Converts a 32/64-bit signed integer to a single-precision float, storing in the destination XMM register (bits 31:0), modifying MXCSR flag (PE).
void handlers::cvtsi2ss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			( instr.op1_size ( ) != 4 && instr.op1_size ( ) != 8 ) ) {
		// !TODO(exception)
		return;
	}

	const int64_t src_val = helpers::get_operand_value<int64_t> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	std::fesetround ( mxcsr.RC );
	std::feclearexcept ( FE_ALL_EXCEPT );
	const float result = static_cast< float >( instr.op1_size ( ) == 4 ? static_cast< int32_t >( src_val ) : src_val );
	const int fenv_excepts = std::fetestexcept ( FE_INEXACT );

	mxcsr.IE = 0;
	mxcsr.DE = 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = 0;
	mxcsr.PE = ( fenv_excepts & FE_INEXACT ) ? 1 : 0;

	context.set_xmm_float ( instr.op0_reg ( ), result );
}

/// CVTSI2SD - Convert Signed Integer to Scalar Double-Precision
/// Converts a 32/64-bit signed integer to a double-precision float, storing in the destination XMM register (bits 63:0), modifying MXCSR flag (PE).
void handlers::cvtsi2sd ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 8 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ||
			( instr.op1_size ( ) != 4 && instr.op1_size ( ) != 8 ) ) {
		// !TODO(exception)
		return;
	}

	const int64_t src_val = helpers::get_operand_value<int64_t> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	std::fesetround ( mxcsr.RC );
	std::feclearexcept ( FE_ALL_EXCEPT );
	const double result = static_cast< double >( instr.op1_size ( ) == 4 ? static_cast< int32_t >( src_val ) : src_val );
	const int fenv_excepts = std::fetestexcept ( FE_INEXACT );

	mxcsr.IE = 0;
	mxcsr.DE = 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = 0;
	mxcsr.PE = ( fenv_excepts & FE_INEXACT ) ? 1 : 0;

	context.set_xmm_double ( instr.op0_reg ( ), result );
}

/// CVTSS2SD - Convert Scalar Single-Precision to Double-Precision
/// Converts a single-precision float to a double-precision float, storing in the destination XMM register (bits 63:0), modifying MXCSR flags (IE, OE, UE, PE).
void handlers::cvtss2sd ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 8 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const float src_val = helpers::get_operand_value<float> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );

	const double result = static_cast< double >( src_val );
	mxcsr.IE = ( std::isnan ( src_val ) || std::isinf ( src_val ) ) ? 1 : 0;
	mxcsr.DE = ( std::fpclassify ( src_val ) == FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.ZE = 0;
	mxcsr.OE = 0;
	mxcsr.UE = ( std::fpclassify ( result ) == FP_SUBNORMAL && std::fpclassify ( src_val ) != FP_SUBNORMAL ) ? 1 : 0;
	mxcsr.PE = ( !std::isinf ( result ) && !std::isnan ( result ) && std::fpclassify ( result ) != FP_ZERO ) ? 1 : 0;

	if ( mxcsr.IE || mxcsr.UE ) {
		// !TODO(exception)
		return;
	}

	context.set_xmm_double ( instr.op0_reg ( ), result );
}

/// CVTSD2SS - Convert Scalar Double-Precision to Single-Precision
/// Converts a double-precision float to a single-precision float, storing in the destination XMM register (bits 31:0), modifying MXCSR flags (IE, OE, UE, PE).
void handlers::cvtsd2ss ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Register ||
			instr.op0_size ( ) != 4 ||
			instr.op0_reg ( ) < Register::XMM0 || instr.op0_reg ( ) > Register::XMM31 ) {
		// !TODO(exception)
		return;
	}

	const double src_val = helpers::get_operand_value<double> ( instr, 1u, context );
	auto& mxcsr = context.get_mxcsr ( );
	
	std::fesetround ( mxcsr.RC );
	std::feclearexcept ( FE_ALL_EXCEPT );
	const float result = static_cast< float >( src_val );
	const int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT );

	mxcsr.IE = ( fenv_excepts & FE_INVALID || std::isnan ( src_val ) || std::isinf ( src_val ) ) ? 1 : 0;
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
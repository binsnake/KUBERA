// --- START OF FILE fpu.cpp ---
#include "pch.hpp"
#include <cmath>
#include <cfenv>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/math/special_functions/modf.hpp>


namespace mp = boost::multiprecision;
using float80_t = mp::number<mp::cpp_bin_float<64, mp::digit_base_2, void, std::int16_t, -16382, 16383>, mp::et_off>;

void addss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	const float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	const float a = dst_val;
	const float b = src_val;
	const float result = a + b;

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );
	state.update_mxcsr_arithmetic ( a, b, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = {} + {} = {}", reg_idx, a, b, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void subss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	float a = dst_val;
	float b = src_val;
	float result = a - b;

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );
	state.update_mxcsr_arithmetic ( a, b, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = {} - {} = {}", reg_idx, a, b, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void mulss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	float a = dst_val;
	float b = src_val;
	float result = a * b;

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;
	state.update_mxcsr_arithmetic ( a, b, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = {} * {} = {}", reg_idx, a, b, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void divss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	float a = dst_val;
	float b = src_val;
	float result = a / b;

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;
	state.update_mxcsr_arithmetic ( a, b, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = {} / {} = {}", reg_idx, a, b, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void sqrtss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	if (
		std::signbit ( src_val ) || std::isnan ( src_val )
		) {
		GuestExceptionInfo ex;
		ex.set_exception ( STATUS_FLOAT_INVALID_OPERATION, instr.ip ( ) );
		throw ex;
	}

	float a = src_val;
	float result = std::sqrtf ( a );

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;
	state.update_mxcsr_sqrt ( a, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = sqrt({}) = {}", reg_idx, a, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void sqrtsd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	double dst_val = state.get_xmm_double ( ops [ 0 ].reg );
	double src_val = helpers::get_src<double> ( &instr, 1, state, 8 );

	if ( std::signbit ( src_val ) || std::isnan ( src_val ) ) {
		GuestExceptionInfo ex;
		ex.set_exception ( STATUS_FLOAT_INVALID_OPERATION, instr.ip ( ) );
		throw ex;
	}

	double a = src_val;
	double result = std::sqrt ( a );

	state.set_xmm_double ( ops [ 0 ].reg, result, effect );;
	state.update_mxcsr_sqrt ( a, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[63:0] = sqrt({}) = {}", reg_idx, a, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}


void comiss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	float src1 = state.get_xmm_float ( ops [ 0 ].reg );
	float src2 = helpers::get_src<float> ( &instr, 1, state, 4 );

	state.update_flags_for_compare ( src1, src2, false, effect );
}

void ucomiss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	float src1 = state.get_xmm_float ( ops [ 0 ].reg );
	float src2 = helpers::get_src<float> ( &instr, 1, state, 4 );

	state.update_flags_for_compare ( src1, src2, true, effect );
}

void comisd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	double src1 = state.get_xmm_double ( ops [ 0 ].reg );
	double src2 = helpers::get_src<double> ( &instr, 1, state, 8 );

	state.update_flags_for_compare ( src1, src2, false, effect );
}

void cmpss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float op1_val = state.get_xmm_float ( ops [ 0 ].reg );
	float op2_val = helpers::get_src<float> ( &instr, 1, state, 4 );
	uint8_t predicate = ops [ 2 ].imm & 0x07;

	float a = op1_val;
	float b = op2_val;

	bool is_nan_a = std::isnan ( a );
	bool is_nan_b = std::isnan ( b );
	bool unordered = is_nan_a || is_nan_b;
	bool result = false;

	uint32_t old_mxcsr_flags = *( uint32_t* ) &state.cpu->cpu_flags.mxcsr;
	state.cpu->cpu_flags.mxcsr.IE = 0;

	bool is_sNaN_a = false;
	bool is_sNaN_b = false;
	bool signal_ie = ( is_sNaN_a || is_sNaN_b );

	switch ( predicate ) {
		case 0: if ( unordered ) { signal_ie = true; result = false; }
					else { result = ( a == b ); } break;
		case 1: if ( unordered ) { signal_ie = true; result = false; }
					else { result = ( a < b ); } break;
		case 2: if ( unordered ) { signal_ie = true; result = false; }
					else { result = ( a <= b ); } break;
		case 3: result = unordered; break;
		case 4: if ( unordered ) { result = true; }
					else { result = ( a != b ); } break;
		case 5: if ( unordered ) { result = true; }
					else { result = !( a < b ); } break;
		case 6: if ( unordered ) { result = true; }
					else { result = !( a <= b ); } break;
		case 7: result = !unordered; break;
	}

	if ( signal_ie ) {
		state.cpu->cpu_flags.mxcsr.IE = 1;
	}
	if ( state.cpu->cpu_flags.mxcsr.IE != ( ( old_mxcsr_flags >> 0 ) & 1 ) ) state.log_mxcsr_flag_change ( effect, "IE", ( old_mxcsr_flags >> 0 ) & 1, state.cpu->cpu_flags.mxcsr.IE );


	uint32_t mask = result ? 0xFFFFFFFF : 0x00000000;
	state.set_xmm_float ( ops [ 0 ].reg, std::bit_cast< float >( mask ), effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = 0x{:08x} (Pred={}, {}, {} vs {})",
													 reg_idx, mask, predicate, result ? "True" : "False", a, b ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void cvtss2si ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type != X86_OP_REG || ( ops [ 0 ].size != 4 && ops [ 0 ].size != 8 ) ) {
		effect.push_to_changes ( state, "Invalid destination for CVTSS2SI (expected 32/64-bit GP reg)" );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	uint8_t op_size = ops [ 0 ].size;
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	fesetround ( state.cpu->cpu_flags.mxcsr.RC );

	int64_t result = 0;
	bool exception = false;
	int64_t indefinite_int = ( op_size == 8 ) ? INT64_MIN : INT32_MIN;

	std::feclearexcept ( FE_ALL_EXCEPT );
	if ( op_size == 4 ) {
		result = static_cast< int64_t >( std::lrintf ( src_val ) );
	}
	else {
		result = std::lrintf ( src_val );
	}

	int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_INEXACT );

	if ( ( fenv_excepts & FE_INVALID ) ||
			( op_size == 4 && ( result > INT32_MAX || result < INT32_MIN ) ) ||
			( op_size == 8 && ( src_val > ( float ) INT64_MAX || src_val < ( float ) INT64_MIN ) ) ) {
		exception = true;
		result = indefinite_int;
		state.update_mxcsr_conversion_float_to_int ( src_val, result, false, effect );
	}
	else {
		if constexpr ( std::is_same_v<decltype( result ), int32_t> ) {
			state.update_mxcsr_conversion_float_to_int ( src_val, static_cast< int32_t > ( result ), false, effect );
		}
		else {
			state.update_mxcsr_conversion_float_to_int ( src_val, result, false, effect );
		}
	}

	state.set_reg ( ops [ 0 ].reg, result, op_size, effect );
	effect.push_to_changes ( state, std::format ( "{} = 0x{:x} (from {})", cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 0 ].reg ), result & ( ( 1ULL << ( op_size * 8 ) ) - 1 ), src_val ) );
}

void cvttss2si ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type != X86_OP_REG || ( ops [ 0 ].size != 4 && ops [ 0 ].size != 8 ) ) {
		effect.push_to_changes ( state, "Invalid destination for CVTTSS2SI (expected 32/64-bit GP reg)" );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t op_size = ops [ 0 ].size;
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	int64_t result = 0;
	bool exception = false;
	int64_t indefinite_int = ( op_size == 8 ) ? INT64_MIN : INT32_MIN;

	std::feclearexcept ( FE_ALL_EXCEPT );
	if ( op_size == 4 ) {
		result = static_cast< int32_t >( src_val );
	}
	else {
		result = static_cast< int64_t >( src_val );
	}
	int fenv_excepts = std::fetestexcept ( FE_INVALID );

	if ( ( fenv_excepts & FE_INVALID ) || std::isnan ( src_val ) || std::isinf ( src_val ) ||
		 ( op_size == 4 && ( src_val >= 2147483648.0f || src_val < -2147483648.0f ) ) ||
		 ( op_size == 8 && ( src_val >= ( float ) INT64_MAX || src_val <= ( float ) INT64_MIN ) )
		) {
		exception = true;
		result = indefinite_int;
		state.update_mxcsr_conversion_float_to_int ( src_val, result, true, effect );
	}
	else {
		if constexpr ( std::is_same_v<decltype( result ), int32_t> ) {
			state.update_mxcsr_conversion_float_to_int ( src_val, static_cast< int32_t > ( result ), true, effect );
		}
		else {
			state.update_mxcsr_conversion_float_to_int ( src_val, result, true, effect );
		}
	}


	state.set_reg ( ops [ 0 ].reg, result, op_size, effect );
	effect.push_to_changes ( state, std::format ( "{} = 0x{:x} (truncated from {})", cs_reg_name ( state.decoder.back ( )->get_handle ( ), ops [ 0 ].reg ), result & ( ( 1ULL << ( op_size * 8 ) ) - 1 ), src_val ) );
}

void cvtsi2ss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type != X86_OP_REG || ops [ 0 ].reg < X86_REG_XMM0 ) {
		effect.push_to_changes ( state, "CVTSI2SS: Invalid destination (expected XMM)" );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t src_size = ( ops [ 1 ].size == 4 || ops [ 1 ].size == 8 ) ? ops [ 1 ].size : 4;
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	int64_t src_int = helpers::get_src<int64_t> ( &instr, 1, state, src_size );

	if ( src_size == 4 ) src_int = static_cast< int32_t > ( src_int );

	std::fesetround ( state.cpu->cpu_flags.mxcsr.RC );
	std::feclearexcept ( FE_ALL_EXCEPT );
	float result = static_cast< float >( src_int );
	int fenv_excepts = std::fetestexcept ( FE_INEXACT );

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;
	if ( src_size == 4 ) {
		state.update_mxcsr_conversion_int_to_float ( static_cast< int32_t >( src_int ), result, effect );
	}
	else {
		state.update_mxcsr_conversion_int_to_float ( src_int, result, effect );
	}


	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = (float)({}) = {}", reg_idx, src_int, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void cvtsi2sd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type != X86_OP_REG || ops [ 0 ].reg < X86_REG_XMM0 ) {
		effect.push_to_changes ( state, "CVTSI2SD: Invalid destination (expected XMM)" );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t src_size = ( ops [ 1 ].size == 4 || ops [ 1 ].size == 8 ) ? ops [ 1 ].size : 4;
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	int64_t src_int = helpers::get_src<int64_t> ( &instr, 1, state, src_size );

	if ( src_size == 4 ) src_int = static_cast< int32_t > ( src_int );

	double result = static_cast< double > ( src_int );

	state.set_xmm_double ( ops [ 0 ].reg, result, effect );;
	if ( src_size == 4 ) {
		state.update_mxcsr_conversion_int_to_float ( static_cast< int32_t >( src_int ), result, effect );
	}
	else {
		state.update_mxcsr_conversion_int_to_float ( src_int, result, effect );
	}

	effect.push_to_changes ( state, std::format ( "xmm{}[63:0] = (double)({}) = {}", reg_idx, src_int, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void cvtss2sd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type != X86_OP_REG || ops [ 0 ].reg < X86_REG_XMM0 ) {
		effect.push_to_changes ( state, "CVTSS2SD: Invalid destination (expected XMM)" );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	double result = static_cast< double > ( src_val );

	state.set_xmm_double ( ops [ 0 ].reg, result, effect );;
	state.update_mxcsr_conversion ( src_val, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[63:0] = (double)({}) = {}", reg_idx, src_val, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void cvtsd2ss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type != X86_OP_REG || ops [ 0 ].reg < X86_REG_XMM0 ) {
		effect.push_to_changes ( state, "CVTSD2SS: Invalid destination (expected XMM)" );
		GuestExceptionInfo ex; ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) ); throw ex;
	}
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	double src_val = helpers::get_src<double> ( &instr, 1, state, 8 );

	std::fesetround ( state.cpu->cpu_flags.mxcsr.RC );
	std::feclearexcept ( FE_ALL_EXCEPT );
	float result = static_cast< float > ( src_val );
	int fenv_excepts = std::fetestexcept ( FE_INVALID | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT );

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;
	state.update_mxcsr_conversion ( src_val, result, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = (float)({}) = {}", reg_idx, src_val, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void minss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	float a = dst_val;
	float b = src_val;
	float result;
	bool set_ie = false;

	bool is_nan_a = std::isnan ( a );
	bool is_nan_b = std::isnan ( b );


	if ( is_nan_a || is_nan_b ) {
		result = b;

	}
	else if ( a == 0.0f && b == 0.0f ) {

		result = std::signbit ( a ) ? a : b;
	}
	else {
		result = ( a < b ) ? a : b;
	}

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;

	uint32_t old_ie = state.cpu->cpu_flags.mxcsr.IE;
	state.cpu->cpu_flags.mxcsr.IE = set_ie;
	if ( old_ie != state.cpu->cpu_flags.mxcsr.IE ) state.log_mxcsr_flag_change ( effect, "IE", old_ie, state.cpu->cpu_flags.mxcsr.IE );


	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = minss({}, {}) = {}", reg_idx, a, b, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}

void maxss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t reg_idx = ops [ 0 ].reg - X86_REG_XMM0;
	float dst_val = state.get_xmm_float ( ops [ 0 ].reg );
	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	float a = dst_val;
	float b = src_val;
	float result;
	bool set_ie = false;

	bool is_nan_a = std::isnan ( a );
	bool is_nan_b = std::isnan ( b );


	if ( is_nan_a || is_nan_b ) {
		result = b;

	}
	else if ( a == 0.0f && b == 0.0f ) {

		result = std::signbit ( b ) ? a : b;
	}
	else {
		result = ( a > b ) ? a : b;
	}

	state.set_xmm_float ( ops [ 0 ].reg, result, effect );;

	uint32_t old_ie = state.cpu->cpu_flags.mxcsr.IE;
	state.cpu->cpu_flags.mxcsr.IE = set_ie;
	if ( old_ie != state.cpu->cpu_flags.mxcsr.IE ) state.log_mxcsr_flag_change ( effect, "IE", old_ie, state.cpu->cpu_flags.mxcsr.IE );

	effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = maxss({}, {}) = {}", reg_idx, a, b, result ) );
	effect.modified_regs.insert ( ops [ 0 ].reg );
}


void andps ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint128_t dst_val = state.get_xmm_raw ( dst_reg );
	uint128_t src_val = helpers::get_src<uint128_t> ( &instr, 1, state, 16 );

	dst_val &= src_val;
	state.set_xmm_raw ( dst_reg, dst_val, effect );
	effect.push_to_changes ( state, std::format ( "xmm{} = xmm{} & src", dst_reg - X86_REG_XMM0, dst_reg - X86_REG_XMM0 ) );
	effect.modified_regs.insert ( dst_reg );
}

void orps ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint128_t dst_val = state.get_xmm_raw ( dst_reg );
	uint128_t src_val = helpers::get_src<uint128_t> ( &instr, 1, state, 16 );

	dst_val |= src_val;
	state.set_xmm_raw ( dst_reg, dst_val, effect );
	effect.push_to_changes ( state, std::format ( "xmm{} = xmm{} | src", dst_reg - X86_REG_XMM0, dst_reg - X86_REG_XMM0 ) );
	effect.modified_regs.insert ( dst_reg );
}

void xorps ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint128_t dst_val = state.get_xmm_raw ( dst_reg );
	uint128_t src_val = helpers::get_src<uint128_t> ( &instr, 1, state, 16 );


	if ( ops [ 1 ].type == X86_OP_REG && ops [ 1 ].reg == dst_reg ) {
		dst_val = uint128_t { 0 };
	}
	else {
		dst_val ^= src_val;
	}
	state.set_xmm_raw ( dst_reg, dst_val, effect );
	effect.push_to_changes ( state, std::format ( "xmm{} = xmm{} ^ src", dst_reg - X86_REG_XMM0, dst_reg - X86_REG_XMM0 ) );
	effect.modified_regs.insert ( dst_reg );
}

void roundss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {

	effect.push_to_changes ( state, "ROUNDSS handler needs implementation for rounding modes and PE flag." );
}
void rcpss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {

	effect.push_to_changes ( state, "RCPSS handler needs implementation for approximation and MXCSR flags." );
}
void rsqrtss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {

	effect.push_to_changes ( state, "RSQRTSS handler needs implementation for approximation and MXCSR flags." );
}

void movhlps ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {

	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	x86_reg src_reg = ops [ 1 ].reg;
	uint128_t dst_val = state.get_xmm_raw ( dst_reg );
	const uint128_t src_val = state.get_xmm_raw ( src_reg );

	uint64_t src_high_bits_as_u64 = static_cast< uint64_t >( src_val >> 64 );
	uint128_t new_low_part = src_high_bits_as_u64;

	uint128_t result_val = ( dst_val & ( uint128_t ( 0xFFFFFFFFFFFFFFFF ) << 64 ) ) | new_low_part;

	state.set_xmm_raw ( dst_reg, result_val, effect );

	effect.push_to_changes ( state, std::format ( "xmm{}[63:0] = xmm{}[127:64]", dst_reg - X86_REG_XMM0, src_reg - X86_REG_XMM0 ) );
	effect.modified_regs.insert ( dst_reg );
}

void unpcklps ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {

	const cs_x86_op* ops = instr.operands ( );
	x86_reg dst_reg = ops [ 0 ].reg;
	uint128_t dst_val = state.get_xmm_raw ( dst_reg );
	uint128_t src_val = helpers::get_src<uint128_t> ( &instr, 1, state, 16 );



	const uint32_t dst0 = static_cast< uint32_t >( dst_val );
	const uint32_t dst1 = static_cast< uint32_t >( dst_val >> 32 );
	const uint32_t src0 = static_cast< uint32_t >( src_val );
	const uint32_t src1 = static_cast< uint32_t >( src_val >> 32 );

	uint128_t result = 0;
	result |= static_cast< uint128_t >( dst0 );
	result |= static_cast< uint128_t >( src0 ) << 32;
	result |= static_cast< uint128_t >( dst1 ) << 64;
	result |= static_cast< uint128_t >( src1 ) << 96;

	state.set_xmm_raw ( dst_reg, result, effect );

	effect.push_to_changes ( state, "UNPCKLPS executed (interleave low)" );
	effect.modified_regs.insert ( dst_reg );
}

void movss ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	const cs_x86_op& dst_op = ops [ 0 ];
	const cs_x86_op& src_op = ops [ 1 ];

	float src_val = helpers::get_src<float> ( &instr, 1, state, 4 );

	if ( dst_op.type == X86_OP_REG && src_op.type == X86_OP_REG ) {
		if ( dst_op.reg < X86_REG_XMM0 || dst_op.reg > X86_REG_XMM31 || src_op.reg < X86_REG_XMM0 || src_op.reg > X86_REG_XMM31 ) return;
		uint8_t dst_reg_idx = dst_op.reg - X86_REG_XMM0;
		uint8_t src_reg_idx = src_op.reg - X86_REG_XMM0;

		state.set_xmm_float ( dst_op.reg, src_val, effect );
		effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = xmm{}[31:0] ({})",
														 dst_reg_idx, src_reg_idx, state.get_xmm_float ( dst_op.reg ) ) );
		effect.modified_regs.insert ( dst_op.reg );

	}
	else if ( dst_op.type == X86_OP_REG && src_op.type == X86_OP_MEM ) {
		if ( dst_op.reg < X86_REG_XMM0 || dst_op.reg > X86_REG_XMM31 ) return;
		uint8_t dst_reg_idx = dst_op.reg - X86_REG_XMM0;

		state.set_xmm_float ( dst_op.reg, src_val, effect );
		effect.push_to_changes ( state, std::format ( "xmm{}[31:0] = mem32 ({})", dst_reg_idx, src_val ) );
		effect.modified_regs.insert ( dst_op.reg );

	}
	else if ( dst_op.type == X86_OP_MEM && src_op.type == X86_OP_REG ) {
		if ( src_op.reg < X86_REG_XMM0 || src_op.reg > X86_REG_XMM31 ) return;

		int64_t addr = helpers::calculate_mem_addr ( dst_op, instr, state );
		if ( addr == 0 ) {
			effect.push_to_changes ( state, "MOVSS: Failed to compute memory address" );
			return;
		}

		uint32_t val_to_write = std::bit_cast< uint32_t >( src_val );

		if ( state.is_within_stack_bounds ( addr, 4 ) ) {
			state.set_stack ( addr, val_to_write, effect, 4 );
		}
		else {
			state.set_memory ( addr, val_to_write, 4, effect );
		}
		effect.push_to_changes ( state, std::format ( "mem32 at 0x{:x} = xmm{}[31:0] ({})",
														 addr, src_op.reg - X86_REG_XMM0, src_val ) );
		effect.modified_mem.insert ( addr );
	}
}


void mulsd ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	x86_reg dst_reg = ops [ 0 ].reg;
	uint8_t reg_idx = dst_reg - X86_REG_XMM0;
	double dst_val = state.get_xmm_double ( ops [ 0 ].reg );
	double src_val = helpers::get_src<double> ( &instr, 1, state, 8 );

	double a = dst_val;
	double b = src_val;
	double result = a * b;

	state.set_xmm_double ( ops [ 0 ].reg, result, effect );;
	effect.push_to_changes ( state, std::format ( "xmm{}[63:0] = {} * {} = {}", reg_idx, a, b, result ) );

	state.update_mxcsr_arithmetic ( a, b, result, effect );

	effect.modified_regs.insert ( dst_reg );
}

void stmxcsr ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) != 1 || ops [ 0 ].type != X86_OP_MEM ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}
	if ( ops [ 0 ].size != 4 ) {
		effect.push_to_changes ( state, "STMXCSR: Invalid memory operand size (must be 4 bytes)" );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	const cs_x86_op& mem_op = ops [ 0 ];

	uint64_t dest_addr = helpers::calculate_mem_addr ( mem_op, instr, state );
	if ( dest_addr == 0 && !state.exit_due_to_critical_error ) {
		state.exit_due_to_critical_error = true;
		return;
	}

	uint32_t mxcsr_value = *( uint32_t* ) &state.cpu->cpu_flags.mxcsr;

	try {
		state.set_memory ( dest_addr, mxcsr_value, 4, effect );
	}
	catch ( const GuestExceptionInfo& mem_ex ) {
		throw mem_ex;
	}

	if ( state.options.enable_logging ) {
		effect.push_to_changes ( state, std::format ( "STMXCSR: Stored MXCSR (0x{:08X}) to [0x{:016X}]", mxcsr_value, dest_addr ) );
	}
}

void ldmxcsr ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( instr.operand_count ( ) != 1 || ops [ 0 ].type != X86_OP_MEM ) {
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}
	if ( ops [ 0 ].size != 4 ) {
		effect.push_to_changes ( state, "LDMXCSR: Invalid memory operand size (must be 4 bytes)" );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}

	const cs_x86_op& mem_op = ops [ 0 ];

	uint64_t src_addr = helpers::calculate_mem_addr ( mem_op, instr, state );
	if ( src_addr == 0 && !state.exit_due_to_critical_error ) {
		state.exit_due_to_critical_error = true;
		return;
	}

	uint32_t new_mxcsr_value = 0;
	try {
		new_mxcsr_value = static_cast< uint32_t >( state.get_memory ( src_addr, 4 ) );
	}
	catch ( const GuestExceptionInfo& mem_ex ) {
		throw mem_ex;
	}

	if ( ( new_mxcsr_value >> 16 ) != 0 ) {
		effect.push_to_changes ( state, std::format ( "LDMXCSR: Attempted to load value 0x{:08X} with reserved bits set", new_mxcsr_value ) );
		GuestExceptionInfo ex;
		ex.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
		throw ex;
	}


	uint32_t old_val = *( uint32_t* ) &state.cpu->cpu_flags.mxcsr;
	*( uint32_t* ) ( &state.cpu->cpu_flags.mxcsr ) = new_mxcsr_value;

	if ( state.options.enable_logging ) {
		effect.push_to_changes ( state, std::format ( "LDMXCSR: Loaded MXCSR from [0x{:016X}], value 0x{:08X} -> 0x{:08X}", src_addr, old_val, new_mxcsr_value ) );
	}
}

void fld ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	float80_t value_to_load;
	bool is_sti = false;
	uint16_t determined_fsw_flags = 0;

	int next_top = ( state.cpu->fpu.fpu_top - 1 + 8 ) % 8;
	int st7_phys_idx = ( next_top + 7 ) % 8;
	if ( state.get_fpu_tag ( st7_phys_idx ) != FPU_TAG_EMPTY ) {
		determined_fsw_flags |= ( FSW_IE | FSW_SF | FSW_C1 );
		state.check_fpu_exception ( determined_fsw_flags );
		effect.push_to_changes ( state, "FLD: FPU Stack Overflow (#IS)" );
		return;
	}

	try {
		if ( ops [ 0 ].type == X86_OP_MEM ) {
			uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
			if ( addr == 0 && !state.exit_due_to_critical_error ) {
				state.exit_due_to_critical_error = true;
				return;
			}
			switch ( op_size ) {
				case 4:
					value_to_load = helpers::get_operand_value<float> ( instr, 0, state, effect );
					break;
				case 8:
					value_to_load = helpers::get_operand_value<double> ( instr, 0, state, effect );
					break;
				case 10:
					value_to_load = state.read_float80_from_memory ( addr, effect );
					break;
				default:
					effect.push_to_changes ( state, std::format ( "FLD: Unsupported memory operand size {}", op_size ) );
					throw std::runtime_error ( "Invalid FLD size" );
			}

			if ( state.classify_fpu_operand ( value_to_load ) == FPU_TAG_SPECIAL ) {
				if ( boost::multiprecision::fpclassify ( value_to_load ) == FP_SUBNORMAL ) {
					determined_fsw_flags |= FSW_DE;
				}
				else if ( boost::multiprecision::isnan ( value_to_load ) ) {
					determined_fsw_flags |= FSW_IE;
				}
			}

		}
		else if ( ops [ 0 ].type == X86_OP_REG && ops [ 0 ].reg >= X86_REG_ST0 && ops [ 0 ].reg <= X86_REG_ST7 ) {
			is_sti = true;
			int src_sti = ops [ 0 ].reg - X86_REG_ST0;
			int src_phys_idx = state.get_fpu_phys_idx ( src_sti );
			if ( state.get_fpu_tag ( src_phys_idx ) == FPU_TAG_EMPTY ) {
				determined_fsw_flags |= ( FSW_IE | FSW_SF );
				state.check_fpu_exception ( determined_fsw_flags );
				effect.push_to_changes ( state, std::format ( "FLD: Source ST({}) is empty (#IS)", src_sti ) );
				return;
			}
			value_to_load = state.cpu->fpu.fpu_stack [ src_phys_idx ];
		}
		else {
			effect.push_to_changes ( state, "FLD: Invalid operand type." );
			throw std::runtime_error ( "Invalid FLD operand" );
		}
	}
	catch ( const GuestExceptionInfo& e ) { UNREFERENCED_PARAMETER ( e ); throw; }
	catch ( const std::exception& e ) {
		effect.push_to_changes ( state, std::format ( "FLD: Error getting operand: {}", e.what ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}


	if ( state.exit_due_to_critical_error ) return;

	state.cpu->fpu.fpu_top = next_top;
	state.cpu->fpu.fpu_stack [ state.cpu->fpu.fpu_top ] = value_to_load;

	state.cpu->fpu.fpu_status_word &= ~FSW_C1;
	state.update_fsw_top ( );
	uint8_t new_tag = state.classify_fpu_operand ( value_to_load );
	state.set_fpu_tag ( state.cpu->fpu.fpu_top, new_tag );

	state.check_fpu_exception ( determined_fsw_flags );

	if ( state.options.enable_logging ) {
		double log_val = value_to_load.convert_to<double> ( );
		if ( is_sti ) {
			effect.push_to_changes ( state, std::format ( "FLD ST({}), ApproxValue: {}, NewTop: {}", ops [ 0 ].reg - X86_REG_ST0, log_val, state.cpu->fpu.fpu_top ) );
		}
		else {
			effect.push_to_changes ( state, std::format ( "FLD mem{}, ApproxValue: {}, NewTop: {}", op_size * 8, log_val, state.cpu->fpu.fpu_top ) );
		}
	}
	effect.modified_regs.insert ( X86_REG_ST0 );
}

void fprem ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint16_t determined_fsw_flags = 0;

	int st0_phys_idx = state.cpu->fpu.fpu_top;
	int st1_phys_idx = ( state.cpu->fpu.fpu_top + 1 ) % 8;
	if ( state.get_fpu_tag ( st0_phys_idx ) == FPU_TAG_EMPTY ||
			state.get_fpu_tag ( st1_phys_idx ) == FPU_TAG_EMPTY ) {
		determined_fsw_flags |= ( FSW_IE | FSW_SF | FSW_C2 );
		state.check_fpu_exception ( determined_fsw_flags );
		effect.push_to_changes ( state, "FPREM: Stack Underflow (#IS)" );
		return;
	}

	float80_t st0_val = state.cpu->fpu.fpu_stack [ st0_phys_idx ];
	float80_t st1_val = state.cpu->fpu.fpu_stack [ st1_phys_idx ];
	float80_t result;

	bool is_st0_denormal = ( boost::multiprecision::fpclassify ( st0_val ) == FP_SUBNORMAL );
	bool is_st1_denormal = ( boost::multiprecision::fpclassify ( st1_val ) == FP_SUBNORMAL );
	if ( is_st0_denormal || is_st1_denormal ) {
		determined_fsw_flags |= FSW_DE;
	}
	if ( boost::multiprecision::isnan ( st0_val ) || boost::multiprecision::isnan ( st1_val ) ||
			boost::multiprecision::isinf ( st0_val ) || boost::multiprecision::isinf ( st1_val ) ||
			st1_val == 0 ) {
		determined_fsw_flags |= FSW_IE;
		state.cpu->fpu.fpu_status_word |= FSW_C2;
		state.check_fpu_exception ( determined_fsw_flags );
		effect.push_to_changes ( state, "FPREM: Invalid operand (NaN, Inf, Zero Divisor) (#IE)" );
		return;
	}

	result = boost::math::modf ( st0_val, &st1_val );
	if ( result == 0.0 && st0_val != 0.0 ) {
		result = st0_val;
	}

	bool is_result_denormal = ( boost::multiprecision::fpclassify ( result ) == FP_SUBNORMAL );
	if ( result != 0 && is_result_denormal ) {
		determined_fsw_flags |= FSW_UE;
		determined_fsw_flags |= FSW_DE;
	}

	int exp0 = st0_val.backend ( ).exponent ( );
	int exp1 = st1_val.backend ( ).exponent ( );

	if ( exp0 - exp1 >= 64 ) {
		state.cpu->fpu.fpu_status_word |= FSW_C2;
		state.cpu->fpu.fpu_status_word &= ~( FSW_C0 | FSW_C1 | FSW_C3 );
	}
	else {
		state.cpu->fpu.fpu_status_word &= ~FSW_C2;
		state.cpu->fpu.fpu_status_word &= ~( FSW_C0 | FSW_C1 | FSW_C3 );
	}


	state.cpu->fpu.fpu_stack [ st0_phys_idx ] = result;
	state.set_fpu_tag ( st0_phys_idx, state.classify_fpu_operand ( result ) );
	state.check_fpu_exception ( determined_fsw_flags );

	if ( state.options.enable_logging ) {
		double log_st0 = st0_val.convert_to<double> ( );
		double log_st1 = st1_val.convert_to<double> ( );
		double log_res = result.convert_to<double> ( );
		effect.push_to_changes ( state, std::format ( "FPREM ST(0)={}, ST(1)={}, Result ST(0)={}, FSW=0x{:04x}", log_st0, log_st1, log_res, state.cpu->fpu.fpu_status_word ) );
	}
	effect.modified_regs.insert ( X86_REG_ST0 );
}

void fstp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	bool is_sti = false;
	uint16_t determined_fsw_flags = 0;

	int st0_phys_idx = state.cpu->fpu.fpu_top;
	if ( state.get_fpu_tag ( st0_phys_idx ) == FPU_TAG_EMPTY ) {
		determined_fsw_flags |= ( FSW_IE | FSW_SF | FSW_C1 );
		state.check_fpu_exception ( determined_fsw_flags );
		effect.push_to_changes ( state, "FSTP: FPU Stack Empty (#IS)" );
		return;
	}

	float80_t value_to_store = state.cpu->fpu.fpu_stack [ st0_phys_idx ];

	if ( boost::multiprecision::isnan ( value_to_store ) ) determined_fsw_flags |= FSW_IE;
	if ( boost::multiprecision::fpclassify ( value_to_store ) == FP_SUBNORMAL ) determined_fsw_flags |= FSW_DE;

	int original_round_mode = std::fegetround ( );
	std::fesetround ( state.get_std_rounding_mode ( ) );

	try {
		if ( ops [ 0 ].type == X86_OP_MEM ) {
			uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );
			if ( addr == 0 && !state.exit_due_to_critical_error ) {
				state.exit_due_to_critical_error = true;
				std::fesetround ( original_round_mode );
				return;
			}
			switch ( op_size ) {
				case 4:
				{
					float f_res = value_to_store.convert_to<float> ( );
					helpers::set_dst_value<uint32_t> ( instr, 0, std::bit_cast< uint32_t >( f_res ), state, effect );
					float80_t check_back = f_res;
					if ( f_res != 0 && value_to_store != 0 && check_back == 0 ) determined_fsw_flags |= FSW_UE;
					if ( !boost::multiprecision::isinf ( check_back ) && boost::multiprecision::isinf ( value_to_store ) ) determined_fsw_flags |= FSW_OE;
					if ( check_back != value_to_store ) determined_fsw_flags |= FSW_PE;
				}
				break;
				case 8:
				{
					double d_res = value_to_store.convert_to<double> ( );
					helpers::set_dst_value<uint64_t> ( instr, 0, std::bit_cast< uint64_t >( d_res ), state, effect );
					float80_t check_back = d_res;
					if ( d_res != 0 && value_to_store != 0 && check_back == 0 ) determined_fsw_flags |= FSW_UE;
					if ( !boost::multiprecision::isinf ( check_back ) && boost::multiprecision::isinf ( value_to_store ) ) determined_fsw_flags |= FSW_OE;
					if ( check_back != value_to_store ) determined_fsw_flags |= FSW_PE;
				}
				break;
				case 10:
				{
					state.write_float80_to_memory ( addr, value_to_store, effect );
				}
				break;
				default:
					effect.push_to_changes ( state, std::format ( "FSTP: Unsupported memory operand size {}", op_size ) );
					std::fesetround ( original_round_mode );
					throw std::runtime_error ( "Invalid FSTP size" );
			}
		}
		else if ( ops [ 0 ].type == X86_OP_REG && ops [ 0 ].reg >= X86_REG_ST0 && ops [ 0 ].reg <= X86_REG_ST7 ) {
			is_sti = true;
			int dst_sti = ops [ 0 ].reg - X86_REG_ST0;
			int dst_phys_idx = state.get_fpu_phys_idx ( dst_sti );
			state.cpu->fpu.fpu_stack [ dst_phys_idx ] = value_to_store;
			state.set_fpu_tag ( dst_phys_idx, state.classify_fpu_operand ( value_to_store ) );
			effect.modified_regs.insert ( ops [ 0 ].reg );
		}
		else {
			effect.push_to_changes ( state, "FSTP: Invalid destination operand type." );
			std::fesetround ( original_round_mode );
			throw std::runtime_error ( "Invalid FSTP operand" );
		}
	}
	catch ( const GuestExceptionInfo& e ) {
		std::fesetround ( original_round_mode );
		throw e;
	}
	catch ( const std::exception& e ) {
		std::fesetround ( original_round_mode );
		effect.push_to_changes ( state, std::format ( "FSTP: Error during store: {}", e.what ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}
	catch ( ... ) {
		std::fesetround ( original_round_mode );
		throw;
	}

	std::fesetround ( original_round_mode );

	if ( state.exit_due_to_critical_error ) return;

	state.cpu->fpu.fpu_status_word &= ~FSW_C1;
	if ( determined_fsw_flags & ( FSW_UE | FSW_OE ) ) {
		state.cpu->fpu.fpu_status_word |= FSW_C1;
	}
	state.check_fpu_exception ( determined_fsw_flags );

	state.set_fpu_tag ( st0_phys_idx, FPU_TAG_EMPTY );
	state.cpu->fpu.fpu_top = ( state.cpu->fpu.fpu_top + 1 ) % 8;
	state.update_fsw_top ( );


	if ( state.options.enable_logging ) {
		double log_val = value_to_store.convert_to<double> ( );
		if ( is_sti ) {
			effect.push_to_changes ( state, std::format ( "FSTP ST({}), ApproxValue: {}, NewTop: {}", ops [ 0 ].reg - X86_REG_ST0, log_val, state.cpu->fpu.fpu_top ) );
		}
		else {
			effect.push_to_changes ( state, std::format ( "FSTP mem{}, ApproxValue: {}, NewTop: {}", op_size * 8, log_val, state.cpu->fpu.fpu_top ) );
		}
	}
	effect.modified_regs.insert ( X86_REG_ST0 );
}

void ffree ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	if ( ops [ 0 ].type == X86_OP_REG && ops [ 0 ].reg >= X86_REG_ST0 && ops [ 0 ].reg <= X86_REG_ST7 ) {
		int sti_to_free = ops [ 0 ].reg - X86_REG_ST0;
		int phys_idx = state.get_fpu_phys_idx ( sti_to_free );
		state.set_fpu_tag ( phys_idx, FPU_TAG_EMPTY );
		if ( state.options.enable_logging ) {
			effect.push_to_changes ( state, std::format ( "FFREE ST({}) (Phys Idx {})", sti_to_free, phys_idx ) );
		}
		effect.modified_regs.insert ( ops [ 0 ].reg );
	}
	else {
		effect.push_to_changes ( state, "FFREE: Invalid operand." );

	}
}

void fincstp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	state.cpu->fpu.fpu_top = ( state.cpu->fpu.fpu_top + 1 ) % 8;
	state.cpu->fpu.fpu_status_word &= ~FSW_C1;
	state.update_fsw_top ( );
	if ( state.options.enable_logging ) {
		effect.push_to_changes ( state, std::format ( "FINCSTP, New Top: {}", state.cpu->fpu.fpu_top ) );
	}
	effect.modified_regs.insert ( X86_REG_ST0 );
}

void fmul ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	auto op_count = instr.operand_count ( );
	uint16_t determined_fsw_flags = 0;
	bool pop_stack = ( instr.mnemonic ( ) == X86_INS_FMULP ); // Use ID for checking popping variant

	int st0_phys_idx = state.cpu->fpu.fpu_top;
	float80_t operand1, operand2, result;
	int destination_phys_idx = st0_phys_idx;
	int destination_sti = 0;

	try {
		if ( op_count == 0 ) {
			pop_stack = true;
			int st1_phys_idx = state.get_fpu_phys_idx ( 1 );
			destination_phys_idx = st1_phys_idx;
			destination_sti = 1;

			if ( state.get_fpu_tag ( st0_phys_idx ) == FPU_TAG_EMPTY ||
					state.get_fpu_tag ( st1_phys_idx ) == FPU_TAG_EMPTY ) {
				determined_fsw_flags |= ( FSW_IE | FSW_SF );
				effect.push_to_changes ( state, "FMUL(P) implicit: Stack Underflow (#IS)" );
				goto handle_exceptions;
			}
			operand1 = state.cpu->fpu.fpu_stack [ st1_phys_idx ];
			operand2 = state.cpu->fpu.fpu_stack [ st0_phys_idx ];

		}
		else if ( op_count == 1 ) {
			destination_phys_idx = st0_phys_idx;
			destination_sti = 0;

			if ( state.get_fpu_tag ( st0_phys_idx ) == FPU_TAG_EMPTY ) {
				determined_fsw_flags |= ( FSW_IE | FSW_SF );
				effect.push_to_changes ( state, "FMUL mem: ST(0) empty (#IS)" );
				goto handle_exceptions;
			}
			operand1 = state.cpu->fpu.fpu_stack [ st0_phys_idx ];

			if ( ops [ 0 ].type == X86_OP_MEM ) {
				uint8_t op_size = ops [ 0 ].size;
				if ( op_size == 4 ) {
					operand2 = helpers::get_operand_value<float> ( instr, 0, state, effect );
				}
				else if ( op_size == 8 ) {
					operand2 = helpers::get_operand_value<double> ( instr, 0, state, effect );
				}
				else {
					effect.push_to_changes ( state, std::format ( "FMUL: Unsupported memory operand size {}", op_size ) );
					throw std::runtime_error ( "Invalid FMUL mem size" );
				}
			}
			else if ( ops [ 0 ].type == X86_OP_REG && ops [ 0 ].reg >= X86_REG_ST0 && ops [ 0 ].reg <= X86_REG_ST7 ) { // FMUL ST(i) implies FMUL ST(0), ST(i) -> ST(0)
				int sti = ops [ 0 ].reg - X86_REG_ST0;
				int sti_phys_idx = state.get_fpu_phys_idx ( sti );
				if ( state.get_fpu_tag ( sti_phys_idx ) == FPU_TAG_EMPTY ) {
					determined_fsw_flags |= ( FSW_IE | FSW_SF );
					effect.push_to_changes ( state, "FMUL ST(i): Stack Underflow (#IS)" );
					goto handle_exceptions;
				}
				operand2 = state.cpu->fpu.fpu_stack [ sti_phys_idx ];
			}
			else {
				effect.push_to_changes ( state, "FMUL: Invalid operand count/type combination." );
				throw std::runtime_error ( "Invalid FMUL form" );
			}

		}
		else if ( op_count == 2 ) {
			int sti = -1;
			if ( ops [ 0 ].type == X86_OP_REG && ops [ 0 ].reg >= X86_REG_ST0 && ops [ 0 ].reg <= X86_REG_ST7 &&
					ops [ 1 ].type == X86_OP_REG && ops [ 1 ].reg == X86_REG_ST0 ) { // FMUL ST(i), ST(0) -> ST(i)
				sti = ops [ 0 ].reg - X86_REG_ST0;
				destination_phys_idx = state.get_fpu_phys_idx ( sti );
				destination_sti = sti;
			}
			else if ( ops [ 1 ].type == X86_OP_REG && ops [ 1 ].reg >= X86_REG_ST0 && ops [ 1 ].reg <= X86_REG_ST7 &&
					ops [ 0 ].type == X86_OP_REG && ops [ 0 ].reg == X86_REG_ST0 ) { // FMUL ST(0), ST(i) -> ST(0)
				sti = ops [ 1 ].reg - X86_REG_ST0;
				destination_phys_idx = st0_phys_idx;
				destination_sti = 0;
			}
			else {
				effect.push_to_changes ( state, "FMUL: Invalid ST(i) operand combination." );
				throw std::runtime_error ( "Invalid FMUL ST(i) form" );
			}

			int sti_phys_idx = state.get_fpu_phys_idx ( sti );
			if ( state.get_fpu_tag ( st0_phys_idx ) == FPU_TAG_EMPTY ||
					state.get_fpu_tag ( sti_phys_idx ) == FPU_TAG_EMPTY ) {
				determined_fsw_flags |= ( FSW_IE | FSW_SF );
				effect.push_to_changes ( state, "FMUL ST(i): Stack Underflow (#IS)" );
				goto handle_exceptions;
			}
			operand1 = state.cpu->fpu.fpu_stack [ destination_phys_idx ];
			operand2 = ( destination_sti == 0 ) ? state.cpu->fpu.fpu_stack [ sti_phys_idx ] : state.cpu->fpu.fpu_stack [ st0_phys_idx ];
		}
		else {
			effect.push_to_changes ( state, "FMUL: Unexpected operand count." );
			throw std::runtime_error ( "Invalid FMUL operand count" );
		}

	}
	catch ( const GuestExceptionInfo& e ) { UNREFERENCED_PARAMETER ( e ); throw; }
	catch ( const std::exception& e ) {
		effect.push_to_changes ( state, std::format ( "FMUL: Error getting operand: {}", e.what ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	if ( state.exit_due_to_critical_error ) return;

	{
		using namespace boost::multiprecision;
		int class1 = fpclassify ( operand1 );
		int class2 = fpclassify ( operand2 );

		if ( class1 == FP_SUBNORMAL || class2 == FP_SUBNORMAL ) determined_fsw_flags |= FSW_DE;

		if ( class1 == FP_NAN || class2 == FP_NAN ) determined_fsw_flags |= FSW_IE;

		if ( ( class1 == FP_ZERO && class2 == FP_INFINITE ) || ( class1 == FP_INFINITE && class2 == FP_ZERO ) ) {
			determined_fsw_flags |= FSW_IE;
		}
	}

	if ( determined_fsw_flags & FSW_IE ) {
		effect.push_to_changes ( state, "FMUL: Invalid operand (NaN, 0*Inf) (#IE)" );
		goto handle_exceptions;
	}

	result = operand1 * operand2;

	{
		using namespace boost::multiprecision;
		int res_class = fpclassify ( result );

		if ( res_class == FP_INFINITE ) determined_fsw_flags |= FSW_OE;
		if ( res_class == FP_SUBNORMAL ) determined_fsw_flags |= FSW_DE;

		if ( ( res_class == FP_SUBNORMAL || res_class == FP_ZERO ) &&
				fpclassify ( operand1 ) == FP_NORMAL && fpclassify ( operand2 ) == FP_NORMAL ) {
			determined_fsw_flags |= FSW_UE;
		}

		if ( !( determined_fsw_flags & ( FSW_OE | FSW_UE ) ) && res_class != FP_ZERO ) {
			determined_fsw_flags |= FSW_PE;
		}
	}

handle_exceptions:

	state.cpu->fpu.fpu_status_word &= ~FSW_C1;

	state.check_fpu_exception ( determined_fsw_flags );

	if ( !( state.cpu->fpu.fpu_status_word & FSW_ES ) || ( determined_fsw_flags & FSW_SF ) ) {
		if ( ( determined_fsw_flags & FSW_IE ) && !( determined_fsw_flags & FSW_SF ) && ( state.cpu->fpu.fpu_control_word & FCW_IM ) ) {
			result = std::numeric_limits<float80_t>::quiet_NaN ( ); // Use standard NaN
			effect.push_to_changes ( state, "FMUL: Masked #IE, setting result to QNaN" );
		}

		if ( !( determined_fsw_flags & FSW_SF ) ) {
			state.cpu->fpu.fpu_stack [ destination_phys_idx ] = result;
			state.set_fpu_tag ( destination_phys_idx, state.classify_fpu_operand ( result ) );
			effect.modified_regs.insert ( static_cast< x86_reg >( X86_REG_ST0 + destination_sti ) );
		}
	}


	if ( pop_stack && !( state.cpu->fpu.fpu_status_word & FSW_ES ) ) {
		state.set_fpu_tag ( st0_phys_idx, FPU_TAG_EMPTY );
		state.cpu->fpu.fpu_top = ( state.cpu->fpu.fpu_top + 1 ) % 8;
		state.update_fsw_top ( );
		effect.modified_regs.insert ( X86_REG_ST0 );
	}


	if ( state.options.enable_logging ) {
		double log_op1 = operand1.convert_to<double> ( );
		double log_op2 = operand2.convert_to<double> ( );
		double log_res = result.convert_to<double> ( );
		effect.push_to_changes ( state, std::format ( "FMUL{} -> ST({}), Op1={}, Op2={}, Result={}, FSW=0x{:04x}",
														 pop_stack ? "P" : "", destination_sti, log_op1, log_op2, log_res, state.cpu->fpu.fpu_status_word ) );
	}
}


void fnstcw ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );

	if ( ops [ 0 ].type != X86_OP_MEM ) {
		effect.push_to_changes ( state, "FNSTCW: Operand must be a 16-bit memory location" );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t addr = helpers::calculate_mem_addr ( ops [ 0 ], instr, state );

	uint16_t control_word = state.cpu->fpu.fpu_control_word;

	if ( state.is_within_stack_bounds ( addr, 2 ) ) {
		state.set_stack ( addr, control_word, effect, 2 );
	}
	else {
		state.set_memory ( addr, control_word, 2, effect );
	}

	effect.push_to_changes ( state, std::format ( "FNSTCW: Stored FPU control word 0x{:04x} to [0x{:016x}]", control_word, addr ) );
}


void helpers::bind_fpu ( ) {
	BIND ( addss );
	BIND ( cmpss );
	BIND ( subss );
	BIND ( mulss );
	BIND ( divss );
	BIND ( sqrtss );
	BIND ( sqrtsd );
	BIND ( movss );
	BIND ( cvtss2si );
	BIND ( minss );
	BIND ( maxss );
	BIND ( comiss );
	BIND ( roundss );
	BIND ( rcpss );
	BIND ( rsqrtss );
	BIND ( ucomiss );
	BIND ( cvtsi2ss );
	BIND ( cvttss2si );
	BIND ( cvtss2sd );
	BIND ( cvtsd2ss );
	BIND ( andps );
	BIND ( orps );
	BIND ( xorps );
	BIND ( movhlps );
	BIND ( unpcklps );
	BIND ( cvtsi2sd );
	BIND ( mulsd );
	BIND ( comisd );

	BIND ( ldmxcsr );
	BIND ( stmxcsr );

	BIND ( fld );
	BIND ( fprem );
	BIND ( fstp );
	BIND ( ffree );
	BIND ( fincstp );
	BIND ( fmul );
	BIND2 ( fmulp, fmul );
	BIND ( fnstcw );
}
#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;
/// ADD - Add
void handlers::add ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t ua = a & mask;
	const uint64_t ub = b & mask;
	const uint64_t res = ( ua + ub ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sb = SIGN_EXTEND(ub, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.CF = res < ua;
	flags.ZF = res == 0;
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( ua & 0xF ) + ( ub & 0xF ) ) > 0xF; // Carry from bit 3 to 4
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.OF = ( sa > 0 && sb > 0 && sres < 0 ) || ( sa < 0 && sb < 0 && sres > 0 );

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}
/// SUB - Sub
void handlers::sub ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t ua = a & mask;
	const uint64_t ub = b & mask;
	const uint64_t res = ( ua - ub ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sb = SIGN_EXTEND(ub, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.CF = ua < ub;
	flags.ZF = res == 0;
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0; // Even parity for low 8 bits
	flags.AF = ( ( ua ^ ub ^ res ) & 0x10 ) != 0; // Borrow from bit 3 to 4
	flags.SF = sres < 0;
	flags.OF = ( sa >= 0 && sb < 0 && sres < 0 ) || ( sa < 0 && sb >= 0 && sres >= 0 );

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// INC - Increment
void handlers::inc ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t ua = a & mask;
	const uint64_t res = ( ua + 1 ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.OF = ( sa >= 0 && sres < 0 );
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( ua & 0xF ) + 1 ) > 0xF;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// DEC - Decrement
void handlers::dec ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t ua = a & mask;
	const uint64_t res = ( ua - 1 ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.OF = ( sa < 0 && sres >= 0 );
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ua & 0xF ) == 0;

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

template <typename OpType, typename Func>
void multiply ( const iced::Instruction& instr, KUBERA& context, Func set_flags ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	Register low_reg, high_reg;
	switch ( op_size ) {
		case 1: low_reg = Register::AL; high_reg = Register::AH; break;
		case 2: low_reg = Register::AX; high_reg = Register::DX; break;
		case 4: low_reg = Register::EAX; high_reg = Register::EDX; break;
		case 8: low_reg = Register::RAX; high_reg = Register::RDX; break;
		default: UNREACHABLE();
	}

	const uint64_t acc_val = context.get_reg ( low_reg, op_size );
	const uint128_t full_res = 
		uint128_t ( static_cast< OpType >( acc_val ) ) * uint128_t ( static_cast< OpType >( src_val ) );

	const uint64_t low_res = static_cast< uint64_t >( full_res & mask );
	const uint64_t high_res = static_cast< uint64_t >( full_res >> ( op_size * 8 ) );

	auto& flags = context.get_flags ( );
	set_flags ( flags, low_res, high_res, op_size );

	context.set_reg ( low_reg, low_res, op_size );
	context.set_reg ( high_reg, high_res, op_size );
}

/// MUL - Multiply
void handlers::mul ( const iced::Instruction& instr, KUBERA& context ) {
	multiply<uint64_t> ( instr, context, [ ] ( auto& flags, uint64_t low_res, uint64_t high_res, size_t op_size )
	{
		flags.CF = flags.OF = ( high_res != 0 );
	} );
}

template <size_t OpCount>
void imul_handler(const iced::Instruction& instr, KUBERA& context);

template <>
void imul_handler<1>(const iced::Instruction& instr, KUBERA& context) {
    const size_t op_size = instr.op0_size();
    const int64_t src_val = static_cast<int64_t>(helpers::get_operand_value<uint64_t>(instr, 0u, context));
    const uint64_t mask = GET_OPERAND_MASK(op_size);

    Register low_reg, high_reg;
    switch (op_size) {
        case 1: low_reg = Register::AL; high_reg = Register::AH; break;
        case 2: low_reg = Register::AX; high_reg = Register::DX; break;
        case 4: low_reg = Register::EAX; high_reg = Register::EDX; break;
        case 8: low_reg = Register::RAX; high_reg = Register::RDX; break;
        default: UNREACHABLE();
    }

    const int64_t acc_val = static_cast<int64_t>(context.get_reg(low_reg, op_size));
    const int128_t full_res = static_cast<int128_t>(acc_val) * static_cast<int128_t>(src_val);

    const uint64_t low_res = static_cast<uint64_t>(full_res);
    const uint64_t high_res = static_cast<uint64_t>(full_res >> (op_size * 8));

    context.set_reg(low_reg, low_res, op_size);
    context.set_reg(high_reg, high_res, op_size);

    auto& flags = context.get_flags();
    const int64_t sext_low = SIGN_EXTEND(low_res & mask, op_size);
    flags.CF = flags.OF = !(sext_low == static_cast<int64_t>(full_res));
}

template <>
void imul_handler<2>(const iced::Instruction& instr, KUBERA& context) {
    const size_t op_size = instr.op0_size();
    const int64_t src1_val = static_cast<int64_t>(helpers::get_operand_value<uint64_t>(instr, 0u, context));
    const int64_t src2_val = static_cast<int64_t>(helpers::get_operand_value<uint64_t>(instr, 1u, context));
    const uint64_t mask = GET_OPERAND_MASK(op_size);

    const int128_t res128 = static_cast<int128_t>(src1_val) * static_cast<int128_t>(src2_val);
    const uint64_t res64 = static_cast<uint64_t>(res128);

    helpers::set_operand_value<uint64_t>(instr, 0u, res64, context);

    auto& flags = context.get_flags();
    const int64_t sext_res = SIGN_EXTEND(res64 & mask, op_size);
    flags.CF = flags.OF = !(sext_res == static_cast<int64_t>(res128));
}

/// IMUL - Signed multiply
void handlers::imul(const iced::Instruction& instr, KUBERA& context) {
    switch (instr.op_count()) {
        case 1: return imul_handler<1>(instr, context);
        case 2: return imul_handler<2>(instr, context);
				default:
					UNREACHABLE ( );
    }
}

template <typename DivType, typename QuotType, typename Func>
void divide ( const iced::Instruction& instr, KUBERA& context, Func build_dividend ) {
	const size_t op_size = instr.op0_size ( );
	const DivType divisor = static_cast< DivType >( helpers::get_operand_value<uint64_t> ( instr, 0u, context ) );

	Register quotient_reg, remainder_reg;
	switch ( op_size ) {
		case 1: quotient_reg = Register::AL; remainder_reg = Register::AH; break;
		case 2: quotient_reg = Register::AX; remainder_reg = Register::DX; break;
		case 4: quotient_reg = Register::EAX; remainder_reg = Register::EDX; break;
		case 8: quotient_reg = Register::RAX; remainder_reg = Register::RDX; break;
		default: UNREACHABLE();
	}

	auto dividend = build_dividend ( context, op_size, quotient_reg, remainder_reg );

	QuotType quotient_res = 0, remainder_res = 0;
	bool overflow = false;
	if constexpr ( std::is_same_v<DivType, uint64_t> ) {
		overflow = helpers::divide_unsigned_boost ( dividend, divisor, op_size, quotient_res, remainder_res );
	}
	else {
		overflow = helpers::divide_signed_boost ( dividend, divisor, op_size, quotient_res, remainder_res );
	}

	if ( overflow ) {
		// !TODO(exception)
	}

	context.set_reg ( quotient_reg, static_cast< uint64_t >( quotient_res ), op_size );
	context.set_reg ( remainder_reg, static_cast< uint64_t >( remainder_res ), op_size );
}

/// DIV - Divide
void handlers::div ( const iced::Instruction& instr, KUBERA& context ) {
	divide<uint64_t, uint64_t> ( instr, context, [ ] ( KUBERA& ctx, size_t op_size, Register quot_reg, Register rem_reg ) -> uint128_t
	{
		if ( op_size == 1 ) {
			return ctx.get_reg ( Register::AX, 2 );
		}
		return ( uint128_t ( ctx.get_reg ( rem_reg, op_size ) ) << ( op_size * 8 ) ) | ctx.get_reg ( quot_reg, op_size );
	} );
}

/// IDIV - Signed divide
void handlers::idiv ( const iced::Instruction& instr, KUBERA& context ) {
	divide<int64_t, int64_t> ( instr, context, [ ] ( KUBERA& ctx, size_t op_size, Register quot_reg, Register rem_reg ) -> int128_t
	{
		if ( op_size == 1 ) {
			return static_cast< int16_t >( ctx.get_reg ( Register::AX, 2 ) );
		}
		if ( op_size == 2 ) {
			uint16_t high = static_cast< uint16_t >( ctx.get_reg ( rem_reg, op_size ) );
			uint16_t low = static_cast< uint16_t >( ctx.get_reg ( quot_reg, op_size ) );
			return ( static_cast< int64_t >( high ) << 16 ) | low;
		}
		if ( op_size == 4 ) {
			uint32_t high = static_cast< uint32_t >( ctx.get_reg ( rem_reg, op_size ) );
			uint32_t low = static_cast< uint32_t >( ctx.get_reg ( quot_reg, op_size ) );
			return ( static_cast< int64_t >( high ) << 32 ) | low;
		}
		return ( int128_t ( ctx.get_reg ( rem_reg, 8 ) ) << 64 ) | ctx.get_reg ( quot_reg, 8 );
	} );
}

template <typename Func>
void add_sub_with_carry ( const iced::Instruction& instr, KUBERA& context, Func operation ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t ua = a & mask;
	const uint64_t ub = b & mask;
	const uint64_t carry = context.get_flags ( ).CF ? 1 : 0;
	const uint64_t res = operation ( ua, ub, carry ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sb = SIGN_EXTEND(ub, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.CF = operation ( ua, ub, carry ) > mask;
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( operation ( ua & 0xF, ub & 0xF, carry ) & 0x10 ) != 0;
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.OF = ( sa > 0 && sb > 0 && sres < 0 ) || ( sa < 0 && sb < 0 && sres > 0 );

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// ADC-Add With Carry
/// Adds the source operand, destination operand, and carry flag, storing the result in the destination and updating flags.
void handlers::adc ( const iced::Instruction& instr, KUBERA& context ) {
	add_sub_with_carry ( instr, context, [ ] ( uint64_t ua, uint64_t ub, uint64_t carry )
	{
		return ua + ub + carry;
	} );
}

/// SBB-Integer Subtraction With Borrow
/// Subtracts the source operand and carry flag from the destination operand, storing the result in the destination and updating flags.
void handlers::sbb ( const iced::Instruction& instr, KUBERA& context ) {
	add_sub_with_carry ( instr, context, [ ] ( uint64_t ua, uint64_t ub, uint64_t carry )
	{
		return ua - ub - carry;
	} );
}

/// NEG-Two's Complement Negation
/// Negates the destination operand by computing its two's complement, storing the result and updating flags.
void handlers::neg ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t ua = a & mask;
	const uint64_t res = ( ~ua + 1 ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.CF = ( ua != 0 );
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ua & 0xF ) != 0;
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	const uint64_t min_signed = static_cast< uint64_t >( 1ULL << ( op_size * 8 - 1 ) );
	flags.OF = ( ua == min_signed );

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
}

/// XADD-Exchange and Add
/// Exchanges the destination and source operands, adds them, stores the sum in the destination, and updates flags.
void handlers::xadd ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t a = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t b = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );

	const uint64_t ua = a & mask;
	const uint64_t ub = b & mask;
	const uint64_t res = ( ua + ub ) & mask;

	const int64_t sa = SIGN_EXTEND(ua, op_size);
	const int64_t sb = SIGN_EXTEND(ub, op_size);
	const int64_t sres = SIGN_EXTEND(res, op_size);

	auto& flags = context.get_flags ( );
	flags.CF = ( res < ua );
	flags.ZF = ( res == 0 );
	flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
	flags.AF = ( ( ua & 0xF ) + ( ub & 0xF ) ) > 0xF;
	flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
	flags.OF = ( sa > 0 && sb > 0 && sres < 0 ) || ( sa < 0 && sb < 0 && sres > 0 );

	helpers::set_operand_value<uint64_t> ( instr, 0u, res, context );
	helpers::set_operand_value<uint64_t> ( instr, 1u, ua, context );
}

/// CDQ-Convert Doubleword to Quadword
/// Sign-extends EAX into EDX:EAX, setting EDX to 0xFFFFFFFF if EAX is negative, or 0 otherwise.
void handlers::cdq ( const iced::Instruction& instr, KUBERA& context ) {
	const auto eax = context.get_reg ( Register::EAX, 4 );
	int32_t eax_val = static_cast< int32_t > ( eax );
	uint32_t edx_val = ( eax_val < 0 ) ? 0xFFFFFFFF : 0;
	context.set_reg ( Register::EDX, edx_val, 4 );
}

/// CDQE-Convert Doubleword to Quadword Extended
/// Sign-extends EAX into RAX.
void handlers::cdqe ( const iced::Instruction& instr, KUBERA& context ) {
	const auto eax = context.get_reg ( Register::EAX, 4 );
	int32_t eax_val = static_cast< int32_t > ( eax );
	int64_t sign_extended = static_cast< int64_t > ( eax_val );
	context.set_reg ( Register::RAX, sign_extended, 8 );
}

/// CWD-Convert Word to Doubleword
/// Sign-extends AX into EAX and DX, setting DX to 0xFFFF if AX is negative, or 0 otherwise, and EAX to sign-extended AX.
void handlers::cwd ( const iced::Instruction& instr, KUBERA& context ) {
	const auto ax = context.get_reg ( Register::AX, 2 );
	int16_t ax_val = static_cast< int16_t >( ax );
	int32_t eax_val = static_cast< int32_t >( ax_val );
	uint16_t dx_val = ( ax_val < 0 ) ? 0xFFFF : 0;
	context.set_reg ( Register::EAX, eax_val, 4 );
	context.set_reg ( Register::DX, dx_val, 2 );
}

/// CQO-Convert Quadword to Octoword
/// Sign-extends RAX into RDX:RAX, setting RDX to 0xFFFFFFFFFFFFFFFF if RAX is negative, or 0 otherwise.
void handlers::cqo ( const iced::Instruction& instr, KUBERA& context ) {
	auto rax = context.get_reg ( Register::RAX, 8 );
	uint64_t rax_val = rax;
	uint64_t rdx_val = ( rax_val >> 63 ) ? 0xFFFFFFFFFFFFFFFFULL : 0;
	context.set_reg ( Register::RAX, rax_val, 8 );
	context.set_reg ( Register::RDX, rdx_val, 8 );
}

/// CWDE-Convert Word to Doubleword Extended
/// Sign-extends AX into EAX.
void handlers::cwde ( const iced::Instruction& instr, KUBERA& context ) {
	auto ax = context.get_reg ( Register::AX, 2 );
	int16_t ax_val = static_cast< int16_t >( ax );
	int32_t eax_val = static_cast< int32_t >( ax_val );
	context.set_reg ( Register::EAX, eax_val, 4 );
}

/// CBW-Convert Byte to Word
/// Sign-extends AL into AX.
void handlers::cbw ( const iced::Instruction& instr, KUBERA& context ) {
	auto al = context.get_reg ( Register::AL, 1 );
	int8_t al_val = static_cast< int8_t >( al );
	int16_t ax_val = static_cast< int16_t >( al_val );
	context.set_reg ( Register::AX, ax_val, 2 );
}
#include "../KUBERA.hpp"
#include "../emulator.hpp"
#include <print>

using namespace kubera;
std::array<KubRegister, static_cast< std::size_t > ( Register::DontUse0 )> reg_map;
std::array<int, static_cast< std::size_t > ( Register::DontUse0 )> avx_map {};

KubRegister map_register ( Register reg ) {
	return reg_map [ static_cast< size_t >( reg ) ];
}

void kubera::KUBERA::handle_ip_switch ( uint64_t target ) {
	if ( !memory->check ( target, 1, PageProtection::EXEC ) ) {
		return;
	}

	this->rip ( ) = target;
}

uint64_t KUBERA::get_access_mask ( Register reg, size_t size ) const noexcept {
	switch ( size ) {
		case 8:
		{
			return 0xFFFFFFFFFFFFFFFFULL;
		}
		case 4:
		{
			return 0x00000000FFFFFFFFULL;
		}
		case 2:
		{
			return 0x000000000000FFFFULL;
		}
		case 1:
		{
			if ( reg == Register::CH || reg == Register::DH || reg == Register::BH || reg == Register::AH ) {
				return 0x000000000000FF00ULL;
			}
			return 0x00000000000000FFULL;
		}
		default: return 0x0000000000000000ULL;
	}
}

uint8_t KUBERA::get_access_shift ( Register reg, size_t size ) const noexcept {
	if ( size != 1 ) {
		return 0;
	}
	if ( reg == Register::AH || reg == Register::BH || reg == Register::CH || reg == Register::DH ) {
		return 8;
	}

	return 0;
}

uint64_t KUBERA::get_rflags ( ) const noexcept {
	return cpu->rflags.value;
}

uint64_t KUBERA::get_reg ( Register reg, size_t size ) const noexcept {
	if ( reg == Register::RIP ) {
		return rip ( );
	}

	const auto full_reg = map_register ( reg );
	const auto concrete_full = cpu->registers [ full_reg ];
	const auto access_mask = get_access_mask ( reg, size );
	const auto shift = get_access_shift ( reg, size );
	const auto extracted_value = ( concrete_full & access_mask ) >> shift;

	return extracted_value;
}

void KUBERA::set_rflags ( uint64_t rflags ) noexcept {
	auto& flags = cpu->rflags;
	auto old_flags = flags.value;

	flags.CF = ( rflags >> 0 ) & 1;
	flags.PF = ( rflags >> 2 ) & 1;
	flags.AF = ( rflags >> 4 ) & 1;
	flags.ZF = ( rflags >> 6 ) & 1;
	flags.SF = ( rflags >> 7 ) & 1;
	flags.TF = ( rflags >> 8 ) & 1;
	flags.DF = ( rflags >> 10 ) & 1;
	flags.OF = ( rflags >> 11 ) & 1;
	flags.AC = ( rflags >> 18 ) & 1;

	if ( cpu->current_privilege_level == 0 ) {
		if ( cpu->current_privilege_level <= flags.IOPL ) {
			uint64_t old_IF = flags.IF;
			flags.IF = ( rflags >> 9 ) & 1;
		}

		flags.IOPL = ( rflags >> 12 ) & 3;
		flags.NT = ( rflags >> 14 ) & 1;
		flags.RF = ( rflags >> 16 ) & 1;
		flags.VM = ( rflags >> 17 ) & 1;
		flags.VIF = ( rflags >> 19 ) & 1;
		flags.VIP = ( rflags >> 20 ) & 1;
	}
}

void KUBERA::set_reg(Register reg, uint64_t value_to_set, size_t size) {
    const auto full_reg = map_register(reg);

    if (size == 4 && (full_reg >= KubRegister::RAX && full_reg <= KubRegister::R15)) {
        // 32-bit operations zero the upper 32 bits of the destination register.
        cpu->registers[full_reg] = value_to_set & 0xFFFFFFFFULL;
    } else if (size == 8) {
        // 64-bit operations overwrite the entire register.
        cpu->registers[full_reg] = value_to_set;
    }
    else {
        // 8-bit and 16-bit operations merge with the destination.
        const auto old_full_concrete = cpu->registers[full_reg];
        const auto access_mask = get_access_mask(reg, size);
        const auto shift = get_access_shift(reg, size);
        const uint64_t size_mask = GET_OPERAND_MASK(size);

        const uint64_t shifted_value = (value_to_set & size_mask) << shift;
        const uint64_t new_full_concrete = (old_full_concrete & ~access_mask) | (shifted_value & access_mask);

        cpu->registers[full_reg] = new_full_concrete;
    }
}

bool KUBERA::is_within_stack_bounds ( uint64_t address, size_t size ) const noexcept {
	const auto stack_base_addr = cpu->stack_base;
	const auto stack_top = stack_base_addr + cpu->stack_size;
	const auto stack_bot = stack_base_addr;
	return address >= stack_bot && address <= stack_top - size;
}

void map_gpr ( ) {
	reg_map [ ( size_t ) Register::RAX ] = KubRegister::RAX;
	reg_map [ ( size_t ) Register::EAX ] = KubRegister::RAX;
	reg_map [ ( size_t ) Register::AX ] = KubRegister::RAX;
	reg_map [ ( size_t ) Register::AH ] = KubRegister::RAX;
	reg_map [ ( size_t ) Register::AL ] = KubRegister::RAX;
	reg_map [ ( size_t ) Register::RBX ] = KubRegister::RBX;
	reg_map [ ( size_t ) Register::EBX ] = KubRegister::RBX;
	reg_map [ ( size_t ) Register::BX ] = KubRegister::RBX;
	reg_map [ ( size_t ) Register::BH ] = KubRegister::RBX;
	reg_map [ ( size_t ) Register::BL ] = KubRegister::RBX;
	reg_map [ ( size_t ) Register::RCX ] = KubRegister::RCX;
	reg_map [ ( size_t ) Register::ECX ] = KubRegister::RCX;
	reg_map [ ( size_t ) Register::CX ] = KubRegister::RCX;
	reg_map [ ( size_t ) Register::CH ] = KubRegister::RCX;
	reg_map [ ( size_t ) Register::CL ] = KubRegister::RCX;
	reg_map [ ( size_t ) Register::RDX ] = KubRegister::RDX;
	reg_map [ ( size_t ) Register::EDX ] = KubRegister::RDX;
	reg_map [ ( size_t ) Register::DX ] = KubRegister::RDX;
	reg_map [ ( size_t ) Register::DH ] = KubRegister::RDX;
	reg_map [ ( size_t ) Register::DL ] = KubRegister::RDX;
	reg_map [ ( size_t ) Register::RSI ] = KubRegister::RSI;
	reg_map [ ( size_t ) Register::ESI ] = KubRegister::RSI;
	reg_map [ ( size_t ) Register::SI ] = KubRegister::RSI;
	reg_map [ ( size_t ) Register::SIL ] = KubRegister::RSI;
	reg_map [ ( size_t ) Register::RDI ] = KubRegister::RDI;
	reg_map [ ( size_t ) Register::EDI ] = KubRegister::RDI;
	reg_map [ ( size_t ) Register::DI ] = KubRegister::RDI;
	reg_map [ ( size_t ) Register::DIL ] = KubRegister::RDI;
	reg_map [ ( size_t ) Register::RBP ] = KubRegister::RBP;
	reg_map [ ( size_t ) Register::EBP ] = KubRegister::RBP;
	reg_map [ ( size_t ) Register::BP ] = KubRegister::RBP;
	reg_map [ ( size_t ) Register::BPL ] = KubRegister::RBP;
	reg_map [ ( size_t ) Register::RSP ] = KubRegister::RSP;
	reg_map [ ( size_t ) Register::ESP ] = KubRegister::RSP;
	reg_map [ ( size_t ) Register::SP ] = KubRegister::RSP;
	reg_map [ ( size_t ) Register::SPL ] = KubRegister::RSP;
	reg_map [ ( size_t ) Register::R8 ] = KubRegister::R8;
	reg_map [ ( size_t ) Register::R8D ] = KubRegister::R8;
	reg_map [ ( size_t ) Register::R8W ] = KubRegister::R8;
	reg_map [ ( size_t ) Register::R8L ] = KubRegister::R8;
	reg_map [ ( size_t ) Register::R9 ] = KubRegister::R9;
	reg_map [ ( size_t ) Register::R9D ] = KubRegister::R9;
	reg_map [ ( size_t ) Register::R9W ] = KubRegister::R9;
	reg_map [ ( size_t ) Register::R9L ] = KubRegister::R9;
	reg_map [ ( size_t ) Register::R10 ] = KubRegister::R10;
	reg_map [ ( size_t ) Register::R10D ] = KubRegister::R10;
	reg_map [ ( size_t ) Register::R10W ] = KubRegister::R10;
	reg_map [ ( size_t ) Register::R10L ] = KubRegister::R10;
	reg_map [ ( size_t ) Register::R11 ] = KubRegister::R11;
	reg_map [ ( size_t ) Register::R11D ] = KubRegister::R11;
	reg_map [ ( size_t ) Register::R11W ] = KubRegister::R11;
	reg_map [ ( size_t ) Register::R11L ] = KubRegister::R11;
	reg_map [ ( size_t ) Register::R12 ] = KubRegister::R12;
	reg_map [ ( size_t ) Register::R12D ] = KubRegister::R12;
	reg_map [ ( size_t ) Register::R12W ] = KubRegister::R12;
	reg_map [ ( size_t ) Register::R12L ] = KubRegister::R12;
	reg_map [ ( size_t ) Register::R13 ] = KubRegister::R13;
	reg_map [ ( size_t ) Register::R13D ] = KubRegister::R13;
	reg_map [ ( size_t ) Register::R13W ] = KubRegister::R13;
	reg_map [ ( size_t ) Register::R13L ] = KubRegister::R13;
	reg_map [ ( size_t ) Register::R14 ] = KubRegister::R14;
	reg_map [ ( size_t ) Register::R14D ] = KubRegister::R14;
	reg_map [ ( size_t ) Register::R14W ] = KubRegister::R14;
	reg_map [ ( size_t ) Register::R14L ] = KubRegister::R14;
	reg_map [ ( size_t ) Register::R15 ] = KubRegister::R15;
	reg_map [ ( size_t ) Register::R15D ] = KubRegister::R15;
	reg_map [ ( size_t ) Register::R15W ] = KubRegister::R15;
	reg_map [ ( size_t ) Register::R15L ] = KubRegister::R15;
	reg_map [ ( size_t ) Register::RIP ] = KubRegister::RIP;
	reg_map [ ( size_t ) Register::EIP ] = KubRegister::RIP;
	reg_map [ ( size_t ) Register::DR0 ] = KubRegister::DR0;
	reg_map [ ( size_t ) Register::DR1 ] = KubRegister::DR1;
	reg_map [ ( size_t ) Register::DR2 ] = KubRegister::DR2;
	reg_map [ ( size_t ) Register::DR3 ] = KubRegister::DR3;
	reg_map [ ( size_t ) Register::DR4 ] = KubRegister::DR4;
	reg_map [ ( size_t ) Register::DR5 ] = KubRegister::DR5;
	reg_map [ ( size_t ) Register::DR6 ] = KubRegister::DR6;
	reg_map [ ( size_t ) Register::DR7 ] = KubRegister::DR7;
	reg_map [ ( size_t ) Register::CR0 ] = KubRegister::CR0;
	reg_map [ ( size_t ) Register::CR2 ] = KubRegister::CR2;
	reg_map [ ( size_t ) Register::CR3 ] = KubRegister::CR3;
	reg_map [ ( size_t ) Register::CR4 ] = KubRegister::CR4;
	reg_map [ ( size_t ) Register::CR8 ] = KubRegister::CR8;
	reg_map [ ( size_t ) Register::CS ] = KubRegister::CS;
	reg_map [ ( size_t ) Register::DS ] = KubRegister::DS;
	reg_map [ ( size_t ) Register::ES ] = KubRegister::ES;
	reg_map [ ( size_t ) Register::FS ] = KubRegister::FS;
	reg_map [ ( size_t ) Register::GS ] = KubRegister::GS;
	reg_map [ ( size_t ) Register::SS ] = KubRegister::SS;
}

void map_avx ( ) {
	std::array<Register, 3> bases { Register::XMM0, Register::YMM0, Register::ZMM0 };
	for ( const auto base : bases ) {
		for ( auto i = 0u; i < 31; ++i ) {
			avx_map [ static_cast< size_t > ( base ) + i ] = i;
		}
	}
};

inline int countl_zero_u64 ( uint64_t val ) {
	unsigned long leading_zero;
	if ( _BitScanReverse64 ( &leading_zero, val ) )
		return 63 - leading_zero;
	else
		return 64;
}

float80_t from_ieee754_80 ( std::pair<uint64_t, uint16_t> bits ) {
	const uint64_t mantissa = bits.first;
	const uint16_t sign_exp = bits.second;

	const bool sign = ( sign_exp >> 15 ) & 1;
	const uint16_t biased_exp = sign_exp & 0x7FFF;
	const int16_t exponent_bias = 16383;

	float80_t result;
	// Get a reference to the backend to manipulate its internal state.
	auto& backend = result.backend ( );

	// Case 1: NaN or Infinity (exponent is all 1s)
	if ( biased_exp == 0x7FFF ) {
		// According to Intel's spec, I=1, F=0 is Infinity. Other combinations are NaNs.
		if ( mantissa == 0x8000000000000000ULL ) { // Infinity
			backend.exponent ( ) = float80_t::backend_type::exponent_infinity;
			backend.sign ( ) = sign;
		}
		else { // NaN
			backend.exponent ( ) = float80_t::backend_type::exponent_nan;
			backend.sign ( ) = false; // NaNs are unsigned in cpp_bin_float
		}
		// For special values, the 'bits' member is 0.
		return result;
	}

	// Case 2: Zero
	if ( biased_exp == 0 && mantissa == 0 ) {
		backend.exponent ( ) = float80_t::backend_type::exponent_zero;
		backend.sign ( ) = sign;
		return result;
	}

	// Case 3: Finite non-zero numbers (Normal, Denormal, Pseudo-denormal)
	backend.sign ( ) = sign;

	const bool is_normal = ( mantissa & 0x8000000000000000ULL ) != 0;

	// Optimization for standard normal numbers, which are already normalized.
	if ( biased_exp > 0 && is_normal ) {
		backend.exponent ( ) = biased_exp - exponent_bias;
		backend.bits ( ) = mantissa;
	}
	else {
		// Denormals (E=0, I=0, F!=0) and Pseudo-denormals (E>0, I=0)
		// require normalization for cpp_bin_float.

		// Determine the effective exponent before normalization.
		// For denormals (E=0), the exponent is fixed at 1 - bias.
		const int16_t effective_exp_base = ( biased_exp == 0 )
			? static_cast< int16_t >( 1 - exponent_bias )
			: static_cast< int16_t >( biased_exp - exponent_bias );

		if ( mantissa == 0 ) { // Should not happen if we already checked for zero
			throw std::logic_error ( "Invalid finite number with zero mantissa." );
		}

		// Find how many bits to shift left to normalize the mantissa.
		const int shift = countl_zero_u64 ( mantissa );

		// Normalize the mantissa by shifting its MSB to bit 63.
		backend.bits ( ) = mantissa << shift;

		// Adjust the exponent to compensate for the shift.
		backend.exponent ( ) = effective_exp_base - shift;
	}

	return result;
}

float80_t from_ieee754_80_bytes ( const uint8_t bytes [ 10 ] ) {
	// Safely construct integers from bytes (assumes little-endian source)
	uint64_t mantissa = 0;
	for ( int i = 7; i >= 0; --i ) {
		mantissa = ( mantissa << 8 ) | bytes [ i ];
	}
	uint16_t sign_exp = ( static_cast< uint16_t >( bytes [ 9 ] ) << 8 ) | bytes [ 8 ];

	return from_ieee754_80 ( { mantissa, sign_exp } );
}

float80_t KUBERA::read_type_float80_t ( uint64_t address ) const {
	uint64_t p0 = memory->read<uint64_t> ( address + 0 );
	uint16_t p1 = memory->read<uint16_t> ( address + 8 );

	alignas( 16 ) uint8_t temp [ 10 ];
	std::memcpy ( temp, &p0, 8 );
	std::memcpy ( temp + 8, &p1, 2 );

	return from_ieee754_80_bytes ( temp );
}

uint128_t KUBERA::get_xmm_raw ( Register _reg ) const {
	auto reg = avx_map [ static_cast< int >( _reg ) ];
	uint512_t value = ( *cpu->sse_registers ) [ reg ];
	return value.convert_to<uint128_t> ( );
}

void KUBERA::set_xmm_raw ( Register _reg, const uint128_t& value ) {
	auto reg = avx_map [ static_cast< int >( _reg ) ];
	( *cpu->sse_registers ) [ reg ] = value;
}

uint256_t KUBERA::get_ymm_raw ( Register _reg ) const {
	auto reg = avx_map [ static_cast< int >( _reg ) ];
	uint512_t value = ( *cpu->sse_registers ) [ reg ];
	return value.convert_to<uint256_t> ( );
}

void KUBERA::set_ymm_raw ( Register _reg, const uint256_t& value ) {
	auto reg = avx_map [ static_cast< int >( _reg ) ];
	( *cpu->sse_registers ) [ reg ] = value;
}

uint512_t KUBERA::get_zmm_raw ( Register _reg ) const {
	auto reg = avx_map [ static_cast< int >( _reg ) ];
	uint512_t value = ( *cpu->sse_registers ) [ reg ];
	return value;
}

void KUBERA::set_zmm_raw ( Register _reg, const uint512_t& value ) {
	auto reg = avx_map [ static_cast< int >( _reg ) ];
	( *cpu->sse_registers ) [ reg ] = value;
}

float KUBERA::get_xmm_float ( Register reg ) const {
	uint128_t raw = get_xmm_raw ( reg );
	uint32_t low_bits = static_cast< uint32_t >( raw & 0xFFFFFFFF );
	return std::bit_cast< float >( low_bits );
}

void KUBERA::set_xmm_float ( Register reg, float value ) {
	uint128_t current_raw = get_xmm_raw ( reg );
	uint32_t new_low_bits = std::bit_cast< uint32_t >( value );
	current_raw = ( current_raw & ~uint128_t ( 0xFFFFFFFF ) ) | uint128_t ( new_low_bits );
	set_xmm_raw ( reg, current_raw );
}

double KUBERA::get_xmm_double ( Register reg ) const {
	uint128_t raw = get_xmm_raw ( reg );
	uint64_t low_bits = static_cast< uint64_t >( raw & 0xFFFFFFFFFFFFFFFF );
	return std::bit_cast< double >( low_bits );
}

void KUBERA::set_xmm_double ( Register reg, double value ) {
	uint128_t current_raw = get_xmm_raw ( reg );
	uint64_t new_low_bits = std::bit_cast< uint64_t >( value );
	current_raw = ( current_raw & ~uint128_t ( 0xFFFFFFFFFFFFFFFF ) ) | uint128_t ( new_low_bits );
	set_xmm_raw ( reg, current_raw );
}

void unsupported_instruction ( const iced::Instruction& instr, KUBERA& context ) {
	std::println ( "[KUBERA] Unsupported instruction {}, skipping.", instr.to_string ( ) );
}

#define SET_HANDLER(x, y) instruction_dispatch_table->at ( static_cast< size_t >( x) ) = y
void map_handlers ( ) {
	SET_HANDLER ( Mnemonic::Add, handlers::add );
	SET_HANDLER ( Mnemonic::Sub, handlers::sub );
	SET_HANDLER ( Mnemonic::Inc, handlers::inc );
	SET_HANDLER ( Mnemonic::Dec, handlers::dec );
	SET_HANDLER ( Mnemonic::Mul, handlers::mul );
	SET_HANDLER ( Mnemonic::Imul, handlers::imul );
	SET_HANDLER ( Mnemonic::Div, handlers::div );
	SET_HANDLER ( Mnemonic::Idiv, handlers::idiv );
	SET_HANDLER ( Mnemonic::Adc, handlers::adc );
	SET_HANDLER ( Mnemonic::Sbb, handlers::sbb );
	SET_HANDLER ( Mnemonic::Neg, handlers::neg );
	SET_HANDLER ( Mnemonic::Xadd, handlers::xadd );
	SET_HANDLER ( Mnemonic::Cdq, handlers::cdq );
	SET_HANDLER ( Mnemonic::Cdqe, handlers::cdqe );
	SET_HANDLER ( Mnemonic::Cwd, handlers::cwd );
	SET_HANDLER ( Mnemonic::Cqo, handlers::cqo );
	SET_HANDLER ( Mnemonic::Cwde, handlers::cwde );
	SET_HANDLER ( Mnemonic::Cbw, handlers::cbw );
	SET_HANDLER ( Mnemonic::And, handlers::and_ );
	SET_HANDLER ( Mnemonic::Or, handlers::or_ );
	SET_HANDLER ( Mnemonic::Xor, handlers::xor_ );
	SET_HANDLER ( Mnemonic::Not, handlers::not_ );
	SET_HANDLER ( Mnemonic::Shl, handlers::shl );
	SET_HANDLER ( Mnemonic::Sal, handlers::sal );
	SET_HANDLER ( Mnemonic::Sar, handlers::sar );
	SET_HANDLER ( Mnemonic::Shr, handlers::shr );
	SET_HANDLER ( Mnemonic::Shld, handlers::shld );
	SET_HANDLER ( Mnemonic::Shrd, handlers::shrd );
	SET_HANDLER ( Mnemonic::Rol, handlers::rol );
	SET_HANDLER ( Mnemonic::Ror, handlers::ror );
	SET_HANDLER ( Mnemonic::Rcl, handlers::rcl );
	SET_HANDLER ( Mnemonic::Rcr, handlers::rcr );
	SET_HANDLER ( Mnemonic::Cmovo, handlers::cmovo );
	SET_HANDLER ( Mnemonic::Cmovb, handlers::cmovb );
	SET_HANDLER ( Mnemonic::Cmovge, handlers::cmovnl );
	SET_HANDLER ( Mnemonic::Cmovbe, handlers::cmovbe );
	SET_HANDLER ( Mnemonic::Cmove, handlers::cmovz );
	SET_HANDLER ( Mnemonic::Cmovle, handlers::cmovle );
	SET_HANDLER ( Mnemonic::Cmovl, handlers::cmovl );
	SET_HANDLER ( Mnemonic::Cmovnp, handlers::cmovnp );
	SET_HANDLER ( Mnemonic::Cmovns, handlers::cmovns );
	SET_HANDLER ( Mnemonic::Cmovp, handlers::cmovp );
	SET_HANDLER ( Mnemonic::Cmovae, handlers::cmovnb );
	SET_HANDLER ( Mnemonic::Cmovno, handlers::cmovno );
	SET_HANDLER ( Mnemonic::Cmovs, handlers::cmovs );
	SET_HANDLER ( Mnemonic::Cmovne, handlers::cmovnz );
	SET_HANDLER ( Mnemonic::Cmova, handlers::cmovnbe );
	SET_HANDLER ( Mnemonic::Cmovg, handlers::cmovnle );

	// Set Based on Condition Instructions
	SET_HANDLER ( Mnemonic::Setb, handlers::setb );
	SET_HANDLER ( Mnemonic::Setnp, handlers::setnp );
	SET_HANDLER ( Mnemonic::Sets, handlers::sets );
	SET_HANDLER ( Mnemonic::Setge, handlers::setnl );
	SET_HANDLER ( Mnemonic::Seto, handlers::seto );
	SET_HANDLER ( Mnemonic::Setbe, handlers::setbe );
	SET_HANDLER ( Mnemonic::Sete, handlers::setz );
	SET_HANDLER ( Mnemonic::Setae, handlers::setnb );
	SET_HANDLER ( Mnemonic::Setno, handlers::setno );
	SET_HANDLER ( Mnemonic::Setp, handlers::setp );
	SET_HANDLER ( Mnemonic::Setle, handlers::setle );
	SET_HANDLER ( Mnemonic::Setg, handlers::setnle );
	SET_HANDLER ( Mnemonic::Setns, handlers::setns );
	SET_HANDLER ( Mnemonic::Setl, handlers::setl );
	SET_HANDLER ( Mnemonic::Seta, handlers::setnbe );
	SET_HANDLER ( Mnemonic::Setne, handlers::setnz );

	// Bit Manipulation Instructions
	SET_HANDLER ( Mnemonic::Bzhi, handlers::bzhi );
	SET_HANDLER ( Mnemonic::Andn, handlers::andn );
	SET_HANDLER ( Mnemonic::Bextr, handlers::bextr );
	SET_HANDLER ( Mnemonic::Popcnt, handlers::popcnt );
	SET_HANDLER ( Mnemonic::Bswap, handlers::bswap );
	SET_HANDLER ( Mnemonic::Bt, handlers::bt );
	SET_HANDLER ( Mnemonic::Bts, handlers::bts );
	SET_HANDLER ( Mnemonic::Btr, handlers::btr );
	SET_HANDLER ( Mnemonic::Btc, handlers::btc );
	SET_HANDLER ( Mnemonic::Bsr, handlers::bsr );
	SET_HANDLER ( Mnemonic::Bsf, handlers::bsf );
	SET_HANDLER ( Mnemonic::Tzcnt, handlers::tzcnt );

	// Comparison and Test Instructions
	SET_HANDLER ( Mnemonic::Cmp, handlers::cmp );
	SET_HANDLER ( Mnemonic::Test, handlers::test );
	SET_HANDLER ( Mnemonic::Cmpxchg, handlers::cmpxchg );
	SET_HANDLER ( Mnemonic::Cmpxchg16b, handlers::cmpxchg16b );

	// Control Flow Instructions
	SET_HANDLER ( Mnemonic::Jmp, handlers::jmp );
	SET_HANDLER ( Mnemonic::Je, handlers::je );
	SET_HANDLER ( Mnemonic::Jne, handlers::jne );
	SET_HANDLER ( Mnemonic::Ja, handlers::jnbe );
	SET_HANDLER ( Mnemonic::Jg, handlers::jg );
	SET_HANDLER ( Mnemonic::Jl, handlers::jl );
	SET_HANDLER ( Mnemonic::Jae, handlers::jnb );
	SET_HANDLER ( Mnemonic::Jb, handlers::jb );
	SET_HANDLER ( Mnemonic::Jns, handlers::jns );
	SET_HANDLER ( Mnemonic::Jo, handlers::jo );
	SET_HANDLER ( Mnemonic::Jno, handlers::jno );
	SET_HANDLER ( Mnemonic::Jbe, handlers::jbe );
	SET_HANDLER ( Mnemonic::Js, handlers::js );
	SET_HANDLER ( Mnemonic::Ja, handlers::ja );
	SET_HANDLER ( Mnemonic::Jae, handlers::jae );
	SET_HANDLER ( Mnemonic::Jge, handlers::jge );
	SET_HANDLER ( Mnemonic::Jle, handlers::jle );
	SET_HANDLER ( Mnemonic::Jp, handlers::jp );
	SET_HANDLER ( Mnemonic::Jnp, handlers::jnp );
	SET_HANDLER ( Mnemonic::Jcxz, handlers::jcxz );
	SET_HANDLER ( Mnemonic::Jecxz, handlers::jecxz );
	SET_HANDLER ( Mnemonic::Jrcxz, handlers::jrcxz );
	SET_HANDLER ( Mnemonic::Call, handlers::call );
	SET_HANDLER ( Mnemonic::Ret, handlers::ret );
	SET_HANDLER ( Mnemonic::Iret, handlers::iret );
	SET_HANDLER ( Mnemonic::Iretd, handlers::iretd );
	SET_HANDLER ( Mnemonic::Iretq, handlers::iretq );

	// Stack and Frame Instructions
	SET_HANDLER ( Mnemonic::Enter, handlers::enter );
	SET_HANDLER ( Mnemonic::Leave, handlers::leave );
	SET_HANDLER ( Mnemonic::Push, handlers::push );
	SET_HANDLER ( Mnemonic::Pop, handlers::pop );
	SET_HANDLER ( Mnemonic::Pushfq, handlers::pushfq );
	SET_HANDLER ( Mnemonic::Popfq, handlers::popfq );

	// System Instructions
	SET_HANDLER ( Mnemonic::Cli, handlers::cli );
	SET_HANDLER ( Mnemonic::Cld, handlers::cld );
	SET_HANDLER ( Mnemonic::Clc, handlers::clc );
	SET_HANDLER ( Mnemonic::Clui, handlers::clui );
	SET_HANDLER ( Mnemonic::Cmc, handlers::cmc );
	SET_HANDLER ( Mnemonic::Stc, handlers::stc );
	SET_HANDLER ( Mnemonic::Sti, handlers::sti );
	SET_HANDLER ( Mnemonic::Std, handlers::std );
	SET_HANDLER ( Mnemonic::Rdtsc, handlers::rdtsc );
	SET_HANDLER ( Mnemonic::Cpuid, handlers::cpuid );
	SET_HANDLER ( Mnemonic::Xgetbv, handlers::xgetbv );
	SET_HANDLER ( Mnemonic::Hlt, handlers::hlt );
	SET_HANDLER ( Mnemonic::Int1, handlers::int1 );
	SET_HANDLER ( Mnemonic::Int3, handlers::int3 );
	SET_HANDLER ( Mnemonic::Int, handlers::int_ );
	SET_HANDLER ( Mnemonic::Fxsave, handlers::fxsave );
	SET_HANDLER ( Mnemonic::Fxrstor, handlers::fxrstor );
	SET_HANDLER ( Mnemonic::Stmxcsr, handlers::stmxcsr );
	SET_HANDLER ( Mnemonic::Ldmxcsr, handlers::ldmxcsr );
	SET_HANDLER ( Mnemonic::Sahf, handlers::sahf );
	SET_HANDLER ( Mnemonic::Lahf, handlers::lahf );
	SET_HANDLER ( Mnemonic::Pushf, handlers::pushf );
	SET_HANDLER ( Mnemonic::Popf, handlers::popf );
	SET_HANDLER ( Mnemonic::Syscall, handlers::syscall );

	// Data Movement Instructions
	SET_HANDLER ( Mnemonic::Mov, handlers::mov );
	SET_HANDLER ( Mnemonic::Movd, handlers::movd );
	SET_HANDLER ( Mnemonic::Movq, handlers::movq );
	SET_HANDLER ( Mnemonic::Movsxd, handlers::movsxd );
	SET_HANDLER ( Mnemonic::Movzx, handlers::movzx );
	SET_HANDLER ( Mnemonic::Movsx, handlers::movsx );
	SET_HANDLER ( Mnemonic::Movaps, handlers::movaps );
	SET_HANDLER ( Mnemonic::Movups, handlers::movups );
	SET_HANDLER ( Mnemonic::Lea, handlers::lea );
	SET_HANDLER ( Mnemonic::Xchg, handlers::xchg );

	// String Operations
	SET_HANDLER ( Mnemonic::Movsw, handlers::movsw );
	SET_HANDLER ( Mnemonic::Movsb, handlers::movsb );
	SET_HANDLER ( Mnemonic::Movsd, handlers::movsd );
	SET_HANDLER ( Mnemonic::Movsq, handlers::movsq );
	SET_HANDLER ( Mnemonic::Stosq, handlers::stos );
	SET_HANDLER ( Mnemonic::Stosd, handlers::stos );
	SET_HANDLER ( Mnemonic::Stosb, handlers::stos );
	SET_HANDLER ( Mnemonic::Stosw, handlers::stos );

	// SIMD Instructions
	SET_HANDLER ( Mnemonic::Vpxor, handlers::vpxor );
	SET_HANDLER ( Mnemonic::Vpcmpeqw, handlers::vpcmpeqw );
	SET_HANDLER ( Mnemonic::Vpmovmskb, handlers::vpmovmskb );
	SET_HANDLER ( Mnemonic::Vzeroupper, handlers::vzeroupper );
	SET_HANDLER ( Mnemonic::Vinsertf128, handlers::vinsertf128 );
	SET_HANDLER ( Mnemonic::Vmovups, handlers::vmovups );
	SET_HANDLER ( Mnemonic::Vmovaps, handlers::vmovaps );
	SET_HANDLER ( Mnemonic::Vmovdqu, handlers::vmovdqu );
	SET_HANDLER ( Mnemonic::Movdqu, handlers::movdqu );
	SET_HANDLER ( Mnemonic::Movlhps, handlers::movlhps );
	SET_HANDLER ( Mnemonic::Punpcklqdq, handlers::punpcklqdq );
	SET_HANDLER ( Mnemonic::Prefetchw, handlers::prefetchw );
	SET_HANDLER ( Mnemonic::Psrldq, handlers::psrldq );
	SET_HANDLER ( Mnemonic::Movhlps, handlers::movhlps );
	SET_HANDLER ( Mnemonic::Unpcklps, handlers::unpcklps );
	SET_HANDLER ( Mnemonic::Pinsrb, handlers::pinsrb );
	SET_HANDLER ( Mnemonic::Pinsrd, handlers::pinsrd );
	SET_HANDLER ( Mnemonic::Pinsrq, handlers::pinsrq );
	SET_HANDLER ( Mnemonic::Paddb, handlers::paddb );
	SET_HANDLER ( Mnemonic::Paddw, handlers::paddw );
	SET_HANDLER ( Mnemonic::Paddd, handlers::paddd );
	SET_HANDLER ( Mnemonic::Paddq, handlers::paddq );

	// Floating-Point Instructions
	SET_HANDLER ( Mnemonic::Addss, handlers::addss );
	SET_HANDLER ( Mnemonic::Subss, handlers::subss );
	SET_HANDLER ( Mnemonic::Mulss, handlers::mulss );
	SET_HANDLER ( Mnemonic::Divss, handlers::divss );
	SET_HANDLER ( Mnemonic::Minss, handlers::minss );
	SET_HANDLER ( Mnemonic::Maxss, handlers::maxss );
	SET_HANDLER ( Mnemonic::Andps, handlers::andps );
	SET_HANDLER ( Mnemonic::Orps, handlers::orps );
	SET_HANDLER ( Mnemonic::Xorps, handlers::xorps );
	SET_HANDLER ( Mnemonic::Sqrtss, handlers::sqrtss );
	SET_HANDLER ( Mnemonic::Sqrtsd, handlers::sqrtsd );
	SET_HANDLER ( Mnemonic::Comiss, handlers::comiss );
	SET_HANDLER ( Mnemonic::Ucomiss, handlers::ucomiss );
	SET_HANDLER ( Mnemonic::Comisd, handlers::comisd );
	SET_HANDLER ( Mnemonic::Cmpss, handlers::cmpss );
	SET_HANDLER ( Mnemonic::Cvtss2si, handlers::cvtss2si );
	SET_HANDLER ( Mnemonic::Cvttss2si, handlers::cvttss2si );
	SET_HANDLER ( Mnemonic::Cvtsi2ss, handlers::cvtsi2ss );
	SET_HANDLER ( Mnemonic::Cvtsi2sd, handlers::cvtsi2sd );
	SET_HANDLER ( Mnemonic::Cvtss2sd, handlers::cvtss2sd );
	SET_HANDLER ( Mnemonic::Cvtsd2ss, handlers::cvtsd2ss );
	SET_HANDLER ( Mnemonic::Roundss, handlers::roundss );
	SET_HANDLER ( Mnemonic::Rcpss, handlers::rcpss );
	SET_HANDLER ( Mnemonic::Rsqrtss, handlers::rsqrtss );
	SET_HANDLER ( Mnemonic::Mulsd, handlers::mulsd );
	SET_HANDLER ( Mnemonic::Movss, handlers::movss );

	// 80-bit Floating-Point Instructions
	SET_HANDLER ( Mnemonic::Fld, handlers::fld );
	SET_HANDLER ( Mnemonic::Fprem, handlers::fprem );
	SET_HANDLER ( Mnemonic::Fstp, handlers::fstp );
	SET_HANDLER ( Mnemonic::Ffree, handlers::ffree );
	SET_HANDLER ( Mnemonic::Fincstp, handlers::fincstp );
	SET_HANDLER ( Mnemonic::Fmul, handlers::fmul );
	SET_HANDLER ( Mnemonic::Fnstcw, handlers::fnstcw );

	// Miscellaneous Instructions
	SET_HANDLER ( Mnemonic::Nop, handlers::nop );
}

KUBERA::KUBERA ( ) {
	if ( !memory ) {
		memory = std::make_unique<VirtualMemory> ( );
	}
	const uint64_t stack_addr = memory->alloc_at ( 0xDEADBEEF00000000, 0x200000, PageProtection::READ | PageProtection::WRITE );
	cpu = std::make_unique<CPU> ( stack_addr, 0x200000 );
	decoder = std::make_unique<iced::Decoder> ( );
	instruction_dispatch_table = std::make_unique<InstructionHandlerList> ();
	map_avx ( );
	map_gpr ( );
	instruction_dispatch_table->fill ( unsupported_instruction );
	map_handlers ( );

	set_reg_internal<KubRegister::RSP, Register::RSP> ( stack_addr + cpu->stack_size );
}


std::vector<std::string> KUBERA::get_register_changes ( const std::array<std::uint64_t, KubRegister::COUNT>& old_registers ) const {
	std::vector<std::string> changes;
	for ( size_t i = 0; i < KubRegister::COUNT; ++i ) {
		if ( cpu->registers [ i ] != old_registers [ i ] && static_cast< KubRegister > ( i ) != KubRegister::RIP ) {
			std::stringstream ss;
			ss << register_names [ i ] << " 0x" << std::hex << old_registers [ i ] << ";0x" << std::hex << cpu->registers [ i ];
			changes.push_back ( ss.str ( ) );
		}
	}
	return changes;
}

std::vector<std::string> KUBERA::get_rflags_changes ( const x86::Flags& old_rflags ) const {
	std::vector<std::string> changes;
	auto add_change = [ &changes ] ( const std::string& name, uint64_t old_val, uint64_t new_val )
	{
		if ( old_val != new_val ) {
			changes.push_back ( name + " " + std::to_string ( old_val ) + ";" + std::to_string ( new_val ) );
		}
	};
	add_change ( "CF", old_rflags.CF, cpu->rflags.CF );
	add_change ( "PF", old_rflags.PF, cpu->rflags.PF );
	add_change ( "AF", old_rflags.AF, cpu->rflags.AF );
	add_change ( "ZF", old_rflags.ZF, cpu->rflags.ZF );
	add_change ( "SF", old_rflags.SF, cpu->rflags.SF );
	add_change ( "TF", old_rflags.TF, cpu->rflags.TF );
	add_change ( "IF", old_rflags.IF, cpu->rflags.IF );
	add_change ( "DF", old_rflags.DF, cpu->rflags.DF );
	add_change ( "OF", old_rflags.OF, cpu->rflags.OF );
	add_change ( "IOPL", old_rflags.IOPL, cpu->rflags.IOPL );
	add_change ( "NT", old_rflags.NT, cpu->rflags.NT );
	add_change ( "RF", old_rflags.RF, cpu->rflags.RF );
	add_change ( "VM", old_rflags.VM, cpu->rflags.VM );
	add_change ( "AC", old_rflags.AC, cpu->rflags.AC );
	add_change ( "VIF", old_rflags.VIF, cpu->rflags.VIF );
	add_change ( "VIP", old_rflags.VIP, cpu->rflags.VIP );
	add_change ( "ID", old_rflags.ID, cpu->rflags.ID );
	return changes;
}

std::vector<std::string> KUBERA::get_mxcsr_changes ( const x86::Mxcsr& old_mxcsr ) const {
	std::vector<std::string> changes;
	auto add_change = [ &changes ] ( const std::string& name, unsigned int old_val, unsigned int new_val )
	{
		if ( old_val != new_val ) {
			changes.push_back ( name + " " + std::to_string ( old_val ) + ";" + std::to_string ( new_val ) );
		}
	};
	add_change ( "IE", old_mxcsr.IE, cpu->mxcsr.IE );
	add_change ( "DE", old_mxcsr.DE, cpu->mxcsr.DE );
	add_change ( "ZE", old_mxcsr.ZE, cpu->mxcsr.ZE );
	add_change ( "OE", old_mxcsr.OE, cpu->mxcsr.OE );
	add_change ( "UE", old_mxcsr.UE, cpu->mxcsr.UE );
	add_change ( "PE", old_mxcsr.PE, cpu->mxcsr.PE );
	add_change ( "DAZ", old_mxcsr.DAZ, cpu->mxcsr.DAZ );
	add_change ( "IM", old_mxcsr.IM, cpu->mxcsr.IM );
	add_change ( "DM", old_mxcsr.DM, cpu->mxcsr.DM );
	add_change ( "ZM", old_mxcsr.ZM, cpu->mxcsr.ZM );
	add_change ( "OM", old_mxcsr.OM, cpu->mxcsr.OM );
	add_change ( "UM", old_mxcsr.UM, cpu->mxcsr.UM );
	add_change ( "PM", old_mxcsr.PM, cpu->mxcsr.PM );
	add_change ( "RC", old_mxcsr.RC, cpu->mxcsr.RC );
	add_change ( "FTZ", old_mxcsr.FTZ, cpu->mxcsr.FTZ );
	return changes;
}

template void KUBERA::write_type<uint512_t> ( uint64_t, uint512_t );
template void KUBERA::write_type<uint256_t> ( uint64_t, uint256_t );
template void KUBERA::write_type<uint128_t> ( uint64_t, uint128_t );
template void KUBERA::write_type<float80_t> ( uint64_t, float80_t );
template void KUBERA::write_type<uint64_t> ( uint64_t, uint64_t );
template void KUBERA::write_type<uint32_t> ( uint64_t, uint32_t );
template void KUBERA::write_type<uint16_t> ( uint64_t, uint16_t );
template void KUBERA::write_type<uint8_t> ( uint64_t, uint8_t );

template uint512_t KUBERA::read_type<uint512_t> ( uint64_t ) const;
template uint256_t KUBERA::read_type<uint256_t> ( uint64_t ) const;
template uint128_t KUBERA::read_type<uint128_t> ( uint64_t ) const;
template uint64_t KUBERA::read_type<uint64_t> ( uint64_t ) const;
template uint32_t KUBERA::read_type<uint32_t> ( uint64_t ) const;
template uint16_t KUBERA::read_type<uint16_t> ( uint64_t ) const;
template uint8_t KUBERA::read_type<uint8_t> ( uint64_t ) const;

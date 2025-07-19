#pragma once

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include "x86.hpp"

namespace mp = boost::multiprecision;
using int128_t = mp::int128_t;
using uint128_t = mp::uint128_t;
using uint256_t = mp::uint256_t;
using uint512_t = mp::uint512_t;
using int256_t = mp::int256_t;
using int512_t = mp::int512_t;
using float80_t =
mp::number<mp::cpp_bin_float<
	64,                 // Number of significand bits (including explicit leading bit when non-zero)
	mp::digit_base_2,   // Binary representation
	void, std::int16_t, // Use 16-bit exponent type
	-16382, 16383       // Min/Max exponent values
>, mp::et_off>;       // Disable expression templates for simplicity

namespace kubera
{
	enum KubRegister {
		// General-purpose registers (64-bit)
		RAX,
		RBX,
		RCX,
		RDX,
		RSI,
		RDI,
		RBP,
		RSP,
		R8,
		R9,
		R10,
		R11,
		R12,
		R13,
		R14,
		R15,
		RIP,

		// Debug registers
		DR0,
		DR1,
		DR2,
		DR3,
		DR4,
		DR5,
		DR6,
		DR7,

		// Control registers
		CR0, // Flags
		CR2, // Page fault linear address
		CR3, // Page table base
		CR4, // CPU features/extensions
		CR8, // CPU priority, interrupts

		// Segment registers
		CS,
		DS,
		ES,
		FS,
		GS,
		SS,

		GDTR,

		COUNT // Total count for array sizing
	};

	struct alignas( 64 ) FPU {
		std::array<float80_t, 8> fpu_stack = { 0 };
		x86::FPUTagWord fpu_tag_word = { .value = 0xFFFF };
		x86::FPUStatusWord fpu_status_word = { .value = 0x0000 };
		x86::FPUControlWord fpu_control_word = { .value = 0x027F };
		uint8_t fpu_top = 0;

		int get_fpu_phys_idx ( int sti ) const {
			return ( fpu_top + sti ) % 8;
		}

		void set_fpu_tag ( int phys_idx, uint8_t tag ) {
			switch ( phys_idx ) {
				case 0: fpu_tag_word.TAG0 = tag; break;
				case 1: fpu_tag_word.TAG1 = tag; break;
				case 2: fpu_tag_word.TAG2 = tag; break;
				case 3: fpu_tag_word.TAG3 = tag; break;
				case 4: fpu_tag_word.TAG4 = tag; break;
				case 5: fpu_tag_word.TAG5 = tag; break;
				case 6: fpu_tag_word.TAG6 = tag; break;
				case 7: fpu_tag_word.TAG7 = tag; break;
				default: __assume ( false );
			}
		}

		uint8_t get_fpu_tag ( int phys_idx ) const {
			switch ( phys_idx ) {
				case 0: return fpu_tag_word.TAG0;
				case 1: return fpu_tag_word.TAG1;
				case 2: return fpu_tag_word.TAG2;
				case 3: return fpu_tag_word.TAG3;
				case 4: return fpu_tag_word.TAG4;
				case 5: return fpu_tag_word.TAG5;
				case 6: return fpu_tag_word.TAG6;
				case 7: return fpu_tag_word.TAG7;
				default: __assume ( false );
			}
		}

		void update_fsw_top ( ) {
			fpu_status_word.TOP = fpu_top & 0b111;
		}

		uint8_t classify_fpu_operand ( const float80_t& val ) const {
			using namespace boost::multiprecision;
			int c = fpclassify ( val );
			switch ( c ) {
				case FP_NAN:       return x86::FPU_TAG_SPECIAL;
				case FP_INFINITE:  return x86::FPU_TAG_SPECIAL;
				case FP_ZERO:      return x86::FPU_TAG_ZERO;
				case FP_SUBNORMAL: return x86::FPU_TAG_SPECIAL;
				case FP_NORMAL:    return x86::FPU_TAG_VALID;
				default:           return x86::FPU_TAG_SPECIAL;
			}
		}
	};

	struct alignas( 64 ) CPU {
		std::array<std::uint64_t, KubRegister::COUNT> registers = { 0 };
		std::uint64_t stack_base = 0ULL;
		std::size_t stack_size = 0x200000;
		std::vector<std::uint64_t> shadow_stack { };
		std::uint64_t ssp = 0ULL;
		x86::Flags rflags = static_cast< x86::Flags >( 0x0000000000000202ULL );
		x86::Mxcsr mxcsr = static_cast< x86::Mxcsr >( 0x1F80U );
		std::uint64_t timestamp_counter = 0ULL;
		std::uint8_t current_privilege_level = 3;
		FPU fpu { };
		std::unique_ptr<std::array<uint512_t, 32>> sse_registers = nullptr;

		CPU ( std::uint64_t stack_base_addr, std::size_t _stack_size ) : stack_base ( stack_base_addr ), stack_size ( _stack_size ) {
			sse_registers = std::make_unique<std::array<uint512_t, 32>> ( );
			sse_registers->fill ( uint512_t ( 0 ) );
			timestamp_counter = __rdtsc ( );
		}

		void increment_tsc ( std::size_t amount = 1 ) {
			timestamp_counter += amount;
		}
	};
};
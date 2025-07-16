#pragma once
#ifndef __ICED_DEF
#define __ICED_DEF

/* Required links if you're not using cmake (and on Windows) */
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "userenv")
#pragma comment(lib, "Iced_Wrapper.lib")

/* DEFINES */
#define ICED_USE_STD_STRING // Wrappers will include a std::string_view instead of a char*

/* INCLUDES */
#include <cstdint>
#include <cstddef>
#include <utility>
#include <vector>
#include <algorithm>
#include <cassert>

#ifdef ICED_USE_STD_STRING
#include <string>
#define ICED_STR std::string_view
#else
#define ICED_STR char*
#endif

#include "iced_internal.hpp"

/* MACROS */
#if __cplusplus >= 201703L || _MSVC_LANG >= 201703L
#define NODISCARD [[nodiscard]]
#else
#define NODISCARD
#endif

#if defined(_MSC_VER)
#define UNREACHABLE() __assume(false)
#define FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define UNREACHABLE() __builtin_unreachable()
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
#if __cplusplus >= 202302L || _MSVC_LANG >= 202302L
#define UNREACHABLE() std::unreachable()
#else
#define UNREACHABLE() do {} while (0) // Fallback for older standards
#endif
#define FORCE_INLINE inline
#endif

extern "C" {
	int disas ( void* obj, const void* code, std::size_t len );
	int disas2 ( void* obj, const void* code, std::size_t len );
}

NODISCARD constexpr OpKindSimple opkind_map_to_simple ( OpKind rawType ) {
	static constexpr OpKindSimple lookup [ ] = {
			OpKindSimple::Invalid,    // Invalid
			OpKindSimple::Register,   // Register8-512
			OpKindSimple::Register,
			OpKindSimple::Register,
			OpKindSimple::Register,
			OpKindSimple::Register,
			OpKindSimple::Register,
			OpKindSimple::Register,
			OpKindSimple::Memory,     // Memory8-512
			OpKindSimple::Memory,
			OpKindSimple::Memory,
			OpKindSimple::Memory,
			OpKindSimple::Memory,
			OpKindSimple::Memory,
			OpKindSimple::Memory,
			OpKindSimple::Immediate,  // Immediate8-64
			OpKindSimple::Immediate,
			OpKindSimple::Immediate,
			OpKindSimple::Immediate,
			OpKindSimple::Immediate,
			OpKindSimple::NearBranch, // NearBranch
			OpKindSimple::FarBranch   // FarBranch
	};

	return lookup [ static_cast< uint8_t >( rawType ) ];
}

constexpr bool operator==( OpKind lhs, OpKindSimple rhs ) noexcept {
	return opkind_map_to_simple ( lhs ) == rhs;
}

constexpr bool operator==( OpKindSimple lhs, OpKind rhs ) noexcept {
	return rhs == lhs;
}


/* CLASSES */
namespace iced
{
	class Instruction {
	public:
		Instruction ( ) = default;
		Instruction ( const __iced_internal::IcedInstruction& instruction, std::uint64_t ip_ ) : icedInstr ( instruction ), ip ( ip_ ) { }
		~Instruction ( ) { }

		NODISCARD FlowControl flow_control ( ) const noexcept {
			if ( jcc ( ) ) {
				return FlowControl::ConditionalBranch;
			}
			else if ( jmp ( ) ) {
				if ( op0_kind ( ) == OpKindSimple::Register || op0_kind ( ) == OpKindSimple::Memory ) {
					return FlowControl::IndirectBranch;
				}
				return FlowControl::UnconditionalBranch;
			}
			else if ( ret ( ) ) {
				return FlowControl::Return;
			}
			else if ( call ( ) ) {
				if ( op0_kind ( ) == OpKindSimple::Register || op0_kind ( ) == OpKindSimple::Memory ) {
					return FlowControl::IndirectCall;
				}
				return FlowControl::Call;
			}

			switch ( icedInstr.mnemonic ) {
				case Mnemonic::Syscall:
				case Mnemonic::Sysenter:
				case Mnemonic::Vmlaunch:
				case Mnemonic::Vmresume:
				case Mnemonic::Vmcall:
				case Mnemonic::Vmmcall:
				case Mnemonic::Vmgexit:
				case Mnemonic::Vmrun:
				case Mnemonic::Tdcall:
				case Mnemonic::Seamcall:
				case Mnemonic::Seamret:
					return FlowControl::Call;
				case Mnemonic::Xbegin:
				case Mnemonic::Xabort:
				case Mnemonic::Xend:
					return FlowControl::XbeginXabortXend;

				case Mnemonic::Loop:
				case Mnemonic::Loopne:
				case Mnemonic::Loope:
					return FlowControl::ConditionalBranch;
				case Mnemonic::Int:
				case Mnemonic::Int1:
				case Mnemonic::Int3:
				case Mnemonic::Into:
				case Mnemonic::Smint:
				case Mnemonic::Dmint:
					return FlowControl::Interrupt;
				case Mnemonic::INVALID:
				case Mnemonic::Ud0:
				case Mnemonic::Ud1:
				case Mnemonic::Ud2:
					return FlowControl::Exception;
				default:
					break;
			}

			return FlowControl::Next;
		}

		/// Returns operand size in bytes
		NODISCARD FORCE_INLINE std::size_t op_size ( std::size_t index ) const noexcept {
			static constexpr std::size_t lookup [ ] = {
					0,   // Invalid
					1,   // Register8
					2,   // Register16
					4,   // Register32
					8,   // Register64
					16,  // Register128
					32,  // Register256
					64,  // Register512
					1,   // Memory8
					2,   // Memory16
					4,   // Memory32
					8,   // Memory64
					16,  // Memory128
					32,  // Memory256
					64,  // Memory512
					1,   // Immediate8
					1,   // Immediate8_2nd
					2,   // Immediate16
					4,   // Immediate32
					8,   // Immediate64
					8,   // NearBranch
					4    // FarBranch
			};

			return lookup [ static_cast< uint8_t >( icedInstr.types [ index ] ) ];
		}
		/// <summary>
		///  Calculates size of operand in bytes
		/// </summary>
		/// <param name="index">index of operand</param>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op0_size ( ) const noexcept { return op_size ( 0 ); }
		/// <summary>
		///  Calculates size of first operand in bytes
		/// </summary>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op1_size ( ) const noexcept { return op_size ( 1 ); }
		/// <summary>
		///  Calculates size of second operand in bytes
		/// </summary>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op2_size ( ) const noexcept { return op_size ( 2 ); }
		/// <summary>
		///  Calculates size of third operand in bytes
		/// </summary>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op3_size ( ) const noexcept { return op_size ( 3 ); }

		/// <summary>
		///  Calculates width of operand in bits
		/// </summary>
		/// <param name="index">index of operand</param>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op_bit_width ( std::size_t index ) const noexcept { return op_size ( index ) * 8ULL; }
		/// <summary>
		///		Calculates width of the first operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op0_bit_width ( ) const noexcept { return op_bit_width ( 0 ); }
		/// <summary>
		///		Calculates width of the second operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op1_bit_width ( ) const noexcept { return op_bit_width ( 1 ); }
		/// <summary>
		///		Calculates width of the third operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op2_bit_width ( ) const noexcept { return op_bit_width ( 2 ); }
		/// <summary>
		///		Calculates width of the fourth operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op3_bit_width ( ) const noexcept { return op_bit_width ( 3 ); }

		NODISCARD FORCE_INLINE OpKind op_kind ( std::size_t index ) const noexcept { return static_cast< OpKind >( icedInstr.types [ index ] ); }
		NODISCARD FORCE_INLINE OpKind op0_kind ( ) const noexcept { return op_kind ( 0 ); }
		NODISCARD FORCE_INLINE OpKind op1_kind ( ) const noexcept { return op_kind ( 1 ); }
		NODISCARD FORCE_INLINE OpKind op2_kind ( ) const noexcept { return op_kind ( 2 ); }
		NODISCARD FORCE_INLINE OpKind op3_kind ( ) const noexcept { return op_kind ( 3 ); }

		NODISCARD FORCE_INLINE OpKindSimple op_kind_simple ( std::size_t index ) const noexcept { return opkind_map_to_simple ( icedInstr.types [ index ] ); }

		NODISCARD ICED_STR op_kind_simple_str ( std::size_t operandIndex ) const noexcept {
			switch ( op_kind_simple ( operandIndex ) ) {
				case OpKindSimple::Register:
					return "Register";
				case OpKindSimple::Memory:
					return "Memory";
				case OpKindSimple::Immediate:
					return "Immediate";
				case OpKindSimple::NearBranch:
					return "NearBranch";
				case OpKindSimple::FarBranch:
					return "FarBranch";
				default:
					break;
			}

			return "Invalid";
		}

		NODISCARD FORCE_INLINE ICED_STR op0_kind_simple_str ( ) const noexcept { return op_kind_simple_str ( 0 ); }
		NODISCARD FORCE_INLINE ICED_STR op1_kind_simple_str ( ) const noexcept { return op_kind_simple_str ( 1 ); }
		NODISCARD FORCE_INLINE ICED_STR op2_kind_simple_str ( ) const noexcept { return op_kind_simple_str ( 2 ); }
		NODISCARD FORCE_INLINE ICED_STR op3_kind_simple_str ( ) const noexcept { return op_kind_simple_str ( 3 ); }

		NODISCARD FORCE_INLINE Register op_reg ( std::size_t index ) const noexcept { return icedInstr.regs [ index ]; }
		NODISCARD FORCE_INLINE Register op0_reg ( ) const noexcept { return op_reg ( 0 ); }
		NODISCARD FORCE_INLINE Register op1_reg ( ) const noexcept { return op_reg ( 1 ); }
		NODISCARD FORCE_INLINE Register op2_reg ( ) const noexcept { return op_reg ( 2 ); }
		NODISCARD FORCE_INLINE Register op3_reg ( ) const noexcept { return op_reg ( 3 ); }

		NODISCARD FORCE_INLINE std::uint64_t immediate ( ) const noexcept { return icedInstr.immediate; }
		NODISCARD FORCE_INLINE std::uint64_t immediate2 ( ) const noexcept { return icedInstr.immediate2; }
		NODISCARD FORCE_INLINE std::uint64_t displacement ( ) const noexcept { return icedInstr.mem_disp; }
		NODISCARD FORCE_INLINE Register mem_index ( ) const noexcept { return icedInstr.mem_index; }
		NODISCARD FORCE_INLINE Register mem_base ( ) const noexcept { return icedInstr.mem_base; }
		NODISCARD FORCE_INLINE uint32_t mem_scale ( ) const noexcept { return icedInstr.mem_scale; }
		NODISCARD FORCE_INLINE Register segment_prefix ( ) const noexcept { return icedInstr.segment_prefix; }

		NODISCARD FORCE_INLINE __iced_internal::IcedInstruction& get_internal ( ) noexcept { return icedInstr; }
		NODISCARD FORCE_INLINE std::uint8_t op_count ( ) const noexcept { return icedInstr.operand_count_visible; }
		NODISCARD FORCE_INLINE std::uint8_t length ( ) const noexcept { return icedInstr.length; }
		NODISCARD FORCE_INLINE bool rep_prefix ( ) const noexcept { return icedInstr.attributes.rep; }
		NODISCARD FORCE_INLINE bool repne_prefix ( ) const noexcept { return icedInstr.attributes.repne; }
		NODISCARD FORCE_INLINE bool lock_prefix ( ) const noexcept { return icedInstr.attributes.lock; }
		NODISCARD FORCE_INLINE bool is_broadcast ( ) const noexcept { return icedInstr.is_broadcast; }
		NODISCARD FORCE_INLINE Mnemonic mnemonic ( ) const noexcept { return static_cast< Mnemonic >( icedInstr.mnemonic ); }
		NODISCARD FORCE_INLINE bool valid ( ) const noexcept { return icedInstr.mnemonic != Mnemonic::INVALID; }
		NODISCARD FORCE_INLINE std::uint8_t stack_growth ( ) const noexcept { return icedInstr.stack_growth; }
		NODISCARD FORCE_INLINE bool lea ( ) const noexcept { return match_mnemonic ( Mnemonic::Lea ); }
		NODISCARD FORCE_INLINE bool mov ( ) const noexcept { return match_mnemonic ( Mnemonic::Mov ); }
		NODISCARD FORCE_INLINE bool bp ( ) const noexcept { return match_mnemonic ( Mnemonic::Int3 ); }
		NODISCARD FORCE_INLINE bool nop ( ) const noexcept { return match_mnemonic ( Mnemonic::Nop ); }
		NODISCARD FORCE_INLINE bool call ( ) const noexcept { return match_mnemonic ( Mnemonic::Call ); }
		NODISCARD FORCE_INLINE bool jmp ( ) const noexcept { return match_mnemonic ( Mnemonic::Jmp ); }
		NODISCARD FORCE_INLINE bool jcc ( ) const noexcept {
			const auto& mnemonic = icedInstr.mnemonic;
			return mnemonic >= Mnemonic::Ja && mnemonic <= Mnemonic::Js;
		}
		NODISCARD FORCE_INLINE bool jump ( ) const noexcept { return jmp ( ) || jcc ( ); }
		NODISCARD FORCE_INLINE bool branching ( ) const noexcept { return call ( ) || jump ( ); }
		NODISCARD FORCE_INLINE bool conditional_branch ( ) const noexcept { return jcc ( ); }
		NODISCARD FORCE_INLINE bool unconditional_branch ( ) const noexcept { return call ( ) || jmp ( ); }
		NODISCARD FORCE_INLINE bool indirect_call ( ) const noexcept {
			if ( !call ( ) ) {
				return false;
			}

			return op0_kind ( ) == OpKindSimple::Register || op0_kind ( ) == OpKindSimple::Memory;
		}
		NODISCARD bool modifies_register ( Register reg ) const noexcept {
			return op_kind_simple ( 0 ) == OpKindSimple::Register && op0_reg ( ) == reg;
		}
		NODISCARD bool ret ( ) const noexcept {
			switch ( icedInstr.mnemonic ) {
				case Mnemonic::Ret:
				case Mnemonic::Iret:
				case Mnemonic::Uiret:
					return true;
				default:
					break;
			}

			return false;
		}

		NODISCARD FORCE_INLINE std::uint64_t compute_memory_address ( ) const noexcept {
			if ( icedInstr.mem_base == Register::RIP ) {
				return ip + length ( ) + icedInstr.mem_disp;
			}

			if ( icedInstr.mem_base == Register::None || icedInstr.mem_index == Register::None ) { // Displacement holds absolute address
				return icedInstr.mem_disp;
			}

			return icedInstr.immediate;
		}
		NODISCARD FORCE_INLINE std::uint64_t resolve_memory ( ) const noexcept { return compute_memory_address ( ); }
		NODISCARD std::uint64_t branch_target ( ) const noexcept {
			switch ( op_kind_simple ( 0 ) ) {
				case OpKindSimple::Immediate:
					return icedInstr.immediate2 ? icedInstr.immediate2 : icedInstr.immediate;
				case OpKindSimple::Memory:
					return resolve_memory ( );
				case OpKindSimple::NearBranch:
				case OpKindSimple::FarBranch:
					return ip + length ( ) + icedInstr.mem_disp;
				default:
					return 0ULL;
			}

			UNREACHABLE ( );
		}

		NODISCARD FORCE_INLINE ICED_STR to_string ( ) const noexcept {
			if ( !valid ( ) ) {
				return "Invalid instruction";
			}

			return icedInstr.text;
		}
		std::uint64_t ip;
	private:
		NODISCARD FORCE_INLINE bool match_mnemonic ( Mnemonic mnemonic ) const noexcept { return icedInstr.mnemonic == mnemonic; }
		__iced_internal::IcedInstruction icedInstr;
	};

	class DecoderBase {
	public:
		DecoderBase ( ) = delete;
		DecoderBase ( const std::uint8_t* buffer, std::size_t size, std::uint64_t baseAddress )
			: data_ ( buffer ), ip_ ( baseAddress ), baseAddr_ ( baseAddress ), size_ ( size ), offset_ ( 0 ),
			lastSuccessfulIp_ ( 0 ), lastSuccessfulLength_ ( 0 ) {
			//assert ( buffer != nullptr && "Buffer cannot be null" );
			//assert ( size > 0 && "Buffer size must be greater than 0" );
		}

		DecoderBase ( const DecoderBase& ) = delete;
		DecoderBase& operator=( const DecoderBase& ) = delete;

		DecoderBase ( DecoderBase&& other ) noexcept
			: data_ ( other.data_ ), ip_ ( other.ip_ ), baseAddr_ ( other.baseAddr_ ),
			size_ ( other.size_ ), offset_ ( other.offset_ ),
			lastSuccessfulIp_ ( other.lastSuccessfulIp_ ),
			lastSuccessfulLength_ ( other.lastSuccessfulLength_ ),
			currentInstruction_ ( std::move ( other.currentInstruction_ ) ) {
			other.data_ = nullptr;
			other.size_ = 0;
		}

		DecoderBase& operator=( DecoderBase&& other ) noexcept {
			if ( this != &other ) {
				data_ = other.data_;
				ip_ = other.ip_;
				baseAddr_ = other.baseAddr_;
				size_ = other.size_;
				offset_ = other.offset_;
				lastSuccessfulIp_ = other.lastSuccessfulIp_;
				lastSuccessfulLength_ = other.lastSuccessfulLength_;
				currentInstruction_ = std::move ( other.currentInstruction_ );
				other.data_ = nullptr;
				other.size_ = 0;
			}
			return *this;
		}

		virtual ~DecoderBase ( ) = default;

		NODISCARD FORCE_INLINE std::uint64_t ip ( ) const noexcept { return ip_; }
		NODISCARD FORCE_INLINE const Instruction& current_instruction ( ) const noexcept { return currentInstruction_; }
		NODISCARD FORCE_INLINE Instruction& current_instruction ( ) noexcept { return currentInstruction_; }
		NODISCARD FORCE_INLINE bool can_decode ( ) const noexcept { return offset_ < size_; }
		NODISCARD FORCE_INLINE std::uint64_t last_successful_ip ( ) const noexcept { return lastSuccessfulIp_; }
		NODISCARD FORCE_INLINE std::uint16_t last_successful_length ( ) const noexcept { return lastSuccessfulLength_; }
		NODISCARD FORCE_INLINE std::size_t remaining_size ( ) const noexcept { return size_ - offset_; }

		bool set_ip ( std::uint64_t ip ) noexcept {
			if ( ip < baseAddr_ || ip >= baseAddr_ + size_ ) {
				return false;
			}
			ip_ = ip;
			offset_ = ip - baseAddr_;
			return true;
		}

		bool set_ip ( std::uint8_t* _ip ) noexcept {
			auto ip = reinterpret_cast< std::uint64_t > ( _ip );
			if ( ip < baseAddr_ || ip >= baseAddr_ + size_ ) {
				return false;
			}
			ip_ = ip;
			offset_ = ip - baseAddr_;
			return true;
		}

		void reconfigure ( const std::uint8_t* buffer, std::size_t size, std::uint64_t baseAddress ) noexcept {
			assert ( buffer != nullptr && "Buffer cannot be null" );
			assert ( size > 0 && "Buffer size must be greater than 0" );

			data_ = buffer;
			size_ = size;
			baseAddr_ = baseAddress;
			ip_ = baseAddress;
			offset_ = 0;
			lastSuccessfulIp_ = 0;
			lastSuccessfulLength_ = 0;
			currentInstruction_ = Instruction {};
		}

		void reset ( ) noexcept {
			ip_ = baseAddr_;
			offset_ = 0;
			lastSuccessfulIp_ = 0;
			lastSuccessfulLength_ = 0;
			currentInstruction_ = Instruction {};
		}

	protected:
		FORCE_INLINE void update_state ( const __iced_internal::IcedInstruction& icedInstruction ) noexcept {
			const auto len = icedInstruction.length;
			currentInstruction_ = Instruction { icedInstruction, ip_ };
			lastSuccessfulIp_ = ip_;
			lastSuccessfulLength_ = len;
			ip_ += len;
			offset_ += len;
		}

		const std::uint8_t* data_;
		std::uint64_t ip_;
		std::size_t offset_;

		std::uint64_t baseAddr_;
		std::size_t size_;
		std::uint64_t lastSuccessfulIp_;
		std::uint16_t lastSuccessfulLength_;

		Instruction currentInstruction_;
	};

	class Decoder : public DecoderBase {
	private:
		using DisasmFunc = int( * )( void*, const void*, std::size_t );
		DisasmFunc disasmFunction_;

	public:
		explicit Decoder ( const std::uint8_t* buffer = nullptr, std::size_t size = 15ULL,
						std::uint64_t baseAddress = 0ULL, bool debug = true )
			: DecoderBase ( buffer, size, baseAddress ),
			disasmFunction_ ( debug ? disas2 : disas ) { }

		NODISCARD Instruction& decode ( ) noexcept {
			const auto* current_ptr = data_ + offset_;
			const auto code_size = remaining_size ( );

			__iced_internal::IcedInstruction icedInstruction {};

			constexpr auto decode_size = 16ULL;
			disasmFunction_ ( &icedInstruction, current_ptr, decode_size );

			update_state ( icedInstruction );
			return currentInstruction_;
		}

		void set_debug_mode ( bool debug ) noexcept {
			disasmFunction_ = debug ? disas2 : disas;
		}
	};

	class DebugDecoder : public DecoderBase {
	public:
		explicit DebugDecoder ( const std::uint8_t* buffer = nullptr, std::size_t size = 15ULL,
							 std::uint64_t baseAddress = 0ULL )
			: DecoderBase ( buffer, size, baseAddress ) { }

		NODISCARD Instruction& decode ( ) noexcept {
			const auto* current_ptr = data_ + offset_;
			const auto code_size = remaining_size ( );

			__iced_internal::IcedInstruction icedInstruction {};
			const auto decode_size = std::min ( static_cast< std::size_t >( 16 ), code_size );
			disas2 ( &icedInstruction, current_ptr, decode_size );

			update_state ( icedInstruction );
			return currentInstruction_;
		}

		NODISCARD Instruction peek ( ) noexcept {
			const auto* current_ptr = data_ + offset_;
			const auto code_size = remaining_size ( );

			__iced_internal::IcedInstruction icedInstruction {};
			const auto decode_size = std::min ( static_cast< std::size_t >( 16 ), code_size );
			disas2 ( &icedInstruction, current_ptr, decode_size );

			//updateState ( icedInstruction );
			return Instruction ( icedInstruction, ip ( ) );
		}
	};

	class ReleaseDecoder : public DecoderBase {
	public:
		explicit ReleaseDecoder ( const std::uint8_t* buffer = nullptr, std::size_t size = 15ULL,
								 std::uint64_t baseAddress = 0ULL )
			: DecoderBase ( buffer, size, baseAddress ) { }

		NODISCARD Instruction& decode ( ) noexcept {
			const auto* current_ptr = data_ + offset_;
			const auto code_size = remaining_size ( );

			__iced_internal::IcedInstruction icedInstruction {};
			const auto decode_size = std::min ( static_cast< std::size_t >( 16 ), code_size );
			disas ( &icedInstruction, current_ptr, decode_size );

			update_state ( icedInstruction );
			return currentInstruction_;
		}

		NODISCARD Instruction peek ( ) noexcept {
			const auto* current_ptr = data_ + offset_;
			const auto code_size = remaining_size ( );

			__iced_internal::IcedInstruction icedInstruction {};
			const auto decode_size = std::min ( static_cast< std::size_t >( 16 ), code_size );
			disas ( &icedInstruction, current_ptr, decode_size );

			//updateState ( icedInstruction );
			return Instruction ( icedInstruction, ip ( ) );
		}
	};

	template<bool Debug = true>
	NODISCARD auto make_decoder ( const std::uint8_t* buffer, std::size_t size, std::uint64_t baseAddress = 0ULL ) {
		if constexpr ( Debug ) {
			return DebugDecoder ( buffer, size, baseAddress );
		}
		else {
			return ReleaseDecoder ( buffer, size, baseAddress );
		}
	}
};
#endif
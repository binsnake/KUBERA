#ifndef __ICED_DEF
#define __ICED_DEF

/* Required links if you're not using cmake (and on Windows) */
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "userenv")
#pragma comment(lib, "Iced_Wrapper.lib")
/* DEFINES */

#define ICED_USE_STD_STRING // Wrappers will include a std::string instead of a char*

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

/* CLASSES */
namespace iced
{
	class Instruction {
	public:
		Instruction ( ) = default;
		Instruction ( const __iced_internal::IcedInstruction& instruction, std::uint64_t ip_ ) : icedInstr ( instruction ), ip ( ip_ ) { }
		~Instruction ( ) { }

		NODISCARD FlowControl flowControl ( ) const noexcept {
			if ( isJcc ( ) ) {
				return FlowControl::ConditionalBranch;
			}
			else if ( isJmp ( ) ) {
				if ( op0KindSimple ( ) == OperandKindSimple::Register || op0KindSimple ( ) == OperandKindSimple::Memory ) {
					return FlowControl::IndirectBranch;
				}
				return FlowControl::UnconditionalBranch;
			}
			else if ( isRet ( ) ) {
				return FlowControl::Return;
			}
			else if ( isCall ( ) ) {
				if ( op0KindSimple ( ) == OperandKindSimple::Register || op0KindSimple ( ) == OperandKindSimple::Memory ) {
					return FlowControl::IndirectCall;
				}
				return FlowControl::Call;
			}

			switch ( icedInstr.mnemonic ) {
				case IcedMnemonic::Syscall:
				case IcedMnemonic::Sysenter:
				case IcedMnemonic::Vmlaunch:
				case IcedMnemonic::Vmresume:
				case IcedMnemonic::Vmcall:
				case IcedMnemonic::Vmmcall:
				case IcedMnemonic::Vmgexit:
				case IcedMnemonic::Vmrun:
				case IcedMnemonic::Tdcall:
				case IcedMnemonic::Seamcall:
				case IcedMnemonic::Seamret:
					return FlowControl::Call;
				case IcedMnemonic::Xbegin:
				case IcedMnemonic::Xabort:
				case IcedMnemonic::Xend:
					return FlowControl::XbeginXabortXend;

				case IcedMnemonic::Loop:
				case IcedMnemonic::Loopne:
				case IcedMnemonic::Loope:
					return FlowControl::ConditionalBranch;
				case IcedMnemonic::Int:
				case IcedMnemonic::Int1:
				case IcedMnemonic::Int3:
				case IcedMnemonic::Into:
				case IcedMnemonic::Smint:
				case IcedMnemonic::Dmint:
					return FlowControl::Interrupt;
				case IcedMnemonic::INVALID:
				case IcedMnemonic::Ud0:
				case IcedMnemonic::Ud1:
				case IcedMnemonic::Ud2:
					return FlowControl::Exception;
				default:
					break;
			}

			return FlowControl::Next;
		}

		NODISCARD FORCE_INLINE OperandKindSimple opKindToSimple ( OperandKind rawType ) const noexcept {
			const auto map = static_cast< OperandKind >( rawType );
			switch ( map ) {
				case OperandKind::Memory8:
				case OperandKind::Memory16:
				case OperandKind::Memory32:
				case OperandKind::Memory64:
				case OperandKind::Memory128:
				case OperandKind::Memory256:
				case OperandKind::Memory512:
					return OperandKindSimple::Memory;
				case OperandKind::Immediate8:
				case OperandKind::Immediate8_2nd:
				case OperandKind::Immediate16:
				case OperandKind::Immediate32:
				case OperandKind::Immediate64:
					return OperandKindSimple::Immediate;
				case OperandKind::Register8:
				case OperandKind::Register16:
				case OperandKind::Register32:
				case OperandKind::Register64:
				case OperandKind::Register128:
				case OperandKind::Register256:
				case OperandKind::Register512:
					return OperandKindSimple::Register;
				case OperandKind::NearBranch:
					return OperandKindSimple::NearBranch;
				case OperandKind::FarBranch:
					return OperandKindSimple::FarBranch;
				default:
					break;
			}

			return OperandKindSimple::Invalid;
		}
		/// Returns operand size in bytes
		NODISCARD FORCE_INLINE std::size_t opSize ( std::size_t index ) const noexcept {
			const auto map = icedInstr.types [ index ];
			switch ( map ) {
				case OperandKind::Memory8:
				case OperandKind::Register8:
				case OperandKind::Immediate8:
				case OperandKind::Immediate8_2nd:
					return 1;
				case OperandKind::Memory16:
				case OperandKind::Register16:
				case OperandKind::Immediate16:
					return 2;
				case OperandKind::Memory32:
				case OperandKind::Immediate32:
				case OperandKind::Register32:
				case OperandKind::FarBranch:
					return 4;
				case OperandKind::Memory64:
				case OperandKind::Register64:
				case OperandKind::Immediate64:
				case OperandKind::NearBranch:
					return 8;
				case OperandKind::Memory128:
				case OperandKind::Register128:
					return 16;
				case OperandKind::Memory256:
				case OperandKind::Register256:
					return 32;
				case OperandKind::Memory512:
				case OperandKind::Register512:
					return 64;
				default:
					break;
			}

			return 0ULL;
		}
		/// <summary>
		///  Calculates size of operand in bytes
		/// </summary>
		/// <param name="index">index of operand</param>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op0Size ( ) const noexcept { return opSize ( 0 ); }
		/// <summary>
		///  Calculates size of first operand in bytes
		/// </summary>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op1Size ( ) const noexcept { return opSize ( 1 ); }
		/// <summary>
		///  Calculates size of second operand in bytes
		/// </summary>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op2Size ( ) const noexcept { return opSize ( 2 ); }
		/// <summary>
		///  Calculates size of third operand in bytes
		/// </summary>
		/// <returns>Width in bytes</returns>
		NODISCARD FORCE_INLINE std::size_t op3Size ( ) const noexcept { return opSize ( 3 ); }

		/// <summary>
		///  Calculates width of operand in bits
		/// </summary>
		/// <param name="index">index of operand</param>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t opWidth ( std::size_t index ) const noexcept { return opSize ( index ) * 8ULL; }
		/// <summary>
		///		Calculates width of the first operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op0Width ( ) const noexcept { return opWidth ( 0 ); }
		/// <summary>
		///		Calculates width of the second operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op1Width ( ) const noexcept { return opWidth ( 1 ); }
		/// <summary>
		///		Calculates width of the third operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op2Width ( ) const noexcept { return opWidth ( 2 ); }
		/// <summary>
		///		Calculates width of the fourth operand in bits
		/// </summary>
		/// <returns>Width in bits</returns>
		NODISCARD FORCE_INLINE std::size_t op3Width ( ) const noexcept { return opWidth ( 3 ); }

		NODISCARD FORCE_INLINE OperandKind opKind ( std::size_t index ) const noexcept { return static_cast< OperandKind >( icedInstr.types [ index ] ); }
		NODISCARD FORCE_INLINE OperandKind op0Kind ( ) const noexcept { return opKind ( 0 ); }
		NODISCARD FORCE_INLINE OperandKind op1Kind ( ) const noexcept { return opKind ( 1 ); }
		NODISCARD FORCE_INLINE OperandKind op2Kind ( ) const noexcept { return opKind ( 2 ); }
		NODISCARD FORCE_INLINE OperandKind op3Kind ( ) const noexcept { return opKind ( 3 ); }

		NODISCARD FORCE_INLINE OperandKindSimple opKindSimple ( std::size_t index ) const noexcept { return opKindToSimple ( icedInstr.types [ index ] ); }
		NODISCARD FORCE_INLINE OperandKindSimple op0KindSimple ( ) const noexcept { return opKindSimple ( 0 ); }
		NODISCARD FORCE_INLINE OperandKindSimple op1KindSimple ( ) const noexcept { return opKindSimple ( 1 ); }
		NODISCARD FORCE_INLINE OperandKindSimple op2KindSimple ( ) const noexcept { return opKindSimple ( 2 ); }
		NODISCARD FORCE_INLINE OperandKindSimple op3KindSimple ( ) const noexcept { return opKindSimple ( 3 ); }

		NODISCARD ICED_STR opKindSimpleStr ( std::size_t operandIndex ) const noexcept {
			switch ( opKindSimple ( operandIndex ) ) {
				case OperandKindSimple::Register:
					return "Register";
				case OperandKindSimple::Memory:
					return "Memory";
				case OperandKindSimple::Immediate:
					return "Immediate";
				case OperandKindSimple::NearBranch:
					return "NearBranch";
				case OperandKindSimple::FarBranch:
					return "FarBranch";
				default:
					break;
			}

			return "Invalid";
		}

		NODISCARD FORCE_INLINE ICED_STR op0KindSimpleStr ( ) const noexcept { return opKindSimpleStr ( 0 ); }
		NODISCARD FORCE_INLINE ICED_STR op1KindSimpleStr ( ) const noexcept { return opKindSimpleStr ( 1 ); }
		NODISCARD FORCE_INLINE ICED_STR op2KindSimpleStr ( ) const noexcept { return opKindSimpleStr ( 2 ); }
		NODISCARD FORCE_INLINE ICED_STR op3KindSimpleStr ( ) const noexcept { return opKindSimpleStr ( 3 ); }

		NODISCARD FORCE_INLINE IcedReg opReg ( std::size_t index ) const noexcept { return icedInstr.regs [ index ]; }
		NODISCARD FORCE_INLINE IcedReg op0Reg ( ) const noexcept { return opReg ( 0 ); }
		NODISCARD FORCE_INLINE IcedReg op1Reg ( ) const noexcept { return opReg ( 1 ); }
		NODISCARD FORCE_INLINE IcedReg op2Reg ( ) const noexcept { return opReg ( 2 ); }
		NODISCARD FORCE_INLINE IcedReg op3Reg ( ) const noexcept { return opReg ( 3 ); }

		NODISCARD FORCE_INLINE std::uint64_t immediate ( ) const noexcept { return icedInstr.immediate; }
		NODISCARD FORCE_INLINE std::uint64_t displacement ( ) const noexcept { return icedInstr.mem_disp; }
		NODISCARD FORCE_INLINE std::uint64_t memIndex ( ) const noexcept { return icedInstr.mem_index; }
		NODISCARD FORCE_INLINE IcedReg memBase ( ) const noexcept { return static_cast< IcedReg >( icedInstr.mem_base ); }

		NODISCARD FORCE_INLINE __iced_internal::IcedInstruction& internalInstruction ( ) { return icedInstr; }
		NODISCARD FORCE_INLINE std::uint8_t operandCount ( ) const noexcept { return icedInstr.operand_count_visible; }
		NODISCARD FORCE_INLINE std::uint8_t instructionLength ( ) const noexcept { return icedInstr.length; }
		NODISCARD FORCE_INLINE IcedMnemonic mnemonic ( ) const noexcept { return static_cast< IcedMnemonic >( icedInstr.mnemonic ); }
		NODISCARD FORCE_INLINE bool valid ( ) const noexcept { return icedInstr.mnemonic != IcedMnemonic::INVALID; }
		NODISCARD FORCE_INLINE std::uint8_t stackGrowth ( ) const noexcept { return icedInstr.stack_growth; }
		NODISCARD FORCE_INLINE bool isLea ( ) const noexcept { return idEquals ( IcedMnemonic::Lea ); }
		NODISCARD FORCE_INLINE bool isMov ( ) const noexcept { return idEquals ( IcedMnemonic::Mov ); }
		NODISCARD FORCE_INLINE bool isBp ( ) const noexcept { return idEquals ( IcedMnemonic::Int3 ); }
		NODISCARD FORCE_INLINE bool isNop ( ) const noexcept { return idEquals ( IcedMnemonic::Nop ); }
		NODISCARD FORCE_INLINE bool isCall ( ) const noexcept { return idEquals ( IcedMnemonic::Call ); }
		NODISCARD FORCE_INLINE bool isJmp ( ) const noexcept { return idEquals ( IcedMnemonic::Jmp ); }
		NODISCARD bool isJcc ( ) const noexcept {
			switch ( mnemonic ( ) ) {
				case IcedMnemonic::Jb:
				case IcedMnemonic::Jae:
				case IcedMnemonic::Jbe:
				case IcedMnemonic::Ja:
				case IcedMnemonic::Je:
				case IcedMnemonic::Jne:
				case IcedMnemonic::Jl:
				case IcedMnemonic::Jge:
				case IcedMnemonic::Jle:
				case IcedMnemonic::Jg:
				case IcedMnemonic::Jo:
				case IcedMnemonic::Jno:
				case IcedMnemonic::Jp:
				case IcedMnemonic::Jnp:
				case IcedMnemonic::Js:
				case IcedMnemonic::Jns:
				case IcedMnemonic::Jcxz:
				case IcedMnemonic::Jecxz:
				case IcedMnemonic::Jrcxz:
					return true;
				default:
					break;
			}
			return false;
		}
		NODISCARD FORCE_INLINE bool isJump ( ) const noexcept { return isJmp ( ) || isJcc ( ); }
		NODISCARD FORCE_INLINE bool isBranching ( ) const noexcept { return isCall ( ) || isJump ( ); }
		NODISCARD FORCE_INLINE bool isConditionalBranch ( ) const noexcept { return isJcc ( ); }
		NODISCARD FORCE_INLINE bool isUnconditionalBranch ( ) const noexcept { return isCall ( ) || isJmp ( ); }
		NODISCARD FORCE_INLINE bool isIndirectCall ( ) const noexcept {
			if ( !isCall ( ) ) {
				return false;
			}

			return op0KindSimple ( ) == OperandKindSimple::Register || op0KindSimple ( ) == OperandKindSimple::Memory;
		}
		NODISCARD bool isRet ( ) const noexcept {
			switch ( icedInstr.mnemonic ) {
				case IcedMnemonic::Ret:
				case IcedMnemonic::Iret:
				case IcedMnemonic::Uiret:
					return true;
				default:
					break;
			}

			return false;
		}

		NODISCARD FORCE_INLINE std::uint64_t computeMemoryAddress ( ) const noexcept {
			if ( icedInstr.mem_base == IcedReg::RIP ) {
				return ip + instructionLength ( ) + icedInstr.mem_disp;
			}

			if ( icedInstr.mem_base == IcedReg::None || !icedInstr.mem_index ) { // Displacement holds absolute address
				return icedInstr.mem_disp;
			}

			return icedInstr.immediate;
		}
		NODISCARD FORCE_INLINE std::uint64_t resolveMemoryTarget ( ) const noexcept { return computeMemoryAddress ( ); }
		NODISCARD std::uint64_t branchTarget ( ) const noexcept {
			switch ( op0KindSimple ( ) ) {
				case OperandKindSimple::Immediate:
					return icedInstr.immediate2 ? icedInstr.immediate2 : icedInstr.immediate;
				case OperandKindSimple::Memory:
					return resolveMemoryTarget ( );
				case OperandKindSimple::NearBranch:
				case OperandKindSimple::FarBranch:
					return ip + instructionLength ( ) + icedInstr.mem_disp;
				default:
					return 0ULL;
			}

			UNREACHABLE ( );
		}

		NODISCARD FORCE_INLINE ICED_STR toString ( ) const noexcept {
			if ( !valid ( ) ) {
				return "Invalid instruction";
			}

			return icedInstr.text;
		}
		std::uint64_t ip;
	private:
		NODISCARD FORCE_INLINE bool idEquals ( IcedMnemonic mnemonic ) const noexcept { return icedInstr.mnemonic == mnemonic; }
		__iced_internal::IcedInstruction icedInstr;
	};

	class DecoderBase {
	public:
		DecoderBase ( ) = delete;
		DecoderBase ( const std::uint8_t* buffer, std::size_t size, std::uint64_t baseAddress )
			: data_ ( buffer ), ip_ ( baseAddress ), baseAddr_ ( baseAddress ), size_ ( size ), offset_ ( 0 ),
			lastSuccessfulIp_ ( 0 ), lastSuccessfulLength_ ( 0 ) {
			assert ( buffer != nullptr && "Buffer cannot be null" );
			assert ( size > 0 && "Buffer size must be greater than 0" );
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
		NODISCARD FORCE_INLINE const Instruction& getCurrentInstruction ( ) const noexcept { return currentInstruction_; }
		NODISCARD FORCE_INLINE Instruction& getCurrentInstruction ( ) noexcept { return currentInstruction_; }
		NODISCARD FORCE_INLINE bool canDecode ( ) const noexcept { return offset_ < size_; }
		NODISCARD FORCE_INLINE std::uint64_t lastSuccessfulIp ( ) const noexcept { return lastSuccessfulIp_; }
		NODISCARD FORCE_INLINE std::uint16_t lastSuccessfulLength ( ) const noexcept { return lastSuccessfulLength_; }
		NODISCARD FORCE_INLINE std::size_t remainingSize ( ) const noexcept { return size_ - offset_; }

		bool setIp ( std::uint64_t ip ) noexcept {
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
		FORCE_INLINE void updateState ( const __iced_internal::IcedInstruction& icedInstruction ) noexcept {
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
			const auto code_size = remainingSize ( );

			__iced_internal::IcedInstruction icedInstruction {};

			constexpr auto decode_size = 16ULL;
			disasmFunction_ ( &icedInstruction, current_ptr, decode_size );

			updateState ( icedInstruction );
			return currentInstruction_;
		}

		void setDebugMode ( bool debug ) noexcept {
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
			const auto code_size = remainingSize ( );

			__iced_internal::IcedInstruction icedInstruction {};
			const auto decode_size = std::min ( static_cast< std::size_t >( 16 ), code_size );
			disas2 ( &icedInstruction, current_ptr, decode_size );

			updateState ( icedInstruction );
			return currentInstruction_;
		}
	};

	class ReleaseDecoder : public DecoderBase {
	public:
		explicit ReleaseDecoder ( const std::uint8_t* buffer = nullptr, std::size_t size = 15ULL,
								 std::uint64_t baseAddress = 0ULL )
			: DecoderBase ( buffer, size, baseAddress ) { }

		NODISCARD Instruction& decode ( ) noexcept {
			const auto* current_ptr = data_ + offset_;
			const auto code_size = remainingSize ( );

			__iced_internal::IcedInstruction icedInstruction {};
			const auto decode_size = std::min ( static_cast< std::size_t >( 16 ), code_size );
			disas ( &icedInstruction, current_ptr, decode_size );

			updateState ( icedInstruction );
			return currentInstruction_;
		}
	};

	template<bool Debug = true>
	NODISCARD auto makeDecoder ( const std::uint8_t* buffer, std::size_t size, std::uint64_t baseAddress = 0ULL ) {
		if constexpr ( Debug ) {
			return DebugDecoder ( buffer, size, baseAddress );
		}
		else {
			return ReleaseDecoder ( buffer, size, baseAddress );
		}
	}
};
#endif
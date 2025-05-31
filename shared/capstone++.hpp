#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string> // Added for std::string
#include <cstring> // Added for memcpy/memset
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <string_view>
#include <array>
#include <format>
#include <print>
#include <utility>

constexpr std::array<uint8_t, ( X86_INS_ENDING + 7 ) / 8> create_conditional_branch_bitfield ( ) {
	std::array<uint8_t, ( X86_INS_ENDING + 7 ) / 8> bits = {};
	auto set_bit = [ &bits ] ( unsigned int mnemonic_id )
	{
		if ( mnemonic_id < X86_INS_ENDING ) { // Basic bounds check
			bits [ mnemonic_id / 8 ] |= ( 1 << ( mnemonic_id % 8 ) );
		}
	};
	set_bit ( X86_INS_JB );
	set_bit ( X86_INS_JAE );
	set_bit ( X86_INS_JBE );
	set_bit ( X86_INS_JA );
	set_bit ( X86_INS_JE );
	set_bit ( X86_INS_JNE );
	set_bit ( X86_INS_JL );
	set_bit ( X86_INS_JGE );
	set_bit ( X86_INS_JLE );
	set_bit ( X86_INS_JG );
	set_bit ( X86_INS_JO );
	set_bit ( X86_INS_JNO );
	set_bit ( X86_INS_JP );
	set_bit ( X86_INS_JNP );
	set_bit ( X86_INS_JS );
	set_bit ( X86_INS_JNS );
	set_bit ( X86_INS_JCXZ );
	set_bit ( X86_INS_JECXZ );
	set_bit ( X86_INS_JRCXZ );
	set_bit ( X86_INS_LOOP );
	set_bit ( X86_INS_LOOPE );
	set_bit ( X86_INS_LOOPNE );
	return bits;
}

static constexpr auto conditional_branch_bits = create_conditional_branch_bitfield ( );

enum class OperandType : uint8_t {
	OP_INVALID,
	OP_REG,
	OP_IMM,
	OP_MEM
};

using Register = x86_reg;
using Segment = x86_reg;

#define SHOULD_BREAK_ON_INVALID_TYPE

namespace capstone
{
	class MemoryOperand {
	private:
		const Segment segment_;
		const Register base_;
		const Register index_;
		const int scale_;
		const int64_t disp_;

	public:
		MemoryOperand ( ) noexcept = default;
		MemoryOperand ( MemoryOperand&& other ) noexcept = default;
		MemoryOperand& operator=( MemoryOperand&& other ) noexcept = default;
		MemoryOperand ( const MemoryOperand& other ) = default;
		MemoryOperand& operator=( const MemoryOperand& other ) = default;
		~MemoryOperand ( ) = default;

		[[nodiscard]] Segment segment ( ) const noexcept {
			return segment_;
		}

		[[nodiscard]] Register base_register ( ) const noexcept {
			return base_;
		}

		[[nodiscard]] Register index_register ( ) const noexcept {
			return index_;
		}

		[[nodiscard]] int scale ( ) const noexcept {
			return scale_;
		}

		[[nodiscard]] int64_t displacement ( ) const noexcept {
			return disp_;
		}
	};
	class Operand {
	private:
		const OperandType type_;
		union {
			Register reg_;
			int64_t imm_;
			MemoryOperand mem_;
		};
	public:
		Operand ( ) noexcept = default;
		Operand ( Operand&& other ) noexcept = default;
		Operand& operator=( Operand&& other ) noexcept = default;
		Operand ( const Operand& other ) = default;
		Operand& operator=( const Operand& other ) = default;
		~Operand ( ) = default;

		[[nodiscard]] OperandType type ( ) const noexcept {
			return type_;
		}

		[[nodiscard]] Register reg ( ) const noexcept {
		#ifdef SHOULD_BREAK_ON_INVALID_TYPE
			if ( type ( ) != OperandType::OP_REG ) {
				__debugbreak ( );
			}
		#endif
			return reg_;
		}

		[[nodiscard]] int64_t immediate ( ) const noexcept {
		#ifdef SHOULD_BREAK_ON_INVALID_TYPE
			if ( type ( ) != OperandType::OP_IMM ) {
				__debugbreak ( );
			}
		#endif
			return imm_;
		}

		[[nodiscard]] MemoryOperand memory ( ) const noexcept {
		#ifdef SHOULD_BREAK_ON_INVALID_TYPE
			if ( type ( ) != OperandType::OP_MEM ) {
				__debugbreak ( );
			}
		#endif
			return mem_;
		}
	};
	class Instruction {
	public:
		Instruction ( ) noexcept = default;

		explicit Instruction ( cs_insn* insn, uint64_t ip, csh handle ) noexcept
			: ip_ ( ip ) {
			if ( insn && insn->id != X86_INS_INVALID && insn->size > 0 ) {
				valid_ = true;
				id_ = insn->id;
				size_ = static_cast< uint8_t >( insn->size );

				mnemonic_str_ = insn->mnemonic;
				op_str_ = insn->op_str;

				if ( insn->detail ) {
					x86_detail_copy_ = insn->detail->x86;
					detail_copied_ = true;
				}
			}
		}

		Instruction ( Instruction&& other ) noexcept = default;
		Instruction& operator=( Instruction&& other ) noexcept = default;
		Instruction ( const Instruction& other ) = default;
		Instruction& operator=( const Instruction& other ) = default;
		~Instruction ( ) = default;

		// --- Accessors ---
		[[nodiscard]] inline uint64_t ip ( ) const noexcept {
			return ip_;
		}
		[[nodiscard]] inline uint8_t length ( ) const noexcept {
			return size_;
		}
		[[nodiscard]] inline bool is_valid ( ) const noexcept {
			return valid_;
		}
		[[nodiscard]] inline unsigned int mnemonic ( ) const noexcept {
			return id_;
		}

		// --- String Conversion ---
		[[nodiscard]] std::string to_string ( ) const noexcept {
			if ( !valid_ ) {
				// Use the stored IP even if invalid, maybe helps debugging
				return std::format ( "0x{:016x}: invalid instruction", ip_ );
			}
			// Use stored strings
			return std::format ( "0x{:016x}: {} {}", ip_, mnemonic_str_, op_str_ );
		}

		[[nodiscard]] std::string to_string_no_address ( ) const noexcept {
			if ( !valid_ ) {
				return "invalid instruction";
			}
			// Use stored strings
			return std::format ( "{} {}", mnemonic_str_, op_str_ );
		}

		[[nodiscard]] const std::string& mnemonic_string ( ) const noexcept {
			return mnemonic_str_;
		}
		[[nodiscard]] const std::string& operand_string ( ) const noexcept {
			return op_str_;
		}

		// --- Classification Methods ---
		[[nodiscard]] inline bool is_call ( ) const noexcept {
			return valid_ && id_ == X86_INS_CALL;
		}
		[[nodiscard]] inline bool is_conditional_branch ( ) const noexcept {
			return valid_ && ( id_ < X86_INS_ENDING ) &&
				( conditional_branch_bits [ id_ / 8 ] & ( 1 << ( id_ % 8 ) ) ) != 0;
		}
		[[nodiscard]] inline bool is_jump ( ) const noexcept {
			return valid_ && ( is_conditional_branch ( ) || id_ == X86_INS_JMP );
		}
		[[nodiscard]] inline bool is_unconditional_branch ( ) const noexcept {
			return valid_ && id_ == X86_INS_JMP;
		}
		[[nodiscard]] inline bool is_return ( ) const noexcept {
			return valid_ && ( id_ == X86_INS_RET || id_ == X86_INS_RETF || id_ == X86_INS_RETFQ ||
												 id_ == X86_INS_IRET || id_ == X86_INS_IRETD || id_ == X86_INS_IRETQ );
		}
		[[nodiscard]] inline bool is_int3 ( ) const noexcept {
			return valid_ && id_ == X86_INS_INT3;
		}
		[[nodiscard]] inline bool is_branching ( ) const noexcept {
			return is_jump ( ) || is_call ( );
		}
		[[nodiscard]] bool is_lea_or_mov ( ) const noexcept {
			return valid_ && ( id_ == X86_INS_MOV || id_ == X86_INS_LEA );
		}
		[[nodiscard]] bool is_indirect_call ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || id_ != X86_INS_CALL || x86_detail_copy_.op_count == 0 ) {
				return false;
			}
			const auto& op = x86_detail_copy_.operands [ 0 ];
			return op.type == X86_OP_REG || op.type == X86_OP_MEM;
		}

		[[nodiscard]] inline bool is_avx ( ) const noexcept {
			return valid_ && detail_copied_ && x86_detail_copy_.avx_cc != X86_AVX_CC_INVALID;
		}
		[[nodiscard]] inline bool is_nop ( ) const noexcept {
			return valid_ && id_ == X86_INS_NOP;
		}
		[[nodiscard]] inline bool is_halt ( ) const noexcept {
			return valid_ && id_ == X86_INS_HLT;
		}
		[[nodiscard]] inline bool affects_flags ( ) const noexcept {
			return valid_ && detail_copied_ && x86_detail_copy_.eflags != 0;
		}
		[[nodiscard]] inline bool is_rep ( ) const noexcept {
			return x86_detail_copy_.prefix [ 0 ];
		}		
		[[nodiscard]] inline bool is_lock ( ) const noexcept {
			return x86_detail_copy_.prefix [ 0 ];
		}

		// --- Operand Access ---
		[[nodiscard]] inline const cs_x86_op* operands ( ) const noexcept {
			return ( valid_ && detail_copied_ ) ? x86_detail_copy_.operands : nullptr;
		}
		[[nodiscard]] inline uint8_t operand_count ( ) const noexcept {
			return ( valid_ && detail_copied_ ) ? x86_detail_copy_.op_count : 0;
		}

		// --- Target Resolution ---
		// Note: These now rely on the copied detail structure

		/**
		 * @brief For immediate branches/calls, returns the immediate value (target address).
		 * @return Target address or 0 if not an immediate branch/call or details unavailable.
		 */
		[[nodiscard]] uint64_t near_branch_target ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || !is_branching ( ) || x86_detail_copy_.op_count == 0 ) {
				return 0;
			}
			const auto& op = x86_detail_copy_.operands [ 0 ];
			if ( op.type == X86_OP_IMM ) {
				return static_cast< uint64_t >( op.imm );
			}
			return 0;
		}

		[[nodiscard]] bool has_displacement ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || !is_branching ( ) || x86_detail_copy_.op_count == 0 ) {
				return 0;
			}

			const auto& op = x86_detail_copy_.operands [ 0 ];
			return op.type == X86_OP_MEM;
		}

		[[nodiscard]] bool has_immediate ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || !is_branching ( ) || x86_detail_copy_.op_count == 0 ) {
				return 0;
			}
			const auto& op = x86_detail_copy_.operands [ 0 ];
			return op.type == X86_OP_IMM;
		}

		/**
		 * @brief Resolves target for immediate and RIP-relative branches/calls.
		 * @return Target address or 0 if not resolvable statically or details unavailable.
		 */
		[[nodiscard]] uint64_t branch_target ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || !is_branching ( ) || x86_detail_copy_.op_count == 0 ) {
				return 0;
			}
			const auto& op = x86_detail_copy_.operands [ 0 ];
			if ( op.type == X86_OP_IMM ) {
				return static_cast< uint64_t >( op.imm );
			}
			else if ( op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP ) {
				return ip_ + size_ + static_cast< uint64_t >( op.mem.disp );
			}

			return 0;
		}

		[[nodiscard]] x86_reg branch_target_register ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || !is_branching ( ) || x86_detail_copy_.op_count == 0 ) {
				return X86_REG_INVALID;
			}
			const auto& op = x86_detail_copy_.operands [ 0 ];
			if ( op.type == X86_OP_REG ) {
				return op.reg;
			}

			return X86_REG_INVALID;
		}

		/**
		 * @brief Computes the effective memory address for RIP-relative or absolute memory operands.
		 * @param mem_op The memory operand structure from the copied details.
		 * @return Computed address or 0 if not RIP-relative/absolute or details unavailable.
		 */
		[[nodiscard]] uint64_t compute_memory_address ( const x86_op_mem& mem_op ) const noexcept {
			// Can only resolve statically if RIP-relative or absolute displacement
			if ( mem_op.base == X86_REG_RIP ) {
				// Address = Next IP + Displacement
				return ip_ + size_ + static_cast< uint64_t >( mem_op.disp );
			}
			// Check for absolute address (no base, no index)
			if ( mem_op.base == X86_REG_INVALID && mem_op.index == X86_REG_INVALID ) {
				return static_cast< uint64_t >( mem_op.disp ); // The displacement is the absolute address
			}
			// Cannot resolve addresses involving other base/index registers statically
			return 0;
		}

		/**
		 * @brief For MOV/LEA instructions, resolves the target memory address if it's static (RIP-relative or absolute).
		 * @return Target address or 0 if not MOV/LEA, no memory operand, not statically resolvable, or details unavailable.
		 */
		[[nodiscard]] uint64_t resolve_memory_target ( ) const noexcept {
			if ( !valid_ || !detail_copied_ || ( id_ != X86_INS_MOV && id_ != X86_INS_LEA ) ) {
				return 0;
			}
			// Look through operands for a memory operand we can resolve
			for ( uint8_t i = 0; i < x86_detail_copy_.op_count; ++i ) {
				const auto& op = x86_detail_copy_.operands [ i ];
				if ( op.type == X86_OP_MEM ) {
					// Attempt to compute address statically
					return compute_memory_address ( op.mem );
				}
			}
			return 0; // No resolvable memory operand found
		}
		/**
		* @return Prefix is a uint8_t[4]
		*/
		[[nodiscard]] const uint8_t* prefix ( ) const noexcept {
			return x86_detail_copy_.prefix;
		}

	private:
		uint64_t ip_ = 0;
		unsigned int id_ = X86_INS_INVALID;
		uint8_t size_ = 0;
		bool valid_ = false;
		bool detail_copied_ = false;
		std::string mnemonic_str_; // Store strings to avoid lifetime issues
		std::string op_str_;
		cs_x86 x86_detail_copy_ = {}; // Store the detail struct content
	};


	// --- Decoder Class ---
	class Decoder {
	public:
		Decoder ( const uint8_t* data = nullptr, size_t size = 0, uint64_t base_addr = 0 ) noexcept
			: data_ ( data ), ip_ ( base_addr ), base_addr_ ( base_addr ), size_ ( static_cast< uint32_t >( size ) ),
			offset_ ( 0 ), remaining_size_ ( static_cast< uint32_t >( size ) ) {
			if ( data_ == nullptr || size_ == 0 ) {
				handle_ = 0; // Cannot initialize without data/size
				return;
			}
			auto result = cs_open ( CS_ARCH_X86, CS_MODE_64, &handle_ );
			if ( result != CS_ERR_OK ) {
				std::println ( "[engine - capstone] Failed to initialize decoder {}", ( int ) result );
				handle_ = 0;
			}
			else {
				// Enable detail only if handle is valid
				cs_option ( handle_, CS_OPT_DETAIL, CS_OPT_ON );
			}
		}

		// Rule of 5 for Decoder (handle needs careful management)
		Decoder ( const Decoder& ) = delete; // Disallow copying
		Decoder& operator=( const Decoder& ) = delete;

		Decoder ( Decoder&& other ) noexcept
			: handle_ ( std::exchange ( other.handle_, 0 ) ), // Transfer ownership
			data_ ( other.data_ ),
			ip_ ( other.ip_ ),
			base_addr_ ( other.base_addr_ ),
			size_ ( other.size_ ),
			offset_ ( other.offset_ ),
			remaining_size_ ( other.remaining_size_ ),
			last_successful_ip_ ( other.last_successful_ip_ ),
			last_successful_length_ ( other.last_successful_length_ ) { }

		Decoder& operator=( Decoder&& other ) noexcept {
			if ( this != &other ) {
				// Close existing handle if present
				if ( handle_ ) {
					cs_close ( &handle_ );
				}
				// Move resources from other
				handle_ = std::exchange ( other.handle_, 0 );
				data_ = other.data_;
				ip_ = other.ip_;
				base_addr_ = other.base_addr_;
				size_ = other.size_;
				offset_ = other.offset_;
				remaining_size_ = other.remaining_size_;
				last_successful_ip_ = other.last_successful_ip_;
				last_successful_length_ = other.last_successful_length_;
			}
			return *this;
		}


		~Decoder ( ) noexcept {
			if ( handle_ ) {
				cs_close ( &handle_ );
			}
		}

		void set_ip ( uint64_t ip ) noexcept {
			// Check if base_addr_ and size_ are valid before calculation
			if ( size_ > 0 && ip >= base_addr_ && ( ip - base_addr_ ) < size_ ) {
				ip_ = ip;
				offset_ = static_cast< uint32_t >( ip - base_addr_ );
				remaining_size_ = size_ - offset_;
			}
			else if ( size_ > 0 && ip == base_addr_ + size_ ) {
				// Allow setting IP exactly at the end
				ip_ = ip;
				offset_ = size_;
				remaining_size_ = 0;
			}
			else {
				// IP is out of bounds, set state to prevent decoding
				ip_ = ip; // Store the requested IP anyway
				offset_ = size_; // Point offset to end
				remaining_size_ = 0; // No remaining size
			}
		}

		[[nodiscard]] uint64_t ip ( ) const noexcept {
			return ip_;
		}
		[[nodiscard]] bool can_decode ( ) const noexcept {
			// Need valid handle and remaining data within buffer bounds
			return handle_ != 0 && remaining_size_ > 0 && offset_ < size_;
		}
		[[nodiscard]] const csh& get_handle ( ) const noexcept {
			return handle_;
		}

		[[nodiscard]] const Instruction& get_current_instruction ( ) const noexcept {
			return current_instruction_;
		}

		[[nodiscard]] inline Instruction decode ( ) noexcept {
			if ( !can_decode ( ) ) [[unlikely]] {
				return Instruction ( ); // Return invalid instruction
			}

			// Prepare for iteration
			const uint8_t* current_ptr = data_ + offset_;
			size_t code_size = remaining_size_; // Available size from current offset
			uint64_t address = ip_;             // Start address for this decode attempt

			// cs_malloc is required by cs_disasm_iter documentation
			cs_insn* insn = cs_malloc ( handle_ );
			if ( !insn ) { // Check malloc result
				std::println ( "[engine - capstone] cs_malloc failed" );
				return Instruction ( );
			}

			// Attempt to disassemble one instruction
			if ( cs_disasm_iter ( handle_, &current_ptr, &code_size, &address, insn ) ) [[likely]] {
				// Success!
				// Create our wrapper instruction (copies necessary data)
				current_instruction_ = Instruction ( insn, ip_, handle_ );

				// Update state *before* freeing Capstone instruction
				last_successful_ip_ = ip_;             // Store IP *before* advancing
				last_successful_length_ = insn->size; // Store length
				ip_ += insn->size;
				offset_ += insn->size;
				remaining_size_ -= insn->size;

				cs_free ( insn, 1 ); // Free the Capstone instruction
				return current_instruction_; // Return our valid wrapper
			}
			else {
				// Decoding failed at this position
				cs_free ( insn, 1 ); // Free the allocated instruction even on failure
				// Invalidate last successful? Or keep previous? Keep previous for now.
				// Stop further decoding by setting remaining size to 0?
				remaining_size_ = 0;
				return Instruction ( ); // Return invalid instruction
			}
		}

		// --- Added Functions ---
		/**
		 * @brief Gets the starting IP address of the last instruction successfully decoded by decode().
		 * @return IP address, or 0 if no instruction has been successfully decoded yet.
		 */
		[[nodiscard]] inline uint64_t last_successful_ip ( ) const noexcept {
			return last_successful_ip_;
		}

		/**
		 * @brief Gets the length in bytes of the last instruction successfully decoded by decode().
		 * @return Length in bytes, or 0 if no instruction has been successfully decoded yet.
		 */
		[[nodiscard]] inline uint16_t last_successful_length ( ) const noexcept {
			return last_successful_length_;
		}

		void reconfigure ( uint8_t* data, uint64_t size, uint64_t base_address = 0 ) noexcept {
			data_ = data;
			size_ = static_cast< uint32_t >( size );
			base_addr_ = base_address;
			remaining_size_ = static_cast< uint32_t >( size );
			offset_ = 0;
		}
		// --- End Added Functions ---


		const uint8_t* data_ = nullptr;
	private:
		csh handle_ = 0;
		Instruction current_instruction_ { };
		uint64_t ip_ = 0;
		uint64_t base_addr_ = 0;
		uint32_t size_ = 0;
		uint32_t offset_ = 0;
		uint32_t remaining_size_ = 0;
		uint64_t last_successful_ip_ = 0;
		uint16_t last_successful_length_ = 0;
	};
} // namespace capstone_wrapper
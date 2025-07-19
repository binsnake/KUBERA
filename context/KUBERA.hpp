#pragma once

#include <memory>
#include <array>
#include <functional>
#include <optional>
#include <cstdint>
#include "sign_extend.hpp"

#include "iced.hpp"
#include "configuration.hpp"
#include "types.hpp"
#include "memory.hpp"

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#define GET_OPERAND_MASK(y) (~0ULL >> (64 - (y) * 8))
#define ALIGN_DOWN(var, align) var & ~(align - 1)

namespace kubera
{
	// Type alias for instruction handler function
	using InstructionHandler = void ( * ) ( const iced::Instruction&, class KUBERA& state );

	// Type alias for array of instruction handlers
	using InstructionHandlerList = std::array<InstructionHandler, static_cast< std::size_t > ( Mnemonic::COUNT )>;

	// Optional function to override target address
	inline bool ( *platform_target_override )( uint64_t ) = nullptr;

	// Pointer to the instruction dispatch table
	inline std::unique_ptr<InstructionHandlerList> instruction_dispatch_table = nullptr;

	class KUBERA {
	private:
		std::unique_ptr<CPU> cpu = nullptr;
		std::unique_ptr<VirtualMemory> memory = nullptr;
		uint8_t instr_buffer [ 15 ] = { 0 };

	public:
		std::unique_ptr<iced::Decoder> decoder = nullptr;
		KUBERA ( );
		~KUBERA ( ) = default;

		uint64_t alloc_memory ( std::size_t size, uint8_t prot, std::size_t alignment = 0x1000 ) {
			return memory->alloc ( size, prot, alignment );
		}

		uint64_t load_memory ( const void* data, std::size_t size, uint8_t prot, std::size_t alignment = 0x1000 ) {
			return memory->load ( data, size, prot, alignment );
		}

		kubera::VirtualMemory* get_virtual_memory ( ) noexcept {
			return memory.get ( );
		}

		// Returns a mutable reference to cpu->rflags
		// Warning! This function can overwrite reserved bits!
		x86::Flags& get_flags ( ) noexcept {
			return cpu->rflags;
		}

		// Returns a mutable reference to cpu->mxcsr
		x86::Mxcsr& get_mxcsr ( ) noexcept {
			return cpu->mxcsr;
		}

		// Returns the current privilege level
		uint8_t& get_cpl ( ) const noexcept {
			return cpu->current_privilege_level;
		}

		// Increments the timestamp counter
		void increment_tsc ( size_t amount = 2 ) noexcept {
			cpu->increment_tsc ( amount );
		}

		// Returns a reference to the Floating Point Unit
		FPU& get_fpu ( ) noexcept {
			return cpu->fpu;
		}

		// Reads the timestamp counter
		uint64_t read_tsc ( ) const noexcept {
			return cpu->timestamp_counter;
		}

		// Returns a mutable reference to the RIP register
		uint64_t& rip ( ) noexcept {
			return cpu->registers [ KubRegister::RIP ];
		}

		std::size_t fetch_instruction_bytes ( uint64_t addr, uint8_t* buffer, std::size_t max_bytes ) {
			std::size_t fetched = 0;
			uint64_t current = addr;
			while ( fetched < max_bytes ) {
				void* src = memory->translate ( current, VirtualMemory::EXEC | VirtualMemory::READ );
				if ( !src ) {
					return 0;
				}
				std::size_t offset = current % memory->page_size;
				std::size_t to_copy = std::min ( max_bytes - fetched, memory->page_size - offset );
				std::memcpy ( buffer + fetched, src, to_copy );
				fetched += to_copy;
				current += to_copy;
			}
			return fetched;
		}

		// Emulates the instruction and updates the decoder
		void reconfigure ( uint64_t new_rip ) {
			rip ( ) = new_rip;
			std::size_t bytes_fetched = fetch_instruction_bytes ( new_rip, instr_buffer, 15 );
			if ( bytes_fetched == 0 ) {
				__debugbreak ( );
			}
			decoder->reconfigure ( instr_buffer, bytes_fetched, new_rip );
		}

		// Allocate Type on stack
		template <typename Type>
		Type* allocate_on_stack ( ) {
			uint64_t stack = get_reg_internal<KubRegister::RSP, Register::RSP, uint64_t> ( );
			stack = ALIGN_DOWN ( stack - sizeof ( Type ), std::max ( alignof( Type ), alignof( void* ) ) );
			set_reg_internal<KubRegister::RSP, Register::RSP, uint64_t> ( stack );
			return reinterpret_cast< Type* >( stack );
		}

		void unalign_stack ( ) {
			auto stack = get_reg_internal<KubRegister::RSP, Register::RSP, uint64_t> ( );
			stack = ALIGN_DOWN ( stack - 0x10, 0x10 ) + 0x8;
			set_reg_internal<KubRegister::RSP, Register::RSP, uint64_t> ( stack );
		}

		// Handles instruction pointer switch
		void handle_ip_switch ( uint64_t );

		// Returns the access mask for a register
		uint64_t get_access_mask ( Register reg, size_t size ) const noexcept;

		// Returns the access shift for a register
		uint8_t get_access_shift ( Register reg, size_t size ) const noexcept;

		// Returns the value of RFLAGS
		uint64_t get_rflags ( ) const noexcept;

		// Returns the value of a specified register
		uint64_t get_reg ( Register reg, size_t size = 8 ) const noexcept;

		// Executes an instruction using the dispatch table
		inline void execute ( const iced::Instruction& instr ) {
			( *kubera::instruction_dispatch_table ) [ static_cast< size_t >( instr.mnemonic ( ) ) ] ( instr, *this );
		}

		iced::Instruction& emulate ( ) {
			auto old_rip = rip ( );
			reconfigure ( rip ( ) );
			auto& instr = decoder->decode ( );
			execute ( instr );
			if ( rip ( ) == old_rip ) {
				rip ( ) += instr.length ( );
			}
			increment_tsc ( );
			return instr;
		}

		// Template function to read data of specified type from memory
		template <typename Type>
		Type read_type ( uint64_t address ) const {
			static_assert( !std::is_same_v<Type, float80_t>, "Use read_type_float80_t to read a float80_t" );
			return memory->read<Type> ( address );
		}

		// Reads 80-bit floating-point data from memory
		float80_t read_type_float80_t ( uint64_t address ) const;

		// Template function to write data of specified type to memory
		template <typename Type>
		void write_type ( uint64_t address, Type val ) {
			memory->write<Type> ( address, val );
		}

		// Template function to read data from stack with bounds checking
		template <typename Type>
		Type get_stack ( uint64_t address ) const {
			if ( !is_within_stack_bounds ( address, sizeof ( Type ) ) ) {
				// TODO: Implement exception handling
				return Type ( 0 );
			}

			return read_type<Type> ( address );
		}

		// Template function to read data from memory with permission checking
		template <typename Type>
		Type get_memory ( uint64_t address ) const {
			return read_type<Type> ( address );
		}

		// Sets the RFLAGS register
		void set_rflags ( uint64_t rflags ) noexcept;

		// Sets the value of a specified register
		void set_reg ( Register reg, uint64_t val, size_t size );

		// Template function to write data to stack with bounds checking
		template <typename Type>
		void set_stack ( uint64_t address, Type val ) {
			if ( !is_within_stack_bounds ( address, sizeof ( Type ) ) ) {
				return;
			}

			return write_type<Type> ( address, val );
		}

		// Template function to write data to memory with permission checking
		template <typename Type>
		void set_memory ( uint64_t address, Type val ) {
			return write_type<Type> ( address, val );
		}

		// Checks if an address is within stack bounds
		bool is_within_stack_bounds ( uint64_t address, size_t size ) const noexcept;

		// Retrieves raw XMM register value
		uint128_t get_xmm_raw ( Register reg ) const;

		// Sets raw XMM register value
		void set_xmm_raw ( Register reg, const uint128_t& value );

		// Retrieves raw YMM register value
		uint256_t get_ymm_raw ( Register reg ) const;

		// Sets raw YMM register value
		void set_ymm_raw ( Register reg, const uint256_t& value );

		// Retrieves raw ZMM register value
		uint512_t get_zmm_raw ( Register reg ) const;

		// Sets raw ZMM register value
		void set_zmm_raw ( Register reg, const uint512_t& value );

		// Retrieves XMM register value as float
		float get_xmm_float ( Register reg ) const;

		// Sets XMM register value as float
		void set_xmm_float ( Register reg, float value );

		// Retrieves XMM register value as double
		double get_xmm_double ( Register reg ) const;

		// Sets XMM register value as double
		void set_xmm_double ( Register reg, double value );

		template <Register reg, size_t size>
		static constexpr uint64_t get_access_mask_internal ( ) noexcept {
			switch ( size ) {
				case 8:
					return 0xFFFFFFFFFFFFFFFFULL;
				case 4:
					return 0x00000000FFFFFFFFULL;
				case 2:
					return 0x000000000000FFFFULL;
				case 1:
					if constexpr ( reg == Register::CH || reg == Register::DH || reg == Register::BH || reg == Register::AH ) {
						return 0x000000000000FF00ULL;
					}
					return 0x00000000000000FFULL;
				default:
					return 0x0000000000000000ULL;
			}
		}

		template <Register reg, size_t size>
		static constexpr uint8_t get_access_shift_internal ( ) noexcept {
			if constexpr ( reg == Register::AH || reg == Register::BH || reg == Register::CH || reg == Register::DH ) {
				return 8;
			}

			return 0;
		}

		// An internal helper to get a register which is known at compile-time with less overhead
		template <KubRegister reg, Register iced_reg, typename Type>
		Type get_reg_internal ( ) {
			if constexpr ( reg == KubRegister::RIP ) {
				const auto current_instr_ip = decoder->last_successful_ip ( );
				const auto current_instr_len = decoder->last_successful_length ( );
				return current_instr_ip + current_instr_len;
			}

			constexpr auto access_mask = get_access_mask_internal<iced_reg, sizeof ( Type )> ( );
			constexpr auto shift = get_access_shift_internal<iced_reg, sizeof ( Type )> ( );
			const auto concrete_full = cpu->registers [ reg ];
			const Type extracted_value = ( concrete_full & access_mask ) >> shift;

			return extracted_value;
		}

		// An internal helper to set a register which is known at compile-time with less overhead
		template <KubRegister reg, Register iced_reg, typename Type>
		void set_reg_internal ( Type value ) {
			const auto old_full = cpu->registers [ reg ];
			constexpr auto access_mask = get_access_mask_internal<iced_reg, sizeof ( Type )> ( );
			constexpr auto shift = get_access_shift_internal<iced_reg, sizeof ( Type )> ( );
			constexpr auto mask = ( ~0ULL >> ( 64 - ( sizeof ( Type ) ) * 8 ) );

			if constexpr ( sizeof ( Type ) == 4 && ( reg >= KubRegister::RAX && reg <= KubRegister::R15 ) ) {
				value &= 0xFFFFFFFFULL;
			}
			else {
				value = ( value & ~access_mask ) | ( ( ( value & mask ) << shift ) & access_mask );
			}

			cpu->registers [ reg ] = value;
		}
	};
}
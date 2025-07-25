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

		uint64_t stack_base ( ) const noexcept {
			return cpu->stack_base;
		}

		uint64_t stack_limit ( ) const noexcept {
			return cpu->stack_base + cpu->stack_size;
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

		// Returns the value of the RIP register
		uint64_t rip ( ) const noexcept {
			return cpu->registers [ KubRegister::RIP ];
		}

		std::size_t fetch_instruction_bytes ( uint64_t addr, uint8_t* buffer, std::size_t max_bytes ) {
			std::size_t fetched = 0;
			uint64_t current = addr;
			while ( fetched < max_bytes ) {
				void* src = memory->translate ( current, PageProtection::EXEC | PageProtection::READ );
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
				return static_cast< Type >( rip ( ) );
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

		template <KubRegister reg, typename Type>
		Type get_reg_direct ( ) {
			if constexpr ( reg == KubRegister::RIP ) {
				return static_cast< Type >( rip ( ) );
			}

			const auto concrete_full = cpu->registers [ reg ];
			return concrete_full;
		}

		// An internal helper to set a register which is known at compile-time with less overhead
		template <KubRegister reg, typename Type>
		void set_reg_direct ( Type value ) {
			const auto old_full = cpu->registers [ reg ];
			cpu->registers [ reg ] = value;
		}

		static constexpr std::array<std::string_view, KubRegister::COUNT> register_names = {
			"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
			"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
			"RIP",
			"DR0", "DR1", "DR2", "DR3", "DR4", "DR5", "DR6", "DR7",
			"CR0", "CR2", "CR3", "CR4", "CR8",
			"ES", "CS", "SS", "DS", "FS", "GS"
		};

		std::array<std::uint64_t, KubRegister::COUNT> register_dump ( ) const noexcept {
			return cpu->registers;
		}

		x86::Flags rflags_dump ( ) const noexcept {
			return cpu->rflags;
		}

		x86::Mxcsr mxcsr_dump ( ) const noexcept {
			return cpu->mxcsr;
		}

		std::vector<std::string> get_register_changes ( const std::array<std::uint64_t, KubRegister::COUNT>& old_registers ) const {
			std::vector<std::string> changes;
			for ( size_t i = 0; i < KubRegister::COUNT; ++i ) {
				if ( cpu->registers [ i ] != old_registers [ i ] && static_cast<KubRegister>(i) != KubRegister::RIP ) {
					std::stringstream ss;
					ss << register_names [ i ] << " 0x" << std::hex << old_registers [ i ] << ";0x" << std::hex << cpu->registers [ i ];
					changes.push_back ( ss.str ( ) );
				}
			}
			return changes;
		}

		std::vector<std::string> get_rflags_changes ( const x86::Flags& old_rflags ) const {
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

		std::vector<std::string> get_mxcsr_changes ( const x86::Mxcsr& old_mxcsr ) const {
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
	};
}
#pragma once

#include <shared/context.hpp>
#include <shared/types.hpp>
#include <bit>
#define USE_FLAG_LOGGER() auto _ = FlagLogger ( &state, effect )
#define KB_PREFIX(name) kb_##name
#define BIND(x) handlers::x = std::bind ( x, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3 )
#define BIND2(x, y) handlers::x = std::bind ( y, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3 )
#define BINDW(x) handlers::winapi::x = std::bind ( KB_PREFIX(x), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4 )
#define NO_FLAG_HANDLER nullptr

namespace mp = boost::multiprecision;
using int128_t = mp::int128_t;
using uint128_t = mp::uint128_t;

namespace helpers
{
	inline uint64_t calculate_mem_addr ( const cs_x86_op& mem_op, capstone::Instruction& instr, EmulationContext& state ) {
		if ( mem_op.type != X86_OP_MEM ) {
			state.exit_due_to_critical_error = true;
			return 0;
		}

		uint64_t address = 0;
		if ( mem_op.mem.base != X86_REG_INVALID ) {
			address = state.get_reg ( mem_op.mem.base, 8 );
		}
		if ( mem_op.mem.index != X86_REG_INVALID ) {
			address += state.get_reg ( mem_op.mem.index, 8 ) * mem_op.mem.scale;
		}
		if ( mem_op.mem.segment != X86_REG_INVALID ) {
			address += state.get_reg ( mem_op.mem.segment, 8 );
		}

		address += mem_op.mem.disp;
		return address;
	}

	inline uint64_t get_target2 ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
		const cs_x86_op* ops = instr.operands ( );

		if ( instr.operand_count ( ) > 0 && ops [ 0 ].type == X86_OP_MEM ) {
			const cs_x86_op& op = ops [ 0 ];
			uint64_t addr = calculate_mem_addr ( op, instr, state );

			if ( parser && parser->is_address_in_iat ( addr ) ) {
				return *( uint64_t* ) addr;
			}

			return state.get_memory ( addr, 8 );
		}
		else if ( instr.operand_count ( ) > 0 && ops [ 0 ].type == X86_OP_REG ) {
			return state.get_reg ( ops [ 0 ].reg );
		}
		else if ( instr.operand_count ( ) > 0 && ops [ 0 ].type == X86_OP_IMM ) {
			return ops [ 0 ].imm;
		}
		else if ( instr.branch_target ( ) != 0 ) {
			return instr.branch_target ( );
		}

		return 0;
	}

	inline void binary_op (
		x86_reg dst, uint64_t src, EmulationContext& state, uint8_t op_size,
		std::function<uint64_t ( uint64_t, uint64_t )> op, const char* op_str,
		std::function<void ( uint64_t, uint64_t, uint8_t, InstructionEffect& )> flag_updater,
		InstructionEffect& effect ) {

		const uint64_t operand_mask = ( op_size == 8 ) ? 0xFFFFFFFFFFFFFFFFULL : ( 1ULL << ( op_size * 8 ) ) - 1;
		const uint64_t src_val_raw = static_cast< uint64_t >( src );
		const uint64_t operand_val = src_val_raw & operand_mask;

		const x86_reg full_reg = state.to_64bit_reg ( dst );
		const uint64_t full_val = state.get_reg ( full_reg, 8 );
		const uint64_t access_mask = state.get_access_mask ( dst, op_size );
		const uint8_t access_shift = state.get_access_shift ( dst, op_size );

		const uint64_t target_val = ( full_val & access_mask ) >> access_shift;
		const uint64_t result_val_unmasked = op ( target_val, operand_val );
		const uint64_t merged_val = ( full_val & ~access_mask ) | ( ( result_val_unmasked << access_shift ) & access_mask );

		state.set_reg ( full_reg, merged_val, 8, effect );

		if ( flag_updater ) {
			flag_updater ( target_val, operand_val, op_size, effect );
		}
	}

	inline uint64_t rebase_executable_address ( EmulationContext& state, uint64_t addr ) {
		if ( addr >= state.windows->loaded_base_address && addr < state.windows->loaded_base_address + state.windows->loaded_module_size ) {
			return addr - state.windows->loaded_base_address + parser->get_image_base ( );
		}
		return addr;
	}

	inline uint64_t resolve_and_switch_target (
		capstone::Instruction& instr,
		EmulationContext& state,
		uint64_t final_target_address,
		InstructionEffect& effect,
		bool is_call
	) {

		if ( final_target_address == 0 ) {
			state.decoder.back ( )->set_ip ( 0 );
			state.exit_due_to_critical_error = true;
			return 0;
		}

		auto import_it = state.windows->imports.find ( final_target_address );
		if ( import_it != state.windows->imports.end ( ) ) {
			std::string dll_name = import_it->second.first;
			std::string func_name = import_it->second.second;

			HMODULE hMod = GetModuleHandleA ( dll_name.c_str ( ) );
			if ( !hMod ) hMod = LoadLibraryA ( dll_name.c_str ( ) );
			if ( !hMod ) {
				state.decoder.back ( )->set_ip ( 0 );
				state.exit_due_to_critical_error = true;
				return 0;
			}

			auto proc_addr = reinterpret_cast< uint64_t >( GetProcAddress ( hMod, func_name.c_str ( ) ) );
			if ( !proc_addr ) {
				state.decoder.back ( )->set_ip ( 0 );
				state.exit_due_to_critical_error = true;
				return 0;
			}

			uint64_t module_base = reinterpret_cast< uint64_t >( hMod );

			if ( state.windows->loaded_modules.find ( module_base ) == state.windows->loaded_modules.end ( ) ) {
				try {
					auto dep_parser = std::make_unique<PE::Parser> ( module_base );
					uint64_t module_size = dep_parser->pe_info_.optional_header.size_of_image;
					const uint8_t* code = reinterpret_cast< const uint8_t* >( module_base );
					state.windows->add_module ( hMod, module_base, module_size, code );
				}
				catch ( const std::exception& ) {
					state.decoder.back ( )->set_ip ( 0 );
					state.exit_due_to_critical_error = true;
					return 0;
				}
			}

			auto* new_decoder = state.get_decoder_for_address ( proc_addr );
			if ( !new_decoder ) {
				state.decoder.back ( )->set_ip ( 0 );
				state.exit_due_to_critical_error = true;
				return 0;
			}
			if ( state.decoder.back ( )->data_ != new_decoder->data_ ) {
				state.decoder.emplace_back ( new_decoder );
			}
			state.decoder.back ( )->set_ip ( proc_addr );
			state.windows->current_module_base = reinterpret_cast< uint64_t >( state.decoder.back ( )->data_ );
			return proc_addr;
		}

		auto* target_decoder = state.get_decoder_for_address ( final_target_address );
		if ( target_decoder ) {
			if ( state.decoder.back ( )->data_ != target_decoder->data_ ) {
				state.decoder.emplace_back ( target_decoder );
			}
			state.decoder.back ( )->set_ip ( final_target_address );
			state.windows->current_module_base = reinterpret_cast< uint64_t >( target_decoder->data_ );
			return final_target_address;
		}

		state.decoder.back ( )->set_ip ( 0 );
		state.exit_due_to_critical_error = true;
		return 0;
	}

	namespace
	{
		template <typename T>
		T handle_operand ( const cs_x86_op& op, capstone::Instruction* instr, EmulationContext& state, uint8_t op_size ) {
			switch ( op.type ) {
				case X86_OP_IMM:
					return static_cast< T >( op.imm );
				case X86_OP_REG:
				{
					x86_reg reg = op.reg;
					if constexpr ( std::is_same_v<T, float> ) {
						if ( reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15 ) {
							return state.get_xmm_float ( reg );
						}
					}
					else if constexpr ( std::is_same_v<T, double> ) {
						if ( reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15 ) {
							return state.get_xmm_double ( reg );
						}
					}
					else if constexpr ( std::is_same_v<T, uint128_t> ) {
						if ( reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15 ) {
							return state.get_xmm_raw ( reg );
						}
					}
					else if constexpr ( std::is_same_v<T, uint256_t> ) {
						if ( reg >= X86_REG_YMM0 && reg <= X86_REG_YMM15 ) {
							return state.get_zmm_raw ( reg );
						}
					}
					else if constexpr ( std::is_same_v<T, uint512_t> ) {
						if ( reg >= X86_REG_YMM0 && reg <= X86_REG_YMM15 ) {
							return state.get_ymm_raw ( reg );
						}
					}
					else {
						return static_cast< T >( state.get_reg ( reg, op_size ) );
					}
				}
				case X86_OP_MEM:
				{
					uint64_t addr = calculate_mem_addr ( op, *instr, state );
					if constexpr ( std::is_same_v<T, uint128_t> ) {
						return state.get_memory_128 ( addr );
					}
					if constexpr ( std::is_same_v<T, uint256_t> ) {
						return state.get_memory_256 ( addr );
					}
					if constexpr ( std::is_same_v<T, uint512_t> ) {
						return state.get_memory_512 ( addr );
					}
					else {
						return static_cast< T > ( state.get_memory ( addr, op_size ) );
					}
				}
				default:
					break;
			}
			return T {};
		}
	}

	template <typename T>
	T get_src ( capstone::Instruction* instr, size_t idx, EmulationContext& state, uint8_t op_size ) {
		const cs_x86_op* ops = instr->operands ( );
		return handle_operand<T> ( ops [ idx ], instr, state, op_size );
	}

	template <typename T>
	T get_operand_value (
			capstone::Instruction& instr,
			size_t operand_index,
			EmulationContext& state,
			InstructionEffect& effect
	) {
		const cs_x86_op& op = instr.operands ( ) [ operand_index ];
		uint8_t op_size = op.size;

		switch ( op.type ) {
			case X86_OP_REG:
			{
				if constexpr ( std::is_same_v<T, uint128_t> ) {
					if ( op.reg >= X86_REG_XMM0 && op.reg <= X86_REG_XMM15 ) {
						return state.get_xmm_raw ( op.reg );
					}
					else { state.exit_due_to_critical_error = true; return T {}; }
				}
				else if constexpr ( std::is_same_v<T, float> ) {
					if ( op.reg >= X86_REG_XMM0 && op.reg <= X86_REG_XMM15 ) {
						return state.get_xmm_float ( op.reg );
					}
					else { state.exit_due_to_critical_error = true; return T {}; }
				}
				else if constexpr ( std::is_same_v<T, double> ) {
					if ( op.reg >= X86_REG_XMM0 && op.reg <= X86_REG_XMM15 ) {
						return state.get_xmm_double ( op.reg );
					}
					else { state.exit_due_to_critical_error = true; return T {}; }
				}
				else {
					uint64_t val = state.get_reg ( op.reg, op_size );
					return static_cast< T >( val );
				}
			}
			case X86_OP_MEM:
			{
				uint64_t addr = calculate_mem_addr ( op, instr, state );
				if constexpr ( std::is_same_v<T, uint128_t> ) {
					return state.get_memory_128 ( addr );
				}
				else {
					uint64_t mem_val = state.get_memory ( addr, op_size );
					if constexpr ( std::is_same_v<T, float> ) {
						if ( op_size == 4 ) return std::bit_cast< float >( static_cast< uint32_t >( mem_val ) );
						state.exit_due_to_critical_error = true; return T {};
					}
					else if constexpr ( std::is_same_v<T, double> ) {
						if ( op_size == 8 ) return std::bit_cast< double >( mem_val );
						state.exit_due_to_critical_error = true; return T {};
					}
					else {
						return static_cast< T >( mem_val );
					}
				}
			}
			case X86_OP_IMM:
			{
				return static_cast< T >( op.imm );
			}
			default:
				break;
		}
		return {};
	}

	template <typename T>
	void set_dst_value (
			capstone::Instruction& instr,
			size_t operand_index,
			const T& value,
			EmulationContext& state,
			InstructionEffect& effect
	) {
		const cs_x86_op& dst = instr.operands ( ) [ operand_index ];
		uint8_t op_size = dst.size;

		switch ( dst.type ) {
			case X86_OP_REG:
			{
				if constexpr ( std::is_same_v<T, uint128_t> ) {
					if ( dst.reg >= X86_REG_XMM0 && dst.reg <= X86_REG_XMM15 ) {
						state.set_xmm_raw ( dst.reg, value, effect );
					}
					else { state.exit_due_to_critical_error = true; }
				}
				else if constexpr ( std::is_same_v<T, float> ) {
					if ( dst.reg >= X86_REG_XMM0 && dst.reg <= X86_REG_XMM15 ) {
						state.set_xmm_float ( dst.reg, value, effect );
					}
					else { state.exit_due_to_critical_error = true; }
				}
				else if constexpr ( std::is_same_v<T, double> ) {
					if ( dst.reg >= X86_REG_XMM0 && dst.reg <= X86_REG_XMM15 ) {
						state.set_xmm_double ( dst.reg, value, effect );
					}
					else { state.exit_due_to_critical_error = true; }
				}
				else {
					state.set_reg ( dst.reg, static_cast< uint64_t >( value ), op_size, effect );
				}
				break;
			}
			case X86_OP_MEM:
			{
				uint64_t addr = calculate_mem_addr ( dst, instr, state );
				bool is_stack = state.is_within_stack_bounds ( addr, op_size );

				if constexpr ( std::is_same_v<T, uint128_t> ) {
					if ( is_stack ) { /* Error? set_stack doesn't handle 128 */ state.exit_due_to_critical_error = true; }
					else state.set_memory_128 ( addr, value, effect );
				}
				else if constexpr ( std::is_same_v<T, float> ) {
					if ( is_stack ) state.set_stack ( addr, std::bit_cast< uint32_t >( value ), effect, 4 );
					else state.set_memory ( addr, std::bit_cast< uint32_t >( value ), 4, effect );
				}
				else if constexpr ( std::is_same_v<T, double> ) {
					if ( is_stack ) state.set_stack ( addr, std::bit_cast< uint64_t >( value ), effect, 8 );
					else state.set_memory ( addr, std::bit_cast< uint64_t >( value ), 8, effect );
				}
				else {
					if ( is_stack ) state.set_stack ( addr, static_cast< uint64_t >( value ), effect, op_size );
					else state.set_memory ( addr, static_cast< uint64_t >( value ), op_size, effect );
				}
				effect.modified_mem.insert ( addr );
				break;
			}
			default:
				state.exit_due_to_critical_error = true;
				break;
		}
	}

	inline void handle_unary_op (
		capstone::Instruction& instr,
		EmulationContext& state,
		InstructionEffect& effect,
		std::function<uint64_t ( uint64_t )> operation,
		std::function<void ( EmulationContext&, uint64_t, uint8_t, InstructionEffect& )> flag_updater
	) {
		const cs_x86_op* ops = instr.operands ( );
		uint8_t op_size = ops [ 0 ].size;

		uint64_t dst_val = helpers::get_operand_value<uint64_t> ( instr, 0, state, effect );
		if ( state.exit_due_to_critical_error ) return;

		uint64_t result = operation ( dst_val );

		helpers::set_dst_value<uint64_t> ( instr, 0, result, state, effect );
		if ( state.exit_due_to_critical_error ) return;

		if ( flag_updater ) {
			GET_OPERAND_MASK ( operand_mask, op_size );
			flag_updater ( state, dst_val & operand_mask, op_size, effect );
		}
	}

	inline void handle_cmovcc (
			capstone::Instruction& instr,
			EmulationContext& state,
			InstructionEffect& effect,
			std::function<bool ( const EmulationContext& )> condition
	) {
		if ( condition ( state ) ) {
			const cs_x86_op* ops = instr.operands ( );
			uint8_t op_size = ops [ 0 ].size;
			uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1, state, effect );
			if ( state.exit_due_to_critical_error ) return;

			state.set_reg ( ops [ 0 ].reg, src_val, op_size, effect );
		}
	}

	inline void handle_binary_op (
		 capstone::Instruction& instr,
		 EmulationContext& state,
		 InstructionEffect& effect,
		 std::function<uint64_t ( uint64_t, uint64_t )> operation,
		 std::function<void ( EmulationContext&, uint64_t, uint64_t, uint8_t, InstructionEffect& )> flag_updater
	) {
		const cs_x86_op* ops = instr.operands ( );
		uint8_t op_size = ops [ 0 ].size;

		uint64_t dst_val = helpers::get_operand_value<uint64_t> ( instr, 0, state, effect );
		uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1, state, effect );
		if ( state.exit_due_to_critical_error ) {
			return;
		}
		uint64_t result = operation ( dst_val, src_val );

		helpers::set_dst_value<uint64_t> ( instr, 0, result, state, effect );
		if ( state.exit_due_to_critical_error ) {
			return;
		}
		if ( flag_updater ) {
			GET_OPERAND_MASK ( operand_mask, op_size );
			flag_updater ( state, dst_val & operand_mask, src_val & operand_mask, op_size, effect );
		}
	}

	inline void handle_setcc (
			capstone::Instruction& instr,
			EmulationContext& state,
			InstructionEffect& effect,
			std::function<bool ( const EmulationContext& )> condition
	) {
		const cs_x86_op* ops = instr.operands ( );
		uint8_t result = condition ( state ) ? 1 : 0;

		helpers::set_dst_value<uint8_t> ( instr, 0, result, state, effect );
		if ( state.exit_due_to_critical_error ) {
			return;
		}
	}

	inline int64_t sign_extend ( uint64_t val, uint8_t size_bytes ) {
		if ( size_bytes >= 8 ) return static_cast< int64_t >( val );
		int bits = size_bytes * 8;
		uint64_t mask = ( 1ULL << bits ) - 1;
		uint64_t sign_bit_mask = 1ULL << ( bits - 1 );
		uint64_t val_masked = val & mask;
		if ( ( val_masked & sign_bit_mask ) != 0 ) {
			uint64_t extension = ~mask;
			return static_cast< int64_t >( val_masked | extension );
		}
		else {
			return static_cast< int64_t >( val_masked );
		}
	}

	inline int128_t sign_extend ( uint128_t val, uint8_t size_bytes ) {
		if ( size_bytes >= 16 ) return int128_t ( val );
		int bits = size_bytes * 8;
		uint128_t mask = ( uint128_t ( 1 ) << bits ) - 1;
		uint128_t sign_bit_mask = uint128_t ( 1 ) << ( bits - 1 );
		uint128_t val_masked = val & mask;
		if ( ( val_masked & sign_bit_mask ) != 0 ) {
			uint128_t extension = ~mask;
			return int128_t ( val_masked | extension );
		}
		else {
			return int128_t ( val_masked );
		}
	}

	template uint8_t get_src<uint8_t> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );
	template uint16_t get_src<uint16_t> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );
	template uint32_t get_src<uint32_t> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );
	template uint64_t get_src<uint64_t> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );
	template uint128_t get_src<uint128_t> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );
	template float get_src<float> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );
	template double get_src<double> ( capstone::Instruction*, size_t, EmulationContext&, uint8_t );

	template uint8_t get_operand_value<uint8_t> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );
	template uint16_t get_operand_value<uint16_t> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );
	template uint32_t get_operand_value<uint32_t> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );
	template uint64_t get_operand_value<uint64_t> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );
	template uint128_t get_operand_value<uint128_t> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );
	template float get_operand_value<float> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );
	template double get_operand_value<double> ( capstone::Instruction&, size_t, EmulationContext&, InstructionEffect& );

	template void set_dst_value<uint8_t> ( capstone::Instruction&, size_t, const uint8_t&, EmulationContext&, InstructionEffect& );
	template void set_dst_value<uint16_t> ( capstone::Instruction&, size_t, const uint16_t&, EmulationContext&, InstructionEffect& );
	template void set_dst_value<uint32_t> ( capstone::Instruction&, size_t, const uint32_t&, EmulationContext&, InstructionEffect& );
	template void set_dst_value<uint64_t> ( capstone::Instruction&, size_t, const uint64_t&, EmulationContext&, InstructionEffect& );
	template void set_dst_value<uint128_t> ( capstone::Instruction&, size_t, const uint128_t&, EmulationContext&, InstructionEffect& );
	template void set_dst_value<float> ( capstone::Instruction&, size_t, const float&, EmulationContext&, InstructionEffect& );
	template void set_dst_value<double> ( capstone::Instruction&, size_t, const double&, EmulationContext&, InstructionEffect& );

	void bind_arithmetic ( );
	void bind_bit ( );
	void bind_cf ( );
	void bind_jx ( );
	void bind_cpu ( );
	void bind_fpu ( );
	void bind_avx ( );
	void bind_data ( );
	void bind_logical ( );
	void bind_frame ( );
	void bind_winapi ( );
};
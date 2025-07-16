#pragma once

#include <context/KUBERA.hpp>

namespace helpers
{
	using namespace kubera;
	uint64_t calculate_mem_addr ( const iced::Instruction& instr, KUBERA& state );

	bool divide_unsigned_boost ( uint128_t dividend, uint64_t divisor, size_t op_size, uint64_t& quotient, uint64_t& remainder );
	bool divide_signed_boost ( int128_t dividend, int64_t divisor, size_t op_size, int64_t& quotient, int64_t& remainder );

	template <typename Type>
	Type get_operand_value ( const iced::Instruction& instr, size_t operand_index, KUBERA& state ) {
		switch ( instr.op_kind_simple ( operand_index ) ) {
			case OpKindSimple::Immediate:
				return static_cast< Type >( instr.immediate ( ) );
			case OpKindSimple::Register:
			{
				const auto reg = instr.op_reg ( operand_index );
				if constexpr ( std::is_same_v<Type, float> ) {
					if ( reg >= Register::XMM0 && reg <= Register::XMM31 ) {
						return state.get_xmm_float ( reg );
					}
				}
				else if constexpr ( std::is_same_v<Type, double> ) {
					if ( reg >= Register::XMM0 && reg <= Register::XMM31 ) {
						return state.get_xmm_double ( reg );
					}
				}
				else if constexpr ( std::is_same_v<Type, uint128_t> ) {
					if ( reg >= Register::XMM0 && reg <= Register::XMM31 ) {
						return state.get_xmm_raw ( reg );
					}
				}
				else if constexpr ( std::is_same_v<Type, uint256_t> ) {
					if ( reg >= Register::YMM0 && reg <= Register::YMM31 ) {
						return state.get_ymm_raw ( reg );
					}
				}
				else if constexpr ( std::is_same_v<Type, uint512_t> ) {
					if ( reg >= Register::ZMM0 && reg <= Register::ZMM31 ) {
						return state.get_zmm_raw ( reg );
					}
				}
				else {
					return static_cast< Type >( state.get_reg ( reg, sizeof ( Type ) ) );
				}
			}
			case OpKindSimple::Memory:
			{
				uint64_t address = calculate_mem_addr ( instr, state );
				return state.get_memory<Type> ( address );
			}
			case OpKindSimple::Invalid:
				break;
			default:
				return Type ( instr.branch_target ( ) );
		}
		return Type {};
	}
	template <typename Type>
	void set_operand_value ( const iced::Instruction& instr, size_t operand_index, Type value, KUBERA& state ) {
		switch ( instr.op_kind_simple ( operand_index ) ) {
			case OpKindSimple::Register:
			{
				const auto reg = instr.op_reg ( operand_index );
				if constexpr ( std::is_same_v<Type, float> ) {
					if ( reg >= Register::XMM0 && reg <= Register::XMM31 ) {
						return state.set_xmm_float ( reg, value );
					}
				}
				else if constexpr ( std::is_same_v<Type, double> ) {
					if ( reg >= Register::XMM0 && reg <= Register::XMM31 ) {
						return state.set_xmm_double ( reg, value );
					}
				}
				else if constexpr ( std::is_same_v<Type, uint128_t> ) {
					if ( reg >= Register::XMM0 && reg <= Register::XMM31 ) {
						return state.set_xmm_raw ( reg, value );
					}
				}
				else if constexpr ( std::is_same_v<Type, uint256_t> ) {
					if ( reg >= Register::YMM0 && reg <= Register::YMM31 ) {
						return state.set_ymm_raw ( reg, value );
					}
				}
				else if constexpr ( std::is_same_v<Type, uint512_t> ) {
					if ( reg >= Register::ZMM0 && reg <= Register::ZMM31 ) {
						return state.set_zmm_raw ( reg, value );
					}
				}
				else {
					return state.set_reg ( reg, value, sizeof ( Type ) );
				}
			}
			case OpKindSimple::Memory:
			{
				uint64_t address = calculate_mem_addr ( instr, state );
				return state.set_memory<Type> ( address, value );
			}
			default:
				break;
		}
	}
};
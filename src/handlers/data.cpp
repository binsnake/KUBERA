#include "../../emulator.hpp"
#include <bit>
#include "helpers.hpp"

using namespace kubera;
/// MOV - Move
/// Copies the value from the source operand to the destination operand without affecting flags.
void handlers::mov ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t value = src_val & mask;

	if ( instr.op0_kind ( ) == OpKindSimple::Register ) {
		helpers::set_operand_value<uint64_t> ( instr, 0u, value, context );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		context.set_memory<uint64_t> ( addr, value );
		return;
	}

	// !TODO(exception)
}

/// MOVABS - Move Absolute
/// Moves a 64-bit immediate value to a 64-bit general-purpose register without affecting flags.
void handlers::movabs ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t imm_val = instr.immediate ( );
	const size_t op_size = 8; // MOVABS is always 64-bit
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t value = imm_val & mask;

	if ( instr.op0_kind ( ) == OpKindSimple::Register ) {
		helpers::set_operand_value<uint64_t> ( instr, 0u, value, context );
		return;
	}

	// !TODO(exception)
}

/// MOVAPS - Move Aligned Packed Single-Precision Floating-Point
/// Moves 128 bits of packed single-precision floating-point values from the source to the destination, requiring 16-byte alignment for memory operands, without affecting flags.
void handlers::movaps ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Register ) {
		const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
		context.set_xmm_raw ( instr.op0_reg ( ), src_val );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		if ( addr % 16 != 0 ) {
			// !TODO(exception)
			return;
		}
		const uint128_t src_val = context.get_memory<uint128_t> ( addr );
		context.set_xmm_raw ( instr.op0_reg ( ), src_val );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory && instr.op1_kind ( ) == OpKindSimple::Register ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		if ( addr % 16 != 0 ) {
			// !TODO(exception)
			return;
		}
		const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( )  );
		context.set_memory<uint128_t> ( addr, src_val );
		return;
	}

	// !TODO(exception)
}

/// MOVZX - Move with Zero-Extend
/// Moves the source operand (byte or word) to the destination operand (word, doubleword, or quadword), zero-extending the value to fill the destination, without affecting flags.
void handlers::movzx ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t dst_size = instr.op0_size ( );
	const size_t src_size = instr.op1_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t src_mask = GET_OPERAND_MASK ( src_size );
	const uint64_t value = src_val & src_mask;

	// Validate operand sizes
	if ( src_size == 1 && ( dst_size == 2 || dst_size == 4 || dst_size == 8 ) ||
		src_size == 2 && ( dst_size == 4 || dst_size == 8 ) ||
		src_size == 4 && dst_size == 8 ) {
		if ( instr.op0_kind ( ) == OpKindSimple::Register ) {
			helpers::set_operand_value<uint64_t> ( instr, 0u, value, context );
			return;
		}
	}

	// !TODO(exception)
}

/// MOVD - Move Doubleword
/// Moves a 32-bit value between a general-purpose register and an XMM register, or between memory and an XMM register, without affecting flags.
void handlers::movd ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	if ( op_size != 4 ) {
		// !TODO(exception)
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Register ) {
		if ( instr.op0_reg ( ) >= Register::XMM0 && instr.op0_reg ( ) <= Register::XMM31 &&
				instr.op1_reg ( ) <= Register::R15 ) {
			const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
			const uint128_t xmm_val = static_cast< uint128_t >( src_val & 0xFFFFFFFF );
			context.set_xmm_raw ( instr.op0_reg ( ), xmm_val );
			return;
		}
		if ( instr.op0_reg ( ) <= Register::R15 &&
				instr.op1_reg ( ) >= Register::XMM0 && instr.op1_reg ( ) <= Register::XMM31 ) {
			const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
			const uint64_t val = static_cast< uint64_t >( src_val & 0xFFFFFFFF );
			helpers::set_operand_value<uint64_t> ( instr, 0u, val, context );
			return;
		}
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Memory ) {
		if ( instr.op0_reg ( ) >= Register::XMM0 && instr.op0_reg ( ) <= Register::XMM31 ) {
			const uint64_t addr = helpers::calculate_mem_addr( instr, context );
			if ( addr % 4 != 0 ) {
				// !TODO(exception)
				return;
			}
			const uint64_t src_val = context.get_memory<uint32_t> ( addr );
			const uint128_t xmm_val = static_cast< uint128_t >( src_val );
			context.set_xmm_raw ( instr.op0_reg ( ), xmm_val );
			return;
		}
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory && instr.op1_kind ( ) == OpKindSimple::Register ) {
		if ( instr.op1_reg ( ) >= Register::XMM0 && instr.op1_reg ( ) <= Register::XMM31 ) {
			const uint64_t addr = helpers::calculate_mem_addr( instr, context );
			if ( addr % 4 != 0 ) {
				// !TODO(exception)
				return;
			}
			const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
			const uint32_t val = static_cast< uint32_t >( src_val & 0xFFFFFFFF );
			context.set_memory<uint32_t> ( addr, val );
			return;
		}
	}

	// !TODO(exception)
}

/// LEA - Load Effective Address
/// Computes the effective address of the source memory operand and stores it in the destination register, without affecting flags.
void handlers::lea ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t dst_size = instr.op0_size ( );
	if ( instr.op0_kind ( ) != OpKindSimple::Register ) {
		// !TODO(exception)
		return;
	}

	uint64_t effective_address = helpers::calculate_mem_addr ( instr, context );

	helpers::set_operand_value<uint64_t> ( instr, 0u, effective_address, context );
}

/// MOVSX - Move with Sign-Extend
/// Moves the source operand (byte or word) to the destination register (word, doubleword, or quadword), sign-extending the value, without affecting flags.
void handlers::movsx ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t dst_size = instr.op0_size ( );
	const size_t src_size = instr.op1_size ( );
	if ( instr.op0_kind ( ) != OpKindSimple::Register ) {
		// !TODO(exception)
		return;
	}

	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t src_mask = GET_OPERAND_MASK ( src_size );
	const uint64_t masked_val = src_val & src_mask;
	const int64_t signed_val = SIGN_EXTEND ( masked_val, src_size );

	helpers::set_operand_value<uint64_t> ( instr, 0u, static_cast< uint64_t >( signed_val ), context );
}

/// MOVSXD - Move with Sign-Extend Doubleword
/// Moves a doubleword source operand to a quadword destination register, sign-extending the value, without affecting flags.
void handlers::movsxd ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t dst_size = instr.op0_size ( );
	const size_t src_size = instr.op1_size ( );
	if ( instr.op0_kind ( ) != OpKindSimple::Register || dst_size != 8 || src_size != 4 ) {
		// !TODO(exception)
		return;
	}

	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t src_mask = GET_OPERAND_MASK ( src_size );
	const uint64_t masked_val = src_val & src_mask;
	const int64_t signed_val = SIGN_EXTEND ( masked_val, src_size );

	helpers::set_operand_value<uint64_t> ( instr, 0u, static_cast< uint64_t >( signed_val ), context );
}

/// XCHG - Exchange
/// Exchanges the contents of the source and destination operands, which may be registers or memory, without affecting flags.
void handlers::xchg ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t val1 = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t val2 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t masked_val1 = val1 & mask;
	const uint64_t masked_val2 = val2 & mask;

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Register ) {
		helpers::set_operand_value<uint64_t> ( instr, 0u, masked_val2, context );
		helpers::set_operand_value<uint64_t> ( instr, 1u, masked_val1, context );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory && instr.op1_kind ( ) == OpKindSimple::Register ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		context.set_memory<uint64_t> ( addr, masked_val2 );
		helpers::set_operand_value<uint64_t> ( instr, 1u, masked_val1, context );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		context.set_memory<uint64_t> ( addr, masked_val1 );
		helpers::set_operand_value<uint64_t> ( instr, 0u, masked_val2, context );
		return;
	}

	// !TODO(exception)
}

/// MOVUPS - Move Unaligned Packed Single-Precision Floating-Point
/// Moves 128 bits of packed single-precision floating-point values from the source to the destination, without alignment requirements, and without affecting flags.
void handlers::movups ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Register ) {
		const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
		context.set_xmm_raw ( instr.op0_reg ( ), src_val );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		const uint128_t src_val = context.get_memory<uint128_t> ( addr );
		context.set_xmm_raw ( instr.op0_reg ( ), src_val );
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory && instr.op1_kind ( ) == OpKindSimple::Register ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
		context.set_memory<uint128_t> ( addr, src_val );
		return;
	}

	// !TODO(exception)
}

/// MOVQ - Move Quadword
/// Moves a 64-bit value between XMM registers, general-purpose registers, or memory, without affecting flags.
void handlers::movq ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	if ( op_size != 8 ) {
		// !TODO(exception)
		return;
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Register ) {
		if ( instr.op0_reg ( ) >= Register::XMM0 && instr.op0_reg ( ) <= Register::XMM31 &&
				instr.op1_reg ( ) >= Register::XMM0 && instr.op1_reg ( ) <= Register::XMM31 ) {
			const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
			const uint64_t lo64 = static_cast< uint64_t >( src_val & 0xFFFFFFFFFFFFFFFF );
			const uint128_t dst_val = static_cast< uint128_t >( lo64 );
			context.set_xmm_raw ( instr.op0_reg ( ), dst_val );
			return;
		}
		if ( instr.op0_reg ( ) <= Register::R15 &&
				instr.op1_reg ( ) >= Register::XMM0 && instr.op1_reg ( ) <= Register::XMM31 ) {
			const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
			const uint64_t lo64 = static_cast< uint64_t >( src_val & 0xFFFFFFFFFFFFFFFF );
			helpers::set_operand_value<uint64_t> ( instr, 0u, lo64, context );
			return;
		}
		if ( instr.op0_reg ( ) >= Register::XMM0 && instr.op0_reg ( ) <= Register::XMM31 &&
				instr.op1_reg ( ) <= Register::R15 ) {
			const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
			const uint128_t dst_val = static_cast< uint128_t >( src_val );
			context.set_xmm_raw ( instr.op0_reg ( ), dst_val );
			return;
		}
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Register && instr.op1_kind ( ) == OpKindSimple::Memory ) {
		if ( instr.op0_reg ( ) >= Register::XMM0 && instr.op0_reg ( ) <= Register::XMM31 ) {
			const uint64_t addr = helpers::calculate_mem_addr( instr, context );
			const uint64_t src_val = context.get_memory<uint64_t> ( addr );
			const uint128_t dst_val = static_cast< uint128_t >( src_val );
			context.set_xmm_raw ( instr.op0_reg ( ), dst_val );
			return;
		}
	}

	if ( instr.op0_kind ( ) == OpKindSimple::Memory && instr.op1_kind ( ) == OpKindSimple::Register ) {
		if ( instr.op1_reg ( ) >= Register::XMM0 && instr.op1_reg ( ) <= Register::XMM31 ) {
			const uint64_t addr = helpers::calculate_mem_addr( instr, context );
			const uint128_t src_val = context.get_xmm_raw ( instr.op1_reg ( ) );
			const uint64_t lo64 = static_cast< uint64_t >( src_val & 0xFFFFFFFFFFFFFFFF );
			context.set_memory<uint64_t> ( addr, lo64 );
			return;
		}
	}

	// !TODO(exception)
}

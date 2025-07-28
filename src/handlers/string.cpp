#include "../../emulator.hpp"
#include <bit>
#include "helpers.hpp"

using namespace kubera;

void movs_handler ( const iced::Instruction& instr, KUBERA& context, uint8_t elem_size ) {
	const bool rep = instr.rep_prefix ( );
	const uint64_t count = rep ? context.get_reg ( Register::RCX, 8 ) : 1;
	if ( count == 0 ) {
		return;
	}

	const bool df = context.get_flags ( ).DF;
	const int64_t step = df ? -static_cast< int64_t >( elem_size ) : static_cast< int64_t >( elem_size );
	uint64_t rsi = context.get_reg ( Register::RSI, 8 );
	uint64_t rdi = context.get_reg ( Register::RDI, 8 );

	for ( uint64_t i = 0; i < count; ++i ) {
		const uint64_t src_addr = rsi + i * step;
		const uint64_t dst_addr = rdi + i * step;

		if ( elem_size == 1 ) {
			const uint8_t val = context.get_memory<uint8_t> ( src_addr );
			context.set_memory<uint8_t> ( dst_addr, val );
		}
		else if ( elem_size == 2 ) {
			const uint16_t val = context.get_memory<uint16_t> ( src_addr );
			context.set_memory<uint16_t> ( dst_addr, val );
		}
		else if ( elem_size == 4 ) {
			const uint32_t val = context.get_memory<uint32_t> ( src_addr );
			context.set_memory<uint32_t> ( dst_addr, val );
		}
		else if ( elem_size == 8 ) {
			const uint64_t val = context.get_memory<uint64_t> ( src_addr );
			context.set_memory<uint64_t> ( dst_addr, val );
		}
		else {
			// !TODO(exception)
			return;
		}
	}

	context.set_reg ( Register::RSI, rsi + count * step, 8 );
	context.set_reg ( Register::RDI, rdi + count * step, 8 );
	if ( rep ) {
		context.set_reg ( Register::RCX, 0, 8 );
	}
}

/// MOVS - Move String
/// Copies data of the specified size (byte, word, doubleword, or quadword) from the source address (RSI) to the destination address (RDI), updating RSI and RDI based on DF, and RCX if REP prefix is used, without affecting flags.
void handlers::movs ( const iced::Instruction& instr, KUBERA& context ) {
	const uint8_t elem_size = static_cast< uint8_t >( instr.op0_size ( ) );
	movs_handler ( instr, context, elem_size );
}

/// MOVSB - Move String Byte
/// Copies a byte from the source address (RSI) to the destination address (RDI), updating RSI and RDI based on DF, and RCX if REP prefix is used, without affecting flags.
void handlers::movsb ( const iced::Instruction& instr, KUBERA& context ) {
	movs_handler ( instr, context, 1 );
}

/// MOVSW - Move String Word
/// Copies a word (2 bytes) from the source address (RSI) to the destination address (RDI), updating RSI and RDI based on DF, and RCX if REP prefix is used, without affecting flags.
void handlers::movsw ( const iced::Instruction& instr, KUBERA& context ) {
	movs_handler ( instr, context, 2 );
}

/// MOVSD - Move String Doubleword
/// Copies a doubleword (4 bytes) from the source address (RSI) to the destination address (RDI), updating RSI and RDI based on DF, and RCX if REP prefix is used, without affecting flags.
void handlers::movsd ( const iced::Instruction& instr, KUBERA& context ) {
	movs_handler ( instr, context, 4 );
}

/// MOVSQ - Move String Quadword
/// Copies a quadword (8 bytes) from the source address (RSI) to the destination address (RDI), updating RSI and RDI based on DF, and RCX if REP prefix is used, without affecting flags.
void handlers::movsq ( const iced::Instruction& instr, KUBERA& context ) {
	movs_handler ( instr, context, 8 );
}

/// STOS - Store String
/// Stores a value from RAX (byte, word, doubleword, or quadword) to the destination address (RDI), updating RDI based on DF, and RCX if REP prefix is used, without affecting flags.
void handlers::stos ( const iced::Instruction& instr, KUBERA& context ) {
	const uint8_t elem_size = static_cast< uint8_t >( instr.op0_size ( ) );
	const bool rep = instr.rep_prefix ( );
	const uint64_t count = rep ? context.get_reg ( Register::RCX, 8 ) : 1;
	if ( count == 0 ) {
		if ( rep ) {
			context.set_reg ( Register::RCX, 0, 8 );
		}
		return;
	}

	const bool df = context.get_flags ( ).DF;
	const int64_t step = df ? -static_cast< int64_t >( elem_size ) : static_cast< int64_t >( elem_size );
	const uint64_t rdi = context.get_reg ( Register::RDI, 8 );
	const uint64_t rax = context.get_reg ( Register::RAX, elem_size );
	const uint64_t mask = GET_OPERAND_MASK ( elem_size );
	const uint64_t value = rax & mask;

	for ( uint64_t i = 0; i < count; ++i ) {
		const uint64_t dst_addr = rdi + i * step;

		if ( elem_size == 1 ) {
			context.set_memory<uint8_t> ( dst_addr, static_cast< uint8_t > ( value ) );
		}
		else if ( elem_size == 2 ) {
			context.set_memory<uint16_t> ( dst_addr, static_cast< uint16_t >( value ) );
		}
		else if ( elem_size == 4 ) {
			context.set_memory<uint32_t> ( dst_addr, static_cast< uint32_t >( value ) );
		}
		else if ( elem_size == 8 ) {
			context.set_memory<uint64_t> ( dst_addr, value );
		}
		else {
			// !TODO(exception)
			return;
		}
	}

	context.set_reg ( Register::RDI, rdi + count * step, 8 );
	if ( rep ) {
		context.set_reg ( Register::RCX, 0, 8 );
	}
}

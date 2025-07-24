#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;

/// ENTER - Enter Procedure
/// Allocates a stack frame by pushing the current RBP, setting RBP to the new RSP, and reserving space for local variables and optional nesting levels, without affecting flags.
void handlers::enter ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t size = instr.immediate ( );
	const uint64_t nesting = instr.immediate2 ( );
	const size_t op_size = 8;

	if ( nesting != 0 ) {
		// !TODO(exception)
		return;
	}

	uint64_t current_rsp = context.get_reg ( Register::RSP, 8 );
	const uint64_t current_rbp = context.get_reg ( Register::RBP, 8 );

	current_rsp -= op_size;
	if ( !context.is_within_stack_bounds ( current_rsp, op_size ) ) {
		// !TODO(exception)
		return;
	}
	context.set_stack<uint64_t> ( current_rsp, current_rbp );
	context.set_reg ( Register::RBP, current_rsp, op_size );

	current_rsp -= size;
	if ( !context.is_within_stack_bounds ( current_rsp, size ) ) {
		// !TODO(exception)
		return;
	}
	context.set_reg ( Register::RSP, current_rsp, op_size );
}

/// LEAVE - Leave Procedure
/// Restores the stack frame by setting RSP to RBP, popping RBP from the stack, and adjusting RSP, without affecting flags.
void handlers::leave ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = 8; // LEAVE uses 64-bit stack operations
	const uint64_t current_rbp = context.get_reg ( Register::RBP, op_size );
	const uint64_t saved_rbp = context.get_stack<uint64_t> ( current_rbp );

	if ( !context.is_within_stack_bounds ( current_rbp, op_size ) ) {
		// !TODO(exception)
		return;
	}

	context.set_reg ( Register::RSP, current_rbp, op_size );
	context.set_reg ( Register::RBP, saved_rbp, op_size );
	context.set_reg ( Register::RSP, current_rbp + op_size, op_size );
}

/// PUSHFQ - Push Flags (Quadword)
/// Pushes the 64-bit RFLAGS register onto the stack, without affecting flags.
void handlers::pushfq ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = 8; // PUSHFQ pushes 64-bit RFLAGS
	uint64_t current_rsp = context.get_reg ( Register::RSP, op_size );
	current_rsp -= op_size;

	if ( !context.is_within_stack_bounds ( current_rsp, op_size ) ) {
		// !TODO(exception)
		return;
	}

	const uint64_t rflags = context.get_rflags ( );
	context.set_stack<uint64_t> ( current_rsp, rflags );
	context.set_reg ( Register::RSP, current_rsp, op_size );
}

/// POPFQ - Pop Flags (Quadword)
/// Pops a 64-bit value from the stack into the RFLAGS register, modifying CF, PF, AF, ZF, SF, TF, IF, DF, OF, IOPL, NT, RF, VM, AC, VIF, VIP, and ID flags.
void handlers::popfq ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = 8; // POPFQ pops 64-bit RFLAGS
	const uint64_t current_rsp = context.get_reg ( Register::RSP, op_size );

	if ( !context.is_within_stack_bounds ( current_rsp, op_size ) ) {
		// !TODO(exception)
		return;
	}

	const uint64_t rflags = context.get_stack<uint64_t> ( current_rsp );
	context.set_rflags ( rflags );
	context.set_reg ( Register::RSP, current_rsp + op_size, op_size );
}

/// PUSH - Push onto Stack
/// Pushes a register, memory, or immediate value onto the stack, without affecting flags.
void handlers::push ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t value = src_val & mask;

	uint64_t current_rsp = context.get_reg ( Register::RSP, 8 );
	current_rsp -= 8; // Stack operations are 8 bytes

	if ( !context.is_within_stack_bounds ( current_rsp, 8 ) ) {
		// !TODO(exception)
		return;
	}

	context.set_stack<uint64_t> ( current_rsp, value );
	context.set_reg ( Register::RSP, current_rsp, 8 );
}

/// POP - Pop from Stack
/// Pops a value from the stack into a register or memory, without affecting flags.
void handlers::pop ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = instr.op0_size ( );
	const uint64_t current_rsp = context.get_reg ( Register::RSP, 8 );

	if ( !context.is_within_stack_bounds ( current_rsp, 8 ) ) {
		// !TODO(exception)
		return;
	}

	const uint64_t value = context.get_stack<uint64_t> ( current_rsp );
	const uint64_t mask = GET_OPERAND_MASK ( op_size );
	const uint64_t masked_value = value & mask;

	if ( instr.op0_kind ( ) == OpKindSimple::Register ) {
		helpers::set_operand_value<uint64_t> ( instr, 0u, masked_value, context );
	}
	else if ( instr.op0_kind ( ) == OpKindSimple::Memory ) {
		const uint64_t addr = helpers::calculate_mem_addr( instr, context );
		if ( context.is_within_stack_bounds ( addr, op_size ) ) {
			context.set_stack<uint64_t> ( addr, masked_value );
		}
		else {
			context.set_memory<uint64_t> ( addr, masked_value );
		}
	}
	else {
		// !TODO(exception)
		return;
	}

	context.set_reg ( Register::RSP, current_rsp + 8, 8 );
}
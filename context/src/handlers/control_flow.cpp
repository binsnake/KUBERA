#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;
/// JMP - Jump
/// Jumps to the target address unconditionally
void handlers::jmp ( const iced::Instruction& instr, KUBERA& context ) {
	const auto target = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
	context.handle_ip_switch ( target );
}

/// JNE - Jump if Not Equal
/// Jumps to the target address if the zero flag (ZF) is 0, without affecting flags.
void handlers::jne ( const iced::Instruction& instr, KUBERA& context ) {
	if ( !context.get_flags ( ).ZF ) {
		handlers::jmp ( instr, context );
	}
}

/// JE - Jump if Equal
/// Jumps to the target address if the zero flag (ZF) is 1, without affecting flags.
void handlers::je ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_flags ( ).ZF ) {
		handlers::jmp ( instr, context );
	}
}

/// JNBE - Jump if Not Below or Equal
/// Jumps to the target address if the carry flag (CF) is 0 and the zero flag (ZF) is 0, without affecting flags.
void handlers::jnbe ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( !flags.CF && !flags.ZF ) {
		handlers::jmp ( instr, context );
	}
}

/// JG - Jump if Greater
/// Jumps to the target address if the zero flag (ZF) is 0 and the sign flag (SF) equals the overflow flag (OF), without affecting flags.
void handlers::jg ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( !flags.ZF && flags.SF == flags.OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JL - Jump if Less
/// Jumps to the target address if the sign flag (SF) does not equal the overflow flag (OF), without affecting flags.
void handlers::jl ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( flags.SF != flags.OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JNB - Jump if Not Below
/// Jumps to the target address if the carry flag (CF) is 0, without affecting flags.
void handlers::jnb ( const iced::Instruction& instr, KUBERA& context ) {
	if ( !context.get_flags ( ).CF ) {
		handlers::jmp ( instr, context );
	}
}

/// JB - Jump if Below
/// Jumps to the target address if the carry flag (CF) is 1, without affecting flags.
void handlers::jb ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_flags ( ).CF ) {
		handlers::jmp ( instr, context );
	}
}

/// JNS - Jump if Not Sign
/// Jumps to the target address if the sign flag (SF) is 0, without affecting flags.
void handlers::jns ( const iced::Instruction& instr, KUBERA& context ) {
	if ( !context.get_flags ( ).SF ) {
		handlers::jmp ( instr, context );
	}
}

/// JNL - Jump if Not Less
/// Jumps to the target address if the sign flag (SF) equals the overflow flag (OF), without affecting flags.
void handlers::jnl ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( flags.SF == flags.OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JO - Jump if Overflow
/// Jumps to the target address if the overflow flag (OF) is 1, without affecting flags.
void handlers::jo ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_flags ( ).OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JNO - Jump if Not Overflow
/// Jumps to the target address if the overflow flag (OF) is 0, without affecting flags.
void handlers::jno ( const iced::Instruction& instr, KUBERA& context ) {
	if ( !context.get_flags ( ).OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JBE - Jump if Below or Equal
/// Jumps to the target address if the carry flag (CF) is 1 or the zero flag (ZF) is 1, without affecting flags.
void handlers::jbe ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( flags.CF || flags.ZF ) {
		handlers::jmp ( instr, context );
	}
}

/// JS - Jump if Sign
/// Jumps to the target address if the sign flag (SF) is 1, without affecting flags.
void handlers::js ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_flags ( ).SF ) {
		handlers::jmp ( instr, context );
	}
}

/// JA - Jump if Above
/// Jumps to the target address if the carry flag (CF) is 0 and the zero flag (ZF) is 0, without affecting flags.
void handlers::ja ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( !flags.CF && !flags.ZF ) {
		handlers::jmp ( instr, context );
	}
}

/// JAE - Jump if Above or Equal
/// Jumps to the target address if the carry flag (CF) is 0, without affecting flags.
void handlers::jae ( const iced::Instruction& instr, KUBERA& context ) {
	if ( !context.get_flags ( ).CF ) {
		handlers::jmp ( instr, context );
	}
}

/// JGE - Jump if Greater or Equal
/// Jumps to the target address if the sign flag (SF) equals the overflow flag (OF), without affecting flags.
void handlers::jge ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( flags.SF == flags.OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JLE - Jump if Less or Equal
/// Jumps to the target address if the zero flag (ZF) is 1 or the sign flag (SF) does not equal the overflow flag (OF), without affecting flags.
void handlers::jle ( const iced::Instruction& instr, KUBERA& context ) {
	const auto& flags = context.get_flags ( );
	if ( flags.ZF || flags.SF != flags.OF ) {
		handlers::jmp ( instr, context );
	}
}

/// JP - Jump if Parity
/// Jumps to the target address if the parity flag (PF) is 1, without affecting flags.
void handlers::jp ( const iced::Instruction& instr, KUBERA& context ) {
	if ( context.get_flags ( ).PF ) {
		handlers::jmp ( instr, context );
	}
}

/// JNP - Jump if Not Parity
/// Jumps to the target address if the parity flag (PF) is 0, without affecting flags.
void handlers::jnp ( const iced::Instruction& instr, KUBERA& context ) {
	if ( !context.get_flags ( ).PF ) {
		handlers::jmp ( instr, context );
	}
}

/// JCXZ - Jump if CX Zero
/// Jumps to the target address if the CX register is 0 (16-bit address size), without affecting flags.
void handlers::jcxz ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t cx = context.get_reg ( Register::CX, 2 );
	if ( cx == 0 ) {
		handlers::jmp ( instr, context );
	}
}

/// JECXZ - Jump if ECX Zero
/// Jumps to the target address if the ECX register is 0 (32-bit address size), without affecting flags.
void handlers::jecxz ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t ecx = context.get_reg ( Register::ECX, 4 );
	if ( ecx == 0 ) {
		handlers::jmp ( instr, context );
	}
}

/// JRCXZ - Jump if RCX Zero
/// Jumps to the target address if the RCX register is 0 (64-bit address size), without affecting flags.
void handlers::jrcxz ( const iced::Instruction& instr, KUBERA& context ) {
	const uint64_t rcx = context.get_reg ( Register::RCX, 8 );
	if ( rcx == 0 ) {
		handlers::jmp ( instr, context );
	}
}

/// RET - Return from Procedure
/// Pops the return address from the stack, adjusts RSP (optionally by an immediate value), and jumps to the return address, without affecting flags.
void handlers::ret ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = 8;
	const uint64_t imm = ( instr.op_count ( ) > 0 && instr.op0_kind ( ) == OpKindSimple::Immediate ) ?
		instr.immediate ( ) : 0;
	const uint64_t pop_size = op_size + imm;
	const uint64_t old_rsp = context.get_reg ( Register::RSP, op_size );

	const uint64_t return_ip = context.get_stack<uint64_t> ( old_rsp );
	context.set_reg ( Register::RSP, old_rsp + pop_size, op_size );
	context.handle_ip_switch ( return_ip );
}

/// CALL - Call Procedure
/// Pushes the return address (RIP + instruction length) onto the stack, adjusts RSP, and jumps to the target address, without affecting flags.
void handlers::call ( const iced::Instruction& instr, KUBERA& context ) {
	const size_t op_size = 8;
	const uint64_t return_ip = context.get_reg ( Register::RIP, op_size ) + instr.length ( );
	const uint64_t old_rsp = context.get_reg ( Register::RSP, op_size );
	const uint64_t new_rsp = old_rsp - op_size;

	context.set_stack<uint64_t> ( new_rsp, return_ip );
	context.set_reg ( Register::RSP, new_rsp, op_size );
	handlers::jmp ( instr, context );
}
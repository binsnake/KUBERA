#include "pch.hpp"

uint64_t get_target (
		capstone::Instruction& instr,
		EmulationContext& state,
		InstructionEffect& effect
) {
	const auto& ops = instr.operands ( );
	if ( instr.operand_count ( ) == 0 ) {
		effect.push_to_changes ( state, "get_target: No operands to determine target." );
		state.exit_due_to_critical_error = true;
		return 0;
	}

	const cs_x86_op& op = ops [ 0 ];
	uint64_t next_ip = instr.branch_target ( );

	if ( op.type == X86_OP_MEM ) {
		auto addr = helpers::calculate_mem_addr ( op, instr, state );

		if ( parser && parser->is_address_in_iat ( addr ) ) {
			try {
				uint64_t image_base = parser->get_image_base ( );
				uint64_t image_size = image_base + parser->pe_info_.optional_header.size_of_image;
				if ( addr >= image_base && addr < image_base + image_size ) {
					uint64_t rva = addr - image_base;
					uint64_t iat_value = *( uint64_t* ) addr;
					effect.push_to_changes (
							state,
							std::format ( "get_target: IAT[0x{:x}] -> 0x{:x}", addr, iat_value )
					);
					return iat_value;
				}
				else {
					effect.push_to_changes (
							state,
							std::format ( "get_target: IAT addr 0x{:x} out of image bounds", addr )
					);
				}
			}
			catch ( ... ) {
				effect.push_to_changes (
						state,
						std::format ( "get_target: Failed reading IAT at 0x{:x}, falling back", addr )
				);
			}
		}

		if ( state.is_within_stack_bounds ( addr, 8 ) ) {
			uint64_t val = state.get_stack ( addr, false );
			effect.push_to_changes (
					state,
					std::format ( "get_target: Stack[0x{:x}] -> 0x{:x}", addr, val )
			);
			return val;
		}

		uint64_t val = state.get_memory ( addr, 8 );
		effect.push_to_changes (
				state,
				std::format ( "get_target: Mem[0x{:x}] -> 0x{:x}", addr, val )
		);
		return val;
	}

	if ( op.type == X86_OP_REG ) {
		uint64_t val = state.get_reg ( op.reg, 8 );
		effect.push_to_changes (
				state,
				std::format (
			"get_target: Reg {} -> 0x{:x}",
			cs_reg_name ( state.decoder.back ( )->get_handle ( ), op.reg ),
			val
		)
		);
		return val;
	}

	if ( op.type == X86_OP_IMM ) {
		uint64_t val = instr.branch_target ( );
		effect.push_to_changes (
				state,
				std::format ( "get_target: Imm -> 0x{:x}", val )
		);
		return val;
	}

	if ( instr.branch_target ( ) != 0 ) {
		uint64_t val = instr.branch_target ( );
		effect.push_to_changes (
				state,
				std::format ( "get_target: branch_target() -> 0x{:x}", val )
		);
		return val;
	}

	effect.push_to_changes ( state, "get_target: Could not determine target." );
	state.exit_due_to_critical_error = true;
	return 0;
}

bool is_api_hook ( EmulationContext& state, capstone::Instruction& instr, uint64_t final_addr, InstructionEffect& effect ) {
	if ( final_addr <= state.windows->loaded_base_address || final_addr >= state.windows->loaded_base_address + state.windows->loaded_module_size ) {
		auto ait = state.windows->api_hooks.find ( final_addr );
		if ( ait == state.windows->api_hooks.end ( ) ) { // handle indirection
			ait = state.windows->api_hooks.find ( state.get_reg<uint64_t> ( X86_REG_RAX ) );
		}
		if ( ait != state.windows->api_hooks.end ( ) ) {
			effect.push_to_changes ( state,
					std::format ( "JMP hits API hook at 0x{:x}, dispatching hook inline.", final_addr ) );
			ait->second ( instr, state, effect, final_addr );

			state.decoder.back ( )->set_ip ( state.call_stack.back ( ).return_addr );
			std::ignore = state.decoder.back ( )->decode ( );
			uint64_t old_rsp = state.get_reg ( X86_REG_RSP, 8 );
			uint64_t new_rsp = old_rsp + 8;
			state.set_reg ( X86_REG_RSP, new_rsp, 8, effect );
			state.pop_call_frame ( effect );
			return true;
		}
	}
	return false;
}

void handle_jump_target (
		capstone::Instruction& instr,
		EmulationContext& state,
		InstructionEffect& effect,
		uint64_t initial_target
) {
	if ( initial_target == 0 ) {
		effect.push_to_changes ( state,
				std::format ( "JMP/Jcc ({}) Error: no target", instr.mnemonic ( ) ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	uint64_t final_addr = initial_target;
	if ( is_api_hook ( state, instr, final_addr, effect ) || is_api_hook ( state, instr, state.get_reg<uint64_t> ( X86_REG_RAX ), effect ) ) { // indirect, direct
		return;
	}
	if ( parser && parser->is_address_in_iat ( initial_target ) ) {
		uint64_t image_base = parser->get_image_base ( );
		uint64_t image_size = parser->pe_info_.optional_header.size_of_image;
		if ( initial_target >= image_base && initial_target < image_base + image_size ) {
			uint64_t rva = initial_target - image_base;
			uint64_t iat_val = parser->read_qword_at_rva ( rva );
			effect.push_to_changes ( state,
					std::format ( "Resolved IAT[0x{:x}] -> 0x{:x}", initial_target, iat_val ) );
			final_addr = iat_val;
		}
		else {
			effect.push_to_changes ( state,
					std::format ( "IAT address 0x{:x} out of bounds", initial_target ) );
		}
	}

	uint64_t chosen_base = 0;
	for ( auto& [base, mod] : state.windows->loaded_modules ) {
		if ( final_addr >= base && final_addr < base + mod.size ) {
			chosen_base = base;
			break;
		}
	}
	if ( chosen_base == 0 ) {
		effect.push_to_changes ( state,
				std::format ( "JMP/Jcc ({}) target 0x{:x} not in any loaded module",
														 instr.mnemonic ( ), final_addr ) );
		state.exit_due_to_critical_error = true;
		return;
	}

	if ( state.windows->current_module_base != chosen_base ) {
		LoadedModule& lm = state.windows->loaded_modules.at ( chosen_base );
		if ( state.decoder.back ( )->data_ != lm.decoder.get ( )->data_ ) {
			state.decoder.emplace_back ( lm.decoder.get ( ) );
		}
		state.windows->current_module_base = chosen_base;
		effect.push_to_changes ( state,
				std::format ( "Switched decoder -> module @0x{:x} (size 0x{:x})",
														 chosen_base, lm.size ) );
	}

	state.decoder.back ( )->set_ip ( final_addr );
	effect.push_to_changes ( state,
			std::format ( "JMP/Jcc ({}) -> module+{:#x}",
													 instr.mnemonic ( ), final_addr - chosen_base ) );
}



uint64_t get_initial_target ( const EmulationContext& state, const capstone::Instruction& instr ) {
	uint64_t initial_target = instr.branch_target ( );
	const auto operand = instr.operands ( ) [ 0 ];
	switch ( operand.type ) {
		case X86_OP_MEM:
			return 0;
		case X86_OP_IMM:
			return initial_target + instr.ip ( ) + instr.length ( );
		case X86_OP_REG:
			return state.get_reg<uint64_t> ( operand.reg );
		default:
			__debugbreak ( );
			return 0;
	}
}


void jmp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	handle_jump_target ( instr, state, effect, target );
}

void je ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.ZF;
	effect.push_to_changes ( state, std::format ( "JE: ZF={} -> {}", taken ? '1' : '0', taken ? "taken" : "not taken" ) );

	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jne ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.ZF;
	effect.push_to_changes ( state, std::format ( "JNE: ZF={} -> {}", taken, taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jnbe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.CF && !state.cpu->cpu_flags.flags.ZF;
	effect.push_to_changes ( state, std::format ( "JNBE: CF={} ZF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.CF,
													 ( char ) state.cpu->cpu_flags.flags.ZF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jg ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.ZF && state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF;
	effect.push_to_changes ( state, std::format ( "JG: ZF={} SF={} OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.ZF,
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.SF != state.cpu->cpu_flags.flags.OF;
	effect.push_to_changes ( state, std::format ( "JL: SF={} OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jnb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.CF;
	effect.push_to_changes ( state, std::format ( "JNB: CF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.CF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jb ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.CF;
	effect.push_to_changes ( state, std::format ( "JB: CF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.CF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jns ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.SF;
	effect.push_to_changes ( state, std::format ( "JNS: SF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jnl ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF;
	effect.push_to_changes ( state, std::format ( "JNL: SF={} OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jo ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.OF;
	effect.push_to_changes ( state, std::format ( "JO: OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jno ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.OF;
	effect.push_to_changes ( state, std::format ( "JNO: OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jbe ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.CF || state.cpu->cpu_flags.flags.ZF;
	effect.push_to_changes ( state, std::format ( "JBE: CF={} ZF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.CF,
													 ( char ) state.cpu->cpu_flags.flags.ZF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void js ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.SF;
	effect.push_to_changes ( state, std::format ( "JS: SF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void ja ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.CF && !state.cpu->cpu_flags.flags.ZF;
	effect.push_to_changes ( state, std::format ( "JA: CF={} ZF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.CF,
													 ( char ) state.cpu->cpu_flags.flags.ZF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jae ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.CF;
	effect.push_to_changes ( state, std::format ( "JAE: CF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.CF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jge ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.SF == state.cpu->cpu_flags.flags.OF;
	effect.push_to_changes ( state, std::format ( "JGE: SF={} OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jle ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = ( state.cpu->cpu_flags.flags.ZF || state.cpu->cpu_flags.flags.SF != state.cpu->cpu_flags.flags.OF );
	effect.push_to_changes ( state, std::format ( "JLE: ZF={} SF={} OF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.ZF,
													 ( char ) state.cpu->cpu_flags.flags.SF,
													 ( char ) state.cpu->cpu_flags.flags.OF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = state.cpu->cpu_flags.flags.PF;
	effect.push_to_changes ( state, std::format ( "JP: PF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.PF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jnp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	bool taken = !state.cpu->cpu_flags.flags.PF;
	effect.push_to_changes ( state, std::format ( "JNP: PF={} -> {}",
													 ( char ) state.cpu->cpu_flags.flags.PF,
													 taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jcxz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	uint64_t cx = state.get_reg ( X86_REG_CX, 2 );
	bool taken = cx == 0;
	effect.push_to_changes ( state, std::format ( "JCXZ: CX={} -> {}", cx, taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jecxz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	uint64_t ecx = state.get_reg ( X86_REG_ECX, 4 );
	bool taken = ecx == 0;
	effect.push_to_changes ( state, std::format ( "JECXZ: ECX={} -> {}", ecx, taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void jrcxz ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	uint64_t target = get_target ( instr, state, effect );
	uint64_t rcx = state.get_reg ( X86_REG_RCX, 8 );
	bool taken = rcx == 0;
	effect.push_to_changes ( state, std::format ( "JRCXZ: RCX={} -> {}", rcx, taken ? "taken" : "not taken" ) );
	if ( taken ) {
		handle_jump_target ( instr, state, effect, target );
	}
	else {
		effect.push_to_changes ( state, std::format ( "Fallthrough to 0x{:x} is invalid", instr.branch_target ( ) ) );
	}
}

void helpers::bind_jx ( ) {
	BIND ( jmp );
	BIND ( je );
	BIND ( jne );
	BIND ( jnbe );  // JA
	BIND ( jg );
	BIND ( jl );
	BIND ( jnb );   // JAE
	BIND ( jb );
	BIND ( jns );
	BIND ( jnl );   // JGE
	BIND ( jo );
	BIND ( jno );
	BIND ( jbe );
	BIND ( js );
	BIND ( ja );
	BIND ( jae );
	BIND ( jge );
	BIND ( jle );
	BIND ( jp );
	BIND ( jnp );
	BIND ( jcxz );
	BIND ( jecxz );
	BIND ( jrcxz );
}
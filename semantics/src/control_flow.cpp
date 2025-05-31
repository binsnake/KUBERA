#include "pch.hpp"

void cmp ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	auto src1 = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	auto src2 = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );

	state.update_flags_sub ( src1, src2, op_size, effect );
}

void test ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
	const cs_x86_op* ops = instr.operands ( );
	uint8_t op_size = ops [ 0 ].size;
	auto src1 = helpers::get_src<uint64_t> ( &instr, 0, state, op_size );
	auto src2 = helpers::get_src<uint64_t> ( &instr, 1, state, op_size );
	state.update_flags_test ( src1, src2, op_size, effect );
}

void ret ( capstone::Instruction& instr,
				 EmulationContext& state,
				 InstructionEffect& effect ) {
	int64_t imm = 0;
	if ( instr.operand_count ( ) > 0 && instr.operands ( ) [ 0 ].type == X86_OP_IMM )
		imm = instr.operands ( ) [ 0 ].imm;
	uint64_t pop_size = 8 + imm;

	if ( state.call_stack.empty ( ) ) {
		state.exit_due_to_critical_error = true;
		return;
	}
	CallFrame frame = state.call_stack.back ( );
	uint64_t return_ip = frame.return_addr;
	state.call_stack.pop_back ( );

	uint64_t old_rsp = state.get_reg ( X86_REG_RSP, 8 );
	uint64_t new_rsp = old_rsp + pop_size;
	state.set_reg ( X86_REG_RSP, new_rsp, 8, effect );
	effect.modified_regs.insert ( X86_REG_RSP );
	effect.push_to_changes ( state,
			std::format ( "RET: popped 0x{:x}, RSP += 0x{:x}", return_ip, pop_size )
	);

	for ( auto& [base, mod] : state.windows->loaded_modules ) {
		if ( return_ip >= base && return_ip < base + mod.size ) {
			if ( state.windows->current_module_base != base ) {
				size_t match_index = 0;
				bool found = false;

				for ( size_t i = 0; i < state.decoder.size ( ); ++i ) {
					if ( state.decoder [ i ]->data_ == mod.decoder->data_ ) {
						match_index = i;
						found = true;
						break;
					}
				}

				if ( found ) {
					state.decoder.resize ( match_index + 1 ); // Shrink to just after match
				}
				else {
					state.decoder.emplace_back ( mod.decoder.get ( ) ); // Use shared_ptr
				}
				state.windows->current_module_base = base;
				effect.push_to_changes ( state,
						std::format ( "RET -> switch decoder to module @0x{:x}", base )
				);
			}
			break;
		}
	}

	state.decoder.back ( )->set_ip ( return_ip );
	effect.push_to_changes ( state,
			std::format ( "RET -> 0x{:x} (module+{:#x}", return_ip, return_ip - state.windows->current_module_base )
	);
}

void call ( capstone::Instruction& instr,
					EmulationContext& state,
					InstructionEffect& effect ) {
	uint64_t raw_target = helpers::get_target2 ( instr, state, effect );
	if ( !raw_target ) {
		effect.push_to_changes ( state, "CALL Error: could not decode target" );
		state.exit_due_to_critical_error = true;
		return;
	}
	if ( raw_target <= state.windows->loaded_base_address || raw_target >= state.windows->loaded_base_address + state.windows->loaded_module_size ) {
		auto ait = state.windows->api_hooks.find ( raw_target );
		if ( ait == state.windows->api_hooks.end() ) { // handle indirection
			ait = state.windows->api_hooks.find ( state.get_reg<uint64_t> ( X86_REG_RAX ) );
		}
		if ( ait != state.windows->api_hooks.end ( ) ) {
			effect.push_to_changes ( state,
					std::format ( "CALL hits API hook at 0x{:x}, dispatching hook inline.", raw_target ) );
			ait->second ( instr, state, effect, raw_target );

			return;
		}
	}
	auto it = state.windows->imports.find ( raw_target );
	if ( it != state.windows->imports.end ( ) ) {
		uint64_t return_ip = instr.ip ( ) + instr.length ( );

		uint64_t old_rsp = state.get_reg ( X86_REG_RSP, 8 );
		uint64_t new_rsp = old_rsp - 8;
		state.set_reg ( X86_REG_RSP, new_rsp, 8, effect );
		state.set_stack ( new_rsp, return_ip, effect, /*size=*/8 );
		effect.modified_regs.insert ( X86_REG_RSP );
		effect.modified_mem.insert ( new_rsp );

		// record the frame so RET still works
		state.push_call_frame ( return_ip, effect );

		state.set_reg ( X86_REG_RAX, 0, /*size=*/8, effect );

		state.pop_call_frame ( effect );
		state.set_reg ( X86_REG_RSP, old_rsp, 8, effect );
		state.decoder.back ( )->set_ip ( return_ip );
		effect.push_to_changes ( state,
				std::format ( "Stubbed import call to {}!{} -> returned 0, jumping to 0x{:x}",
														 it->second.first, it->second.second, return_ip ) );
		return;
	}

	uint64_t return_ip = instr.ip ( ) + instr.length ( );
	uint64_t old_rsp = state.get_reg ( X86_REG_RSP, 8 );
	uint64_t new_rsp = old_rsp - 8;
	state.set_reg ( X86_REG_RSP, new_rsp, 8, effect );
	state.set_stack ( new_rsp, return_ip, effect, /*size=*/8 );
	effect.modified_regs.insert ( X86_REG_RSP );
	effect.modified_mem.insert ( new_rsp );

	state.push_call_frame ( return_ip, effect );

	uint64_t landed = helpers::resolve_and_switch_target (
			instr, state, raw_target, effect,
			/*is_call=*/true
	);
	if ( !landed ) {
		effect.push_to_changes ( state, "CALL Error: unable to switch to target" );
		state.exit_due_to_critical_error = true;
	}
	effect.push_to_changes ( state, std::format ( "module+{:#x}", state.decoder.back ( )->ip ( ) - landed ) );
}


void helpers::bind_cf ( ) {
	BIND ( cmp );
	BIND ( test );
	BIND ( call );
	BIND ( ret );
}
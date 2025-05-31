#include "pch.hpp"

void enter ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
  const auto* ops = instr.operands ( );

  int64_t size = ops [ 0 ].imm;   
  int64_t nesting = ops [ 1 ].imm;

  if ( nesting != 0 ) {
    if ( state.options.enable_logging ) {
      effect.push_to_changes ( state,"Warning: Non-zero ENTER nesting level not fully implemented" );
    }
  }

  uint64_t current_rsp = state.get_reg ( X86_REG_RSP );
  uint64_t current_rbp = state.get_reg ( X86_REG_RBP );

  current_rsp -= 8;
  state.set_stack ( current_rsp, current_rbp, effect, 8 );
  state.stack_allocated += 8;
  effect.modified_mem.insert ( current_rsp );

  state.set_reg ( X86_REG_RBP, current_rsp , 8, effect );

  current_rsp -= size;
  state.set_reg ( X86_REG_RSP, current_rsp , 8, effect );
  state.stack_allocated += size;

  if ( nesting > 0 ) {
    int64_t nest_adjust = nesting * 8;
    current_rsp -= nest_adjust;
    state.set_reg ( X86_REG_RSP, current_rsp , 8, effect );
    state.stack_allocated += nest_adjust;
    if ( state.options.enable_logging ) {
      effect.push_to_changes ( state,std::format ( "Adjusted stack for nesting level {}: -0x{:x}", nesting, nest_adjust ) );
    }
  }

  if ( state.options.enable_logging ) {
    effect.push_to_changes ( state,std::format ( "ENTER: Allocated 8(RBP) + 0x{:x}(locals) + 0x{:x}(nesting)", size, nesting * 8 ) );
    effect.push_to_changes ( state,std::format ( "Adjusted stack allocation by +0x{:x}", 8 + size + nesting * 8 ) );
  }
}


void leave ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
  uint64_t current_rbp_emu = state.get_reg ( X86_REG_RBP );
  uint64_t current_rbp_val = current_rbp_emu;
  uint64_t current_rsp_val = state.get_reg ( X86_REG_RSP );

  int64_t frame_locals_size = current_rbp_val - current_rsp_val;
  if ( frame_locals_size < 0 ) {
    effect.push_to_changes ( state,std::format ( "LEAVE Warning: RBP (0x{:x}) is below RSP (0x{:x})", current_rbp_val, current_rsp_val ) );
    frame_locals_size = 0;
  }

  state.set_reg ( X86_REG_RSP, current_rbp_emu, 8, effect );

  uint64_t saved_rbp_val = state.get_stack ( current_rbp_val, false );
  state.set_reg ( X86_REG_RBP, saved_rbp_val, 8, effect );
  state.set_reg ( X86_REG_RSP, current_rbp_val + 8 , 8, effect );

  int64_t dealloc_size = frame_locals_size + 8;
  state.stack_allocated -= dealloc_size;
  if ( state.stack_allocated < 0 ) state.stack_allocated = 0;

  if ( state.options.enable_logging ) {
    effect.push_to_changes ( state,std::format ( "LEAVE: Deallocated frame. Adjusted stack allocation by -0x{:x}", dealloc_size ) );
  }

}

void nop ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect ) {
  effect.is_no_op = true;
}

void helpers::bind_frame ( ) {
  BIND ( enter );
  BIND ( leave );
  BIND ( nop );
}
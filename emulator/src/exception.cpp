
#include "pch.hpp"
#include <semantics/src/pch.hpp>

inline bool is_canonical ( uint64_t addr ) {
  return ( ( addr <= 0x00007FFFFFFFFFFFULL ) || ( addr >= 0xFFFF800000000000ULL ) );
}

bool check_x87_fault_condition ( const EmulationContext& state ) {
  uint16_t fsw = state.cpu->fpu.fpu_status_word;
  uint16_t fcw = state.cpu->fpu.fpu_control_word;
  uint16_t exception_status = fsw & 0x3F;
  uint16_t exception_mask = fcw & 0x3F;
  return ( exception_status & ~exception_mask ) != 0;
}

DWORD map_x87_exception ( const EmulationContext& state ) {
  uint16_t fsw = state.cpu->fpu.fpu_status_word;
  uint16_t fcw = state.cpu->fpu.fpu_control_word;
  uint16_t exception_status = fsw & 0x3F;
  uint16_t exception_mask = fcw & 0x3F;
  uint16_t unmasked = exception_status & ~exception_mask;
  if ( unmasked == 0 ) return 0;
  if ( unmasked & 0x01 ) return EXCEPTION_FLT_INVALID_OPERATION;
  if ( unmasked & 0x02 ) return EXCEPTION_FLT_DENORMAL_OPERAND;
  if ( unmasked & 0x04 ) return EXCEPTION_FLT_DIVIDE_BY_ZERO;
  if ( unmasked & 0x08 ) return EXCEPTION_FLT_OVERFLOW;
  if ( unmasked & 0x10 ) return EXCEPTION_FLT_UNDERFLOW;
  if ( unmasked & 0x20 ) return EXCEPTION_FLT_INEXACT_RESULT;
  return 0;
}

bool check_simd_fault_condition ( const EmulationContext& state ) {
  uint32_t mxcsr = state.cpu->fpu.mxcsr_control;
  uint32_t status = mxcsr & 0x3F;
  uint32_t mask = ( mxcsr >> 7 ) & 0x3F;
  return ( status & ~mask ) != 0;
}

DWORD map_sse_exception ( const EmulationContext& state ) {
  uint32_t mxcsr = state.cpu->fpu.mxcsr_control;
  uint32_t status = mxcsr & 0x3F;
  uint32_t mask = ( mxcsr >> 7 ) & 0x3F;
  return ( ( status & ~mask ) != 0 ) ? EXCEPTION_FLT_INVALID_OPERATION : 0;
}

GuestExceptionInfo check_instruction_exceptions (
    EmulationContext& state,
    capstone::Instruction& instr,
    const PreCheckInfo& check_info
) {
  GuestExceptionInfo result = {};
  uint64_t ip = instr.ip ( );
  const auto& baseInfo = g_instruction_exception_table [ instr.mnemonic ( ) ];
  const auto& cats = baseInfo.categories;

  // INVALID_USAGE
  if ( cats.INVALID_USAGE ) {
    if ( baseInfo.is_privileged && state.cpu->current_privilege_level != 0 ) {
      result.set_exception ( EXCEPTION_PRIV_INSTRUCTION, ip );
      return result;
    }
    if ( baseInfo.is_io ) {
      result.set_exception ( EXCEPTION_PRIV_INSTRUCTION, ip );
      return result;
    }
    if ( check_info.has_lock_prefix ) {
      bool need_mem = !( instr.mnemonic ( ) == X86_INS_XCHG && instr.operands ( ) [ 0 ].type == X86_OP_REG );
      if ( !baseInfo.lock_prefix_allowed || baseInfo.lock_prefix_always_invalid ||
         ( baseInfo.lock_prefix_allowed && need_mem && !check_info.has_mem_operand ) ) {
        result.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, ip );
        return result;
      }
    }
    if ( baseInfo.is_invalid_by_default ) {
      result.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, ip );
      return result;
    }
    if ( baseInfo.is_int3 ) {
      result.set_exception ( EXCEPTION_BREAKPOINT, ip );
      return result;
    }
  }

  // MEMORY
  if ( cats.MEMORY && check_info.has_mem_operand ) {
    uint64_t addr = check_info.mem_effective_addr;
    if ( !is_canonical ( addr ) ) {
      result.set_access_violation ( ip, addr, check_info.mem_is_write );
      return result;
    }
    if ( check_info.uses_fs && state.get_reg ( X86_REG_FS, 2 ) == 0 ) {
      result.set_access_violation ( ip, addr, check_info.mem_is_write );
      return result;
    }
    if ( check_info.uses_gs && state.get_reg ( X86_REG_GS, 2 ) == 0 ) {
      result.set_access_violation ( ip, addr, check_info.mem_is_write );
      return result;
    }
  }

  // STACK
  if ( cats.STACK ) {
    uint64_t addr = state.get_reg ( X86_REG_RSP );
    if ( check_info.is_stack_push ) addr = check_info.stack_access_addr;
    if ( check_info.is_stack_pop )  addr = check_info.stack_access_addr;
    if ( !state.is_within_stack_bounds ( addr, check_info.stack_access_size ) ) {
      if ( check_info.is_stack_push )
        result.set_exception ( EXCEPTION_STACK_OVERFLOW, ip, addr );
      else
        result.set_access_violation ( ip, addr, false );
      return result;
    }
    uint64_t future = state.get_reg ( X86_REG_RSP );
    if ( baseInfo.modifies_rsp_implicitly ) {
      if ( check_info.is_stack_push ) future -= check_info.stack_access_size;
      if ( check_info.is_stack_pop )  future += check_info.stack_access_size;
    }
    if ( !is_canonical ( future ) ) {
      result.set_access_violation ( ip, future, false );
      return result;
    }
  }

  // ALIGNMENT
  if ( cats.ALIGNMENT ) {
    uint64_t addr = 0; uint8_t size = 0; bool do_check = false;
    if ( check_info.has_mem_operand ) {
      addr = check_info.mem_effective_addr; size = check_info.mem_op_size; do_check = true;
    }
    else if ( check_info.is_stack_push || check_info.is_stack_pop ) {
      addr = check_info.stack_access_addr; size = check_info.stack_access_size; do_check = true;
    }
    if ( do_check && size > 0 ) {
      if ( check_info.alignment_required_intrinsic ) {
        if ( addr % check_info.required_alignment_bytes ) {
          result.set_exception ( EXCEPTION_DATATYPE_MISALIGNMENT, ip, addr );
          return result;
        }
      }
      else {
        if ( state.is_alignment_check_enabled ( ) && size > 1 && size <= 8 && ( addr % size ) ) {
          result.set_exception ( EXCEPTION_DATATYPE_MISALIGNMENT, ip, addr );
          return result;
        }
      }
    }
  }

  // CONTROL_FLOW
  if ( cats.CONTROL_FLOW ) {
    InstructionEffect eff;
    uint64_t target = helpers::get_target2 ( instr, state, eff );
    if ( target && !is_canonical ( target ) ) {
      result.set_access_violation ( ip, target, true );
      return result;
    }
  }

  return result;
}

GuestExceptionInfo check_post_execution_arithmetic (
    EmulationContext& state,
    const InstructionExceptionInfo& baseInfo,
    uint64_t ip,
    uint8_t op_size
) {
  GuestExceptionInfo result = {};
  if ( baseInfo.is_into && state.cpu->cpu_flags.flags.OF ) {
    result.set_exception ( EXCEPTION_INT_OVERFLOW, ip );
    return result;
  }
  return result;
}

GuestExceptionInfo check_post_execution_fpu_simd (
    EmulationContext& state,
    const InstructionExceptionInfo& baseInfo,
    uint64_t ip
) {
  GuestExceptionInfo result = {};
  if ( baseInfo.is_fpu_related && check_x87_fault_condition ( state ) ) {
    DWORD code = map_x87_exception ( state );
    if ( code ) { result.set_exception ( code, ip ); return result; }
  }
  if ( baseInfo.is_sse_avx_related && check_simd_fault_condition ( state ) ) {
    DWORD code = map_sse_exception ( state );
    if ( code ) { result.set_exception ( code, ip ); return result; }
  }
  return result;
}

void setup_guest_exception_dispatch ( EmulationContext& state, const GuestExceptionInfo& ex_info ) {
  if ( !ex_info.exception_occurred ) {
    std::println ( "INTERNAL ERROR: setup_guest_exception_dispatch called with no exception occurred." );
    state.exit_due_to_critical_error = true; return;
  }
  std::println ( "Dispatching exception 0x{:X} @ IP=0x{:016x}, VA=0x{:016x}...",
               ex_info.ExceptionCode, ex_info.ExceptionAddress, ex_info.FaultingVa );
  uint64_t disp = state.windows->ki_user_exception_dispatcher;
  if ( !disp ) { state.exit_due_to_critical_error = true; return; }
  alignas( 16 ) CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_ALL;
  state.save_context ( &ctx ); ctx.Rip = ex_info.ExceptionAddress;
  EXCEPTION_RECORD er = {};
  er.ExceptionCode = ex_info.ExceptionCode;
  er.ExceptionFlags = ex_info.ExceptionFlags;
  er.ExceptionAddress = reinterpret_cast< PVOID >( ex_info.ExceptionAddress );
  er.NumberParameters = ex_info.NumberParameters;
  memcpy ( er.ExceptionInformation, ex_info.ExceptionInformation.data ( ), ex_info.NumberParameters * sizeof ( ULONG_PTR ) );
  uint64_t rsp = state.get_reg ( X86_REG_RSP );
  size_t rsz = ( sizeof ( EXCEPTION_RECORD ) + 15 ) & ~15ULL;
  size_t csz = ( sizeof ( CONTEXT ) + 15 ) & ~15ULL;
  uint64_t ra = rsp - rsz;
  uint64_t ca = ra - csz;
  uint64_t fr = ( ca - 32 ) & ~15ULL;
  *( EXCEPTION_RECORD* ) ra = er;
  *( CONTEXT* ) ca = ctx;
  InstructionEffect de = {};
  state.set_reg ( X86_REG_RCX, ra, 8, de );
  state.set_reg ( X86_REG_RDX, ca, 8, de );
  state.set_reg ( X86_REG_RSP, fr, 8, de );
  if ( state.cpu->cpu_flags.flags.TF ) { state.cpu->cpu_flags.flags.TF = 0; }
  state.decoder.back ( )->set_ip ( disp );
}

void populate_pre_check_info (
    PreCheckInfo& ci,
    EmulationContext& state,
    capstone::Instruction& instr,
    const InstructionExceptionInfo& bi
) {
  ci = {};
  for ( int i = 0; i < 4 && instr.prefix ( ) [ i ]; ++i )
    if ( instr.prefix ( ) [ i ] == X86_PREFIX_LOCK ) ci.has_lock_prefix = true;
  auto ops = instr.operands ( ); size_t cnt = instr.operand_count ( );
  if ( cnt > 0 && ops [ 0 ].type == X86_OP_MEM ) ci.mem_is_write = true;
  for ( size_t i = 0; i < cnt; ++i ) if ( ops [ i ].type == X86_OP_MEM ) {
    ci.has_mem_operand = true;
    ci.mem_op_size = ops [ i ].size;
    ci.mem_segment_reg = static_cast< x86_reg > ( ops [ i ].mem.segment );
    ci.uses_fs = ( ci.mem_segment_reg == X86_REG_FS );
    ci.uses_gs = ( ci.mem_segment_reg == X86_REG_GS );
    ci.mem_effective_addr = helpers::calculate_mem_addr ( ops [ i ], instr, state );
    if ( i > 0 ) ci.mem_is_write = false;
    if ( ( instr.mnemonic ( ) == X86_INS_CMPXCHG || instr.mnemonic ( ) == X86_INS_XADD ) && i == 0 )
      ci.mem_is_write = true;
    if ( instr.mnemonic ( ) == X86_INS_TEST || instr.mnemonic ( ) == X86_INS_CMP )
      ci.mem_is_write = false;
    break;
  }
  ci.is_stack_push = bi.is_explicit_push;
  ci.is_stack_pop = bi.is_explicit_pop;
  if ( ci.is_stack_push || ci.is_stack_pop ) {
    ci.stack_access_size = 8;
    uint64_t r = state.get_reg ( X86_REG_RSP );
    ci.stack_access_addr = ci.is_stack_push ? ( r - 8 ) : r;
  }
  else if ( bi.modifies_rsp_implicitly ) {
    if ( instr.is_call ( ) ) { ci.is_stack_push = true; ci.stack_access_size = 8; ci.stack_access_addr = state.get_reg ( X86_REG_RSP ) - 8; }
    else if ( instr.is_return ( ) ) { ci.is_stack_pop = true; ci.stack_access_size = 8; ci.stack_access_addr = state.get_reg ( X86_REG_RSP ); }
  }
  ci.alignment_required_intrinsic = bi.requires_intrinsic_alignment;
  ci.required_alignment_bytes = bi.intrinsic_alignment_bytes > 0 ? bi.intrinsic_alignment_bytes : 1;
  ci.alignment_required_by_ac = bi.categories.ALIGNMENT;
}


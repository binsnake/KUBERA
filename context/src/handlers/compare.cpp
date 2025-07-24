#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;

/// CMP-Compare
/// Compares the first operand with the second by subtracting the second from the first and updating flags without modifying operands.
void handlers::cmp ( const iced::Instruction& instr, KUBERA& context ) {
  const size_t op_size = instr.op0_size ( );
  const uint64_t src1 = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
  const uint64_t src2 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
  const uint64_t mask = GET_OPERAND_MASK ( op_size );

  const uint64_t ua = src1 & mask;
  const uint64_t ub = src2 & mask;
  const uint64_t res = ( ua - ub ) & mask;

  const int64_t sa = SIGN_EXTEND ( ua, op_size );
  const int64_t sb = SIGN_EXTEND ( ub, op_size );
  const int64_t sres = SIGN_EXTEND ( res, op_size );

  auto& flags = context.get_flags ( );
  flags.CF = ( ua < ub );
  flags.ZF = ( res == 0 );
  flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
  flags.AF = ( ( ua ^ ub ^ res ) & 0x10 ) != 0;
  flags.SF = ( sres < 0 );
  flags.OF = ( sa >= 0 && sb < 0 && sres < 0 ) || ( sa < 0 && sb >= 0 && sres >= 0 );
}

/// TEST-Logical Compare
/// Performs a bitwise AND of the first and second operands and updates flags without modifying operands.
void handlers::test ( const iced::Instruction& instr, KUBERA& context ) {
  const size_t op_size = instr.op0_size ( );
  const uint64_t src1 = helpers::get_operand_value<uint64_t> ( instr, 0u, context );
  const uint64_t src2 = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
  const uint64_t mask = GET_OPERAND_MASK ( op_size );

  const uint64_t res = ( src1 & src2 ) & mask;

  auto& flags = context.get_flags ( );
  flags.SF = ( res >> ( op_size * 8 - 1 ) ) & 1;
  flags.ZF = ( res == 0 );
  flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
  flags.CF = 0;
  flags.OF = 0;
  flags.AF = 0;
}

/// CMPXCHG-Compare and Exchange
/// Compares the destination with RAX (or portion thereof), sets ZF based on equality, and either stores the source in the destination (if equal) or loads the destination into RAX (if not equal), updating flags.
void handlers::cmpxchg ( const iced::Instruction& instr, KUBERA& context ) {
  const size_t op_size = instr.op0_size ( ) ? instr.op0_size ( ) : 8;
  const uint64_t mask = GET_OPERAND_MASK ( op_size );

  const uint64_t dst_val = helpers::get_operand_value<uint64_t> ( instr, 0u, context ) & mask;
  const uint64_t src_bits = helpers::get_operand_value<uint64_t> ( instr, 1u, context ) & mask;
  const uint64_t rax_full = context.get_reg ( Register::RAX, 8 );
  const uint64_t acc_bits = rax_full & mask;

  bool success = ( acc_bits == dst_val );
  if ( success ) {
    helpers::set_operand_value<uint64_t> ( instr, 0u, src_bits, context );
  }
  else {
    const uint64_t new_rax = ( rax_full & ~mask ) | dst_val;
    context.set_reg ( Register::RAX, new_rax, 8 );
  }

  const uint64_t res = ( acc_bits - dst_val ) & mask;
  const int64_t sa = SIGN_EXTEND ( acc_bits, op_size );
  const int64_t sb = SIGN_EXTEND ( dst_val, op_size );
  const int64_t sres = SIGN_EXTEND ( res, op_size );

  auto& flags = context.get_flags ( );
  flags.CF = ( acc_bits < dst_val );
  flags.ZF = success ? 1 : 0;
  flags.PF = std::popcount ( res & 0xFF ) % 2 == 0;
  flags.AF = ( ( acc_bits ^ dst_val ^ res ) & 0x10 ) != 0;
  flags.SF = ( sres < 0 );
  flags.OF = ( sa >= 0 && sb < 0 && sres < 0 ) || ( sa < 0 && sb >= 0 && sres >= 0 );
}

/// CMPXCHG16B-Compare and Exchange 16 Bytes
/// Compares the 128-bit memory destination with RDX:RAX, sets ZF based on equality, and either stores RCX:RBX in the destination (if equal) or loads the destination into RDX:RAX (if not equal).
void handlers::cmpxchg16b ( const iced::Instruction& instr, KUBERA& context ) {
  const uint64_t addr = helpers::calculate_mem_addr( instr, context );
  if ( addr % 16 != 0 ) {
    // !TODO(exception)
    return;
  }
  const uint128_t mem_val = context.get_memory<uint128_t> ( addr );
  const uint64_t rax = context.get_reg ( Register::RAX, 8 );
  const uint64_t rdx = context.get_reg ( Register::RDX, 8 );
  const uint128_t rdx_rax = ( uint128_t ( rdx ) << 64 ) | rax;

  const uint64_t rbx = context.get_reg ( Register::RBX, 8 );
  const uint64_t rcx = context.get_reg ( Register::RCX, 8 );
  const uint128_t rcx_rbx = ( uint128_t ( rcx ) << 64 ) | rbx;

  bool equal = ( mem_val == rdx_rax );
  if ( equal ) {
    context.set_memory<uint128_t> ( addr, rcx_rbx );
  }
  else {
    context.set_reg ( Register::RAX, static_cast< uint64_t >( mem_val ), 8 );
    context.set_reg ( Register::RDX, static_cast< uint64_t >( mem_val >> 64 ), 8 );
  }

  auto& flags = context.get_flags ( );
  flags.ZF = equal ? 1 : 0;
}
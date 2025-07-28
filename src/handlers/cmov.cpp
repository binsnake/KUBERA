#include "../../emulator.hpp"
#include <bit>
#include "helpers.hpp"

using namespace kubera;

template <typename Func>
void cmovcc ( const iced::Instruction& instr, KUBERA& context, Func condition ) {
  if ( condition ( context ) ) {
    const uint64_t src_val = helpers::get_operand_value<uint64_t> ( instr, 1u, context );
    helpers::set_operand_value<uint64_t> ( instr, 0u, src_val, context );
  }
}

/// CMOVO-Conditional Move if Overflow
/// Moves the source operand to the destination if OF is set.
void handlers::cmovo ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).OF; } );
}

/// CMOVNL-Conditional Move if Not Less
/// Moves the source operand to the destination if SF equals OF.
void handlers::cmovnl ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).SF == context.get_flags ( ).OF; } );
}

/// CMOVBE-Conditional Move if Below or Equal
/// Moves the source operand to the destination if CF or ZF is set.
void handlers::cmovbe ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).CF || context.get_flags ( ).ZF; } );
}

/// CMOVZ-Conditional Move if Zero
/// Moves the source operand to the destination if ZF is set.
void handlers::cmovz ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).ZF; } );
}

/// CMOVLE-Conditional Move if Less or Equal
/// Moves the source operand to the destination if ZF is set or SF differs from OF.
void handlers::cmovle ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).ZF || ( context.get_flags ( ).SF != context.get_flags ( ).OF ); } );
}

/// CMOVL-Conditional Move if Less
/// Moves the source operand to the destination if SF differs from OF.
void handlers::cmovl ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).SF != context.get_flags ( ).OF; } );
}

/// CMOVNP-Conditional Move if Not Parity
/// Moves the source operand to the destination if PF is clear.
void handlers::cmovnp ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).PF; } );
}

/// CMOVNS-Conditional Move if Not Sign
/// Moves the source operand to the destination if SF is clear.
void handlers::cmovns ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).SF; } );
}

/// CMOVP-Conditional Move if Parity
/// Moves the source operand to the destination if PF is set.
void handlers::cmovp ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).PF; } );
}

/// CMOVNB-Conditional Move if Not Below
/// Moves the source operand to the destination if CF is clear.
void handlers::cmovnb ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).CF; } );
}

/// CMOVNO-Conditional Move if Not Overflow
/// Moves the source operand to the destination if OF is clear.
void handlers::cmovno ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).OF; } );
}

/// CMOVS-Conditional Move if Sign
/// Moves the source operand to the destination if SF is set.
void handlers::cmovs ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).SF; } );
}

/// CMOVNZ-Conditional Move if Not Zero
/// Moves the source operand to the destination if ZF is clear.
void handlers::cmovnz ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).ZF; } );
}

/// CMOVNBE-Conditional Move if Not Below or Equal
/// Moves the source operand to the destination if CF and ZF are clear.
void handlers::cmovnbe ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).ZF && !context.get_flags ( ).CF; } );
}

/// CMOVB-Conditional Move if Below
/// Moves the source operand to the destination if CF is set.
void handlers::cmovb ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).CF; } );
}

/// CMOVNLE-Conditional Move if Not Less or Equal
/// Moves the source operand to the destination if ZF is clear and SF equals OF.
void handlers::cmovnle ( const iced::Instruction& instr, KUBERA& context ) {
  cmovcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).ZF && ( context.get_flags ( ).SF == context.get_flags ( ).OF ); } );
}

#include "../../emulator.hpp"
#include <bit>
#include "helpers.hpp"

using namespace kubera;

template <typename Func>
void setcc ( const iced::Instruction& instr, KUBERA& context, Func condition ) {
  const size_t op_size = instr.op0_size ( );
  const uint64_t result = condition ( context ) ? 1 : 0;
  helpers::set_operand_value<uint64_t> ( instr, 0u, result, context );
}

/// SETB-Set Byte if Below
/// Sets the destination byte to 1 if CF is set, otherwise to 0.
void handlers::setb ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).CF; } );
}

/// SETNP-Set Byte if Not Parity
/// Sets the destination byte to 1 if PF is clear, otherwise to 0.
void handlers::setnp ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).PF; } );
}

/// SETS-Set Byte if Sign
/// Sets the destination byte to 1 if SF is set, otherwise to 0.
void handlers::sets ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).SF; } );
}

/// SETNL-Set Byte if Not Less
/// Sets the destination byte to 1 if SF equals OF, otherwise to 0.
void handlers::setnl ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).SF == context.get_flags ( ).OF; } );
}

/// SETO-Set Byte if Overflow
/// Sets the destination byte to 1 if OF is set, otherwise to 0.
void handlers::seto ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).OF; } );
}

/// SETBE-Set Byte if Below or Equal
/// Sets the destination byte to 1 if CF or ZF is set, otherwise to 0.
void handlers::setbe ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).CF | context.get_flags ( ).ZF; } );
}

/// SETZ-Set Byte if Zero
/// Sets the destination byte to 1 if ZF is set, otherwise to 0.
void handlers::setz ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).ZF; } );
}

/// SETNB-Set Byte if Not Below
/// Sets the destination byte to 1 if CF is clear, otherwise to 0.
void handlers::setnb ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).CF; } );
}

/// SETNO-Set Byte if Not Overflow
/// Sets the destination byte to 1 if OF is clear, otherwise to 0.
void handlers::setno ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).OF; } );
}

/// SETP-Set Byte if Parity
/// Sets the destination byte to 1 if PF is set, otherwise to 0.
void handlers::setp ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).PF; } );
}

/// SETLE-Set Byte if Less or Equal
/// Sets the destination byte to 1 if ZF is set or SF differs from OF, otherwise to 0.
void handlers::setle ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).ZF | ( context.get_flags ( ).SF ^ context.get_flags ( ).OF ); } );
}

/// SETNLE-Set Byte if Not Less or Equal
/// Sets the destination byte to 1 if ZF is clear and SF equals OF, otherwise to 0.
void handlers::setnle ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).ZF && ( context.get_flags ( ).SF == context.get_flags ( ).OF ); } );
}

/// SETNS-Set Byte if Not Sign
/// Sets the destination byte to 1 if SF is clear, otherwise to 0.
void handlers::setns ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).SF; } );
}

/// SETL-Set Byte if Less
/// Sets the destination byte to 1 if SF differs from OF, otherwise to 0.
void handlers::setl ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return context.get_flags ( ).SF != context.get_flags ( ).OF; } );
}

/// SETNBE-Set Byte if Not Below or Equal
/// Sets the destination byte to 1 if CF and ZF are clear, otherwise to 0.
void handlers::setnbe ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).CF && !context.get_flags ( ).ZF; } );
}

/// SETNZ-Set Byte if Not Zero
/// Sets the destination byte to 1 if ZF is clear, otherwise to 0.
void handlers::setnz ( const iced::Instruction& instr, KUBERA& context ) {
  setcc ( instr, context, [ ] ( KUBERA& context ) { return !context.get_flags ( ).ZF; } );
}

#include <context/emulator.hpp>
#include <bit>
#include "helpers.hpp"

using namespace kubera;
/// NOP - No operation
void handlers::nop ( const iced::Instruction& instr, KUBERA& context ) {

}

/// PREFETCHW - Prefetch Write
/// Provides a hint to prefetch a memory location for writing, with no effect on registers or memory, without affecting flags.
void handlers::prefetchw ( const iced::Instruction& instr, KUBERA& context ) {
	if ( instr.op0_kind ( ) != OpKindSimple::Memory ) {
		// !TODO(exception)
		return;
	}
	// No-op in emulation
}
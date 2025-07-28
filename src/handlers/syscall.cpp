#include "../../emulator.hpp"
#include <bit>
#include "helpers.hpp"

using namespace kubera;

/// SYSCALL-Fast System Call
void handlers::syscall ( const iced::Instruction& instr, KUBERA& context ) {
	std::printf ( "[!!!] Syscall instruction executed without a platform hook!\n" );
}
#include <KUBERA/KUBERA.hpp>
#include <print>
#include <sstream>
#include <chrono>
#include <Windows.h>

/*
0:  48 01 d1                add    rcx,rdx
3:  48 c1 c1 05             rol    rcx,0x5
7:  48 81 e1 aa aa 00 00    and    rcx,0xaaaa
e:  48 c1 c9 0b             ror    rcx,0xb
12: 48 81 f1 f0 f0 00 00    xor    rcx,0xf0f0
19: 48 c1 d1 0d             rcl    rcx,0xd
1d: 48 81 c9 cc cc 00 00    or     rcx,0xcccc
24: 48 c1 e1 08             shl    rcx,0x8
28: 48 81 e1 55 55 00 00    and    rcx,0x5555
2f: 48 c1 d1 03             rcl    rcx,0x3
33: 48 81 f1 a5 a5 00 00    xor    rcx,0xa5a5
3a: 48 f7 d1                not    rcx
3d: 48 81 c9 ff ff 00 00    or     rcx,0xffff
44: 48 83 f1 1f             xor    rcx,0x1f
48: 48 c1 e1 04             shl    rcx,0x4
4c: 48 81 e1 aa aa 00 00    and    rcx,0xaaaa
53: 48 c1 e9 07             shr    rcx,0x7
57: 48 c1 c1 09             rol    rcx,0x9
5b: 48 81 f1 3c 3c 3c 3c    xor    rcx,0x3c3c3c3c
62: 48 c1 e9 02             shr    rcx,0x2
66: 48 81 c9 ff ff 00 00    or     rcx,0xffff
6d: 48 c1 c9 06             ror    rcx,0x6
71: 48 81 e1 f5 f5 00 00    and    rcx,0xf5f5
78: 48 c1 e1 05             shl    rcx,0x5
7c: 48 81 f1 5a 5a 00 00    xor    rcx,0x5a5a
83: 48 89 c8                mov    rax,rcx
86: c3                      ret
*/
const uint8_t test_fn [ ] = { 0x48, 0x01, 0xD1, 0x48, 0xC1, 0xC1, 0x05, 0x48, 0x81, 0xE1, 0xAA, 0xAA, 0x00, 0x00, 0x48, 0xC1, 0xC9, 0x0B, 0x48, 0x81, 0xF1, 0xF0, 0xF0, 0x00, 0x00, 0x48, 0xC1, 0xD1, 0x0D, 0x48, 0x81, 0xC9, 0xCC, 0xCC, 0x00, 0x00, 0x48, 0xC1, 0xE1, 0x08, 0x48, 0x81, 0xE1, 0x55, 0x55, 0x00, 0x00, 0x48, 0xC1, 0xD1, 0x03, 0x48, 0x81, 0xF1, 0xA5, 0xA5, 0x00, 0x00, 0x48, 0xF7, 0xD1, 0x48, 0x81, 0xC9, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0x83, 0xF1, 0x1F, 0x48, 0xC1, 0xE1, 0x04, 0x48, 0x81, 0xE1, 0xAA, 0xAA, 0x00, 0x00, 0x48, 0xC1, 0xE9, 0x07, 0x48, 0xC1, 0xC1, 0x09, 0x48, 0x81, 0xF1, 0x3C, 0x3C, 0x3C, 0x3C, 0x48, 0xC1, 0xE9, 0x02, 0x48, 0x81, 0xC9, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0xC1, 0xC9, 0x06, 0x48, 0x81, 0xE1, 0xF5, 0xF5, 0x00, 0x00, 0x48, 0xC1, 0xE1, 0x05, 0x48, 0x81, 0xF1, 0x5A, 0x5A, 0x00, 0x00, 0x48, 0x89, 0xC8, 0xC3 };
const uint8_t benchmark_fn [ ] = {
	0x48, 0x01, 0xD1,				// add rcx, rdx
	0x48, 0xC1, 0xD1, 0x0D, // rcl rcx, 0xd
	0x48, 0xF7, 0xD1,				// not rcx
	0x48, 0x89, 0xC8,				// mov rax, rcx
};

// This function is a benchmark for the emulation speed.
void run_emulation_loop ( kubera::KUBERA& ctx, const uint8_t* test_fn, size_t test_fn_size, uint64_t flags_before_running ) {
	uint64_t instruction_count = 0;
	auto start_time = std::chrono::high_resolution_clock::now ( );
	while ( true ) {
		auto current_time = std::chrono::high_resolution_clock::now ( );
		auto elapsed_seconds = std::chrono::duration_cast< std::chrono::duration<double> > (
				current_time - start_time ).count ( );

		if ( elapsed_seconds >= 10.0 ) {
			break;
		}

		// We configure the decoder to the start of the shellcode.
		ctx.decoder->reconfigure ( test_fn, test_fn_size, 0 );
		// We use set_reg_internal here because we are aware of exactly which registers we want to set,
		// reducing overhead for getting the correct bits of a 64-bit register
		ctx.set_reg_internal<kubera::KubRegister::RCX, Register::RCX, uint32_t> ( 0xFFAA );
		ctx.set_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint32_t> ( 0x0055 );
		// We reset the EFlags, so the state is reset properly for every iteration
		ctx.get_flags ( ).value = flags_before_running;
		// We are only emulating 4 instructions.
		for ( auto i = 0u; i < 4u; ++i ) {
			// We decode the instruction with Iced
			auto instr = ctx.decoder->decode ( );
			// We execute the instruction within out emulation context
			ctx.execute ( instr );
		}

		instruction_count += 4;
	}

	auto end_time = std::chrono::high_resolution_clock::now ( );
	auto total_seconds = std::chrono::duration_cast< std::chrono::duration<double> > (
			end_time - start_time ).count ( );
	double instructions_per_second = instruction_count / total_seconds;

	std::println ( "Total instructions executed: {}", instruction_count );
	std::println ( "Total time elapsed: {:.2f} seconds", total_seconds );
	std::println ( "Instructions per second: {:.2f}", instructions_per_second );
}


/// The following function executes a function on hardware, capturing the result and flags.
/// Then, it runs the same function with the same entry flags and parameters with the emulator and shows the results.
int main ( ) {
	std::println ( "[+] Initializing KUBERA - Windows example" );
	// Currently, the function is for running a benchmark
	kubera::KUBERA ctx {};
	run_emulation_loop ( ctx, benchmark_fn, sizeof ( benchmark_fn ), __readeflags ( ) );
	std::getchar ( );
	// Comment the emulation loop & getchar, along with the return underneath to test the emulator against hardware
	// on Windows.
	return 1;
	// Generic way to set a register's value
	ctx.set_reg ( Register::RCX, 0xFFAA, 4 );
	ctx.set_reg ( Register::RDX, 0x0055, 4 );

	DWORD old;
	// Allocate memory for the shellcode on host
	auto* alloc = VirtualAlloc ( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( !alloc ) {
		std::println ( "Failed to allocate memory" ); std::getchar ( );
		return -1;
	}
	// Copy the shellcode to the new memory allocation
	memcpy ( alloc, test_fn, sizeof ( test_fn ) );
	// Adjust permissions to be readable and executable, as RWX memory may cause problems.
	VirtualProtect ( alloc, 0x1000, PAGE_EXECUTE_READ, &old );
	// We record the flags before running the shellcode, to match in our emulation loop.
	const auto flags_before_running = __readeflags ( );
	// Run the shellcode natively to get expected output.
	const auto expected_value =
		reinterpret_cast< uint64_t ( * )( uint64_t, uint64_t ) >( alloc ) ( 0xFFAA, 0x0055 );
	// Resulting flags after running the shellcode natively.
	const auto native_flags = __readeflags ( );
	// Configure the decoder
	ctx.decoder->reconfigure ( test_fn, sizeof ( test_fn ), 0 );
	// Set the initial flags for the emulator to the same flags the host had prior to execution.
	ctx.get_flags ( ).value = flags_before_running;
	// Emulate in loop
	while ( ctx.decoder->can_decode ( ) ) {
		auto instr = ctx.decoder->decode ( );

		ctx.execute ( instr );
		std::println ( "{}", instr.to_string ( ) );
	}

	const auto emu_value = ctx.get_reg ( Register::RAX );
	const auto emu_flags = ctx.get_flags ( ).value;
	std::println ( "RAX    => [EMU: {:#x}] = [HW: {:#x}]", emu_value, expected_value );
	std::println ( "EFLAGS => [EMU: {:#x}] = [HW: {:#x}]", emu_flags, native_flags );
	// Compare the results
	assert ( emu_value == expected_value && "Native & Emulator value mismatch for test_fn" );
	assert ( emu_flags == native_flags && "Native & Emulator flag mismatch for test_fn" );
	std::getchar ( );
}
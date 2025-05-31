#include "header.hpp"
#include <semantics/src/pch.hpp>
#include <shared/context.hpp>
#include <shared/capstone++.hpp>
#include <print>
#include <format>

std::vector<ExceptionTestShellcode> g_exception_tests;

TestResult run_test_shellcode ( const ExceptionTestShellcode& test_case ) {
	TestResult result;
	result.message = "[" + test_case.name + "] ";

	constexpr size_t STACK_SIZE = 0x10000;
	constexpr size_t STACK_ALIGNMENT = 16;
	constexpr int MAX_STEPS = 500;

	EmulationContext state;
	int64_t rsp_offset_dummy = 0;
	InstructionEffect effectd {};

	state.rsp_base = std::unique_ptr<uint8_t [ ], void( * )( uint8_t* )> (
		static_cast< uint8_t* >( _aligned_malloc ( STACK_SIZE, STACK_ALIGNMENT ) ),
		[ ] ( uint8_t* ptr ) { _aligned_free ( ptr ); }
	);
	if ( !state.rsp_base ) {
		result.message += "Failed to allocate stack.";
		return result;
	}
	state.stack_allocated = STACK_SIZE;
	uint64_t stack_base_addr = reinterpret_cast< uint64_t >( state.rsp_base.get ( ) );
	uint64_t initial_rsp = ( stack_base_addr + STACK_SIZE - 0x28 ) & ~15ULL;
	state.set_reg ( X86_REG_RSP, initial_rsp, 8, effectd );
	state.cpu->current_privilege_level = 3; // Assume user mode for tests

	// --- Set required RFLAGS.AC if needed by test ---
	if ( test_case.requires_ac_flag ) {
		state.cpu->cpu_flags.flags.AC = 1;
		// state.cr0.AM = 1; // Assuming CR0.AM is effectively 1 in 64-bit mode if emulated
		std::println ( "DEBUG: Set RFLAGS.AC=1 for test '{}'", test_case.name );
	}
	else {
		state.cpu->cpu_flags.flags.AC = 0; // Ensure AC is off otherwise
	}
	// ---

	LPVOID shellcode_mem = VirtualAlloc (
		nullptr,
		test_case.bytes.size ( ),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE // Use RWX for simplicity in testing writes to code
	);
	if ( !shellcode_mem ) {
		result.message += "Failed to VirtualAlloc executable memory.";
		return result;
	}
	uint64_t shellcode_base_addr = reinterpret_cast< uint64_t >( shellcode_mem );
	memcpy ( shellcode_mem, test_case.bytes.data ( ), test_case.bytes.size ( ) );

	capstone::Decoder* decoder = new capstone::Decoder ( static_cast< uint8_t* >( shellcode_mem ), test_case.bytes.size ( ) - 1, shellcode_base_addr );
	if ( !decoder->can_decode ( ) ) {
		result.message += "Failed to initialize Capstone decoder.";
		VirtualFree ( shellcode_mem, 0, MEM_RELEASE );
		return result;
	}
	state.decoder.emplace_back ( decoder );

	decoder->set_ip ( shellcode_base_addr );

	int steps = 0;
	capstone::Instruction current_instr; // Store current instruction being processed

	while ( steps < MAX_STEPS && decoder->can_decode ( ) ) {
		uint64_t ip_before_decode = decoder->ip ( );
		result.stop_rip = ip_before_decode; // Tentative stop RIP

		current_instr = decoder->decode ( );

		GuestExceptionInfo exception_info = {}; // Holds exception detected in this cycle
		bool run_handler = true;
		bool handler_executed_cleanly = false;


		if ( !current_instr.is_valid ( ) ) {
			exception_info.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, ip_before_decode );
			run_handler = false;
		}
		else {
			const InstructionExceptionInfo& baseInfo = g_instruction_exception_table [ current_instr.mnemonic ( ) ];
			PreCheckInfo check_info = {};
			populate_pre_check_info ( check_info, state, current_instr, baseInfo );

			// Run pre-checks
			exception_info = check_instruction_exceptions ( state, current_instr, check_info );
			if ( exception_info.exception_occurred ) {
				run_handler = false; // Don't run handler if pre-check failed
			}
		}

		// Check for expected INT3 marker *after* pre-checks but *before* handler
		if ( run_handler && current_instr.mnemonic ( ) == X86_INS_INT3 && test_case.expected_exception_code == 0 ) {
			result.message += "Reached expected INT3 marker.";
			result.success = true;
			result.stop_rip = current_instr.ip ( ); // Stop at the INT3
			break;
		}

		// Run the handler if no pre-check exception occurred
		if ( run_handler ) {
			InstructionEffect effect; // Dummy effect
			try {
				auto it = instruction_handlers.find ( static_cast< x86_insn >( current_instr.mnemonic ( ) ) );
				if ( it != instruction_handlers.end ( ) && *it->second ) {
					std::println ( "[{}]{}", state.call_stack.size ( ), std::format ( "{:>{}} ({:#x}) {}", "", state.call_stack.size ( ), current_instr.ip ( ), current_instr.to_string_no_address ( ) ) );
					( *it->second )( current_instr, state, effect );
					handler_executed_cleanly = true;
				}
				else {
					// Handler not found for a valid instruction? Treat as illegal.
					exception_info.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, current_instr.ip ( ) );
					handler_executed_cleanly = false; // Handler didn't run
				}
			}
			catch ( const GuestExceptionInfo& handler_ex ) {
				// Handler itself detected and threw an exception (e.g., DIV/IDIV/BOUND)
				exception_info = handler_ex;
				handler_executed_cleanly = true; // Handler ran partially or fully before throwing
			}
			catch ( const std::exception& handler_host_ex ) {
				// Host exception during handler execution (e.g., null pointer in handler logic)
				result.message += " Host Exception in Handler: " + std::string ( handler_host_ex.what ( ) );
				// Map unexpected host errors to a generic guest fault like AV
				exception_info.set_access_violation ( current_instr.ip ( ), 0, false );
				handler_executed_cleanly = false;
			}
		}


		// Run post-checks ONLY if handler executed cleanly AND no exception so far
		if ( handler_executed_cleanly && !exception_info.exception_occurred ) {
			const InstructionExceptionInfo& baseInfo = g_instruction_exception_table [ current_instr.mnemonic ( ) ];
			uint8_t op_size = get_primary_operand_size ( current_instr ); // Simplified helper

			// Post-execution arithmetic check (mainly for INTO)
			GuestExceptionInfo post_ex = check_post_execution_arithmetic ( state, baseInfo, current_instr.ip ( ), op_size );
			if ( post_ex.exception_occurred ) {
				exception_info = post_ex;
			}
			else {
				// Post-execution FPU/SIMD check
				// NOTE: Requires handlers to have updated FSW/MXCSR correctly
				post_ex = check_post_execution_fpu_simd ( state, baseInfo, current_instr.ip ( ) );
				if ( post_ex.exception_occurred ) {
					exception_info = post_ex;
				}
			}
		}

		// Check if any exception was detected in this cycle
		if ( exception_info.exception_occurred ) {
			result.exception_occurred = true;
			result.captured_exception = exception_info;
			result.stop_rip = exception_info.ExceptionAddress; // Use the RIP from the exception record
			result.message += std::format ( " Detected Exception 0x{:X}.", exception_info.ExceptionCode );
			break; // Stop emulation
		}

		// Check for unexpected INT3 marker (if handler ran and instruction was INT3)
		if ( handler_executed_cleanly && current_instr.mnemonic ( ) == X86_INS_INT3 && test_case.expected_exception_code != 0 ) {
			result.message += " Reached INT3 marker unexpectedly (an exception was expected).";
			result.success = false;
			result.stop_rip = current_instr.ip ( ); // Stop at the unexpected INT3
			break;
		}


		steps++;
	} // End while loop

	bool stopped_at_marker_int3 = false;
	if ( !result.exception_occurred && // No *other* exception occurred
			!test_case.bytes.empty ( ) && // Shellcode not empty
			result.stop_rip == shellcode_base_addr + test_case.bytes.size ( ) - 1 && // Stopped at last byte
			test_case.bytes.back ( ) == 0xCC ) // Last byte is INT3
	{
		// This implies the loop finished because decode reached the final INT3 marker
		// We need to check if this *was* the expected behavior
		stopped_at_marker_int3 = true;
	}


	// --- Verification ---
	if ( stopped_at_marker_int3 && test_case.expected_exception_code == 0 ) {
		// Correctly stopped at the marker INT3 for a test expecting normal termination via marker
		result.success = true;
		result.message += " Success (Reached expected INT3 marker).";

	}
	else if ( result.exception_occurred ) {
		// An exception was captured.
		if ( result.captured_exception.ExceptionCode == test_case.expected_exception_code ) {
			// The captured exception matches the one we expected.
			result.success = true;
			result.message += " Success (Correct exception code captured).";
		}
		else {
			// An exception occurred, but it wasn't the one expected.
			result.success = false;
			result.message += std::format ( " Failure (Expected Exception 0x{:X}, Got 0x{:X}).",
																		test_case.expected_exception_code, result.captured_exception.ExceptionCode );
			// If we expected 0 but got something else (and it wasn't the marker INT3 handled above)
			if ( test_case.expected_exception_code == 0 ) {
				result.message += " An unexpected exception occurred.";
			}
		}
	}
	else { // No exception occurred, and didn't stop at marker INT3 (or marker wasn't expected termination)
		if ( test_case.expected_exception_code == 0 ) {
			// Expected normal termination (no exception, possibly no marker or finished early)
			if ( steps >= MAX_STEPS ) {
				result.message += " Failure (Exceeded max steps, expected normal finish).";
				result.success = false;
			}
			else {
				// Finished before max steps without exception and without marker hit being the goal
				result.message += " Success (Finished normally, no exception expected)."; // Assume finishing early is ok if no marker specified/hit
				result.success = true;
			}
		}
		else {
			// Expected an exception, but none occurred and loop finished.
			result.success = false;
			result.message += std::format ( " Failure (Expected Exception 0x{:X}, but none occurred).", test_case.expected_exception_code );
			if ( steps >= MAX_STEPS ) {
				result.message += " Stopped at max steps.";
			}
			else {
				result.message += std::format ( " Stopped at RIP 0x{:X} without error.", result.stop_rip );
			}
		}
	}

	// --- Cleanup ---
	VirtualFree ( shellcode_mem, 0, MEM_RELEASE );

	return result;
}

void initialize_exception_tests ( ) {
	auto add_nop_int3 = [ ] ( std::vector<uint8_t>& vec )
	{
		vec.push_back ( 0x90 ); // NOP
		vec.push_back ( 0xCC ); // INT3 marker
	};

	// --- #DE Divide By Zero ---
	{
		ExceptionTestShellcode test;
		test.name = "Divide By Zero (#DE)";
		test.expected_exception_code = EXCEPTION_INT_DIVIDE_BY_ZERO; // 0xC0000094
		test.notes = "Triggers #DE via DIV instruction with zero divisor. Handler MUST detect.";
		test.bytes = {
			0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
			0x48, 0x31, 0xD2,                         // xor rdx, rdx
			0x48, 0x31, 0xC9,                         // xor rcx, rcx
			0x48, 0xF7, 0xF1,                         // div rcx <- Exception expected here
		};
		add_nop_int3 ( test.bytes ); // Marker should not be reached
		g_exception_tests.push_back ( test );
	}

	// --- #UD Illegal Instruction (UD2 Opcode) ---
	{
		ExceptionTestShellcode test;
		test.name = "Illegal Instruction UD2 (#UD)";
		test.expected_exception_code = EXCEPTION_ILLEGAL_INSTRUCTION; // 0xC000001D
		test.notes = "Executes the UD2 instruction.";
		test.bytes = {
			0x0F, 0x0B, // ud2 <- Exception expected here
			0xCC        // int3 marker
		};
		g_exception_tests.push_back ( test );
	}

	// --- #UD Illegal Instruction (LOCK Misuse) ---
	{
		ExceptionTestShellcode test;
		test.name = "Illegal Instruction LOCK Misuse (#UD)";
		test.expected_exception_code = EXCEPTION_ILLEGAL_INSTRUCTION; // 0xC000001D
		test.notes = "Uses LOCK prefix on INC REG, which is invalid.";
		test.bytes = {
			0xF0, 0x48, 0xFF, 0xC0, // lock inc rax <- Exception expected here
			0xCC                   // int3 marker
		};
		g_exception_tests.push_back ( test );
	}

	// --- #BP Breakpoint (INT3) ---
	{
		ExceptionTestShellcode test;
		test.name = "Breakpoint (#BP)";
		test.expected_exception_code = EXCEPTION_BREAKPOINT; // 0x80000003
		test.notes = "Executes INT3 instruction.";
		test.bytes = {
			0xCC, // int3 <- Exception expected here
			0x90, // nop (potentially skipped by exception handling)
			0xCC  // int3 marker
		};
		g_exception_tests.push_back ( test );
	}

	// --- Access Violation (NULL Pointer Read) ---
	{
		ExceptionTestShellcode test;
		test.name = "Access Violation (NULL Read)";
		test.expected_exception_code = EXCEPTION_ACCESS_VIOLATION; // 0xC0000005
		test.notes = "Attempts to read from address 0.";
		test.bytes = {
			0x48, 0x31, 0xDB,             // xor rbx, rbx
			0x48, 0x8B, 0x03,             // mov rax, [rbx] <- Exception expected here
		};
		add_nop_int3 ( test.bytes );
		g_exception_tests.push_back ( test );
	}

	// --- Access Violation (NULL Pointer Write) ---
	{
		ExceptionTestShellcode test;
		test.name = "Access Violation (NULL Write)";
		test.expected_exception_code = EXCEPTION_ACCESS_VIOLATION; // 0xC0000005
		test.notes = "Attempts to write to address 0.";
		test.bytes = {
			0x48, 0x31, 0xDB,                         // xor rbx, rbx
			0x48, 0xC7, 0xC0, 0x7B, 0x00, 0x00, 0x00, // mov rax, 123
			0x48, 0x89, 0x03,                         // mov [rbx], rax <- Exception expected here
		};
		add_nop_int3 ( test.bytes );
		g_exception_tests.push_back ( test );
	}

	// --- Access Violation (Write Code) ---
	{
		ExceptionTestShellcode test;
		test.name = "Access Violation (Write Code)";
		test.expected_exception_code = EXCEPTION_ACCESS_VIOLATION; // 0xC0000005
		test.notes = "Attempts to write to the current instruction pointer (read-only code).";
		test.bytes = {
			// mov byte ptr [rip+0], 0 -> Writes to the byte after the immediate 0
			// Encoding: C6 /0 ib -> C6 05 disp32 ib
			0xC6, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, // mov byte ptr [rip+1], 0 <- Exception expected here
			0x90, // Target of the write (will cause AV)
			0xCC // INT3 marker (should not be reached)
		};
		// The instruction is 7 bytes. [rip+1] points to the NOP (offset 7).
		g_exception_tests.push_back ( test );
	}


	// --- Datatype Misalignment (#AC) ---
	{
		ExceptionTestShellcode test;
		test.name = "Datatype Misalignment (#AC)";
		test.expected_exception_code = EXCEPTION_DATATYPE_MISALIGNMENT; // 0x80000002
		test.notes = "Requires RFLAGS.AC=1 set by test framework. Uses MOVAPS on unaligned stack address.";
		test.requires_ac_flag = true; // <<< Mark test as needing AC flag set
		test.bytes = {
			0x48, 0x83, 0xEC, 0x20,             // sub rsp, 0x20
			0x48, 0x8D, 0x5C, 0x24, 0x01,       // lea rbx, [rsp+1] (RBX is now rsp+1, unaligned)
			0x0F, 0x28, 0x03,                   // movaps xmm0, [rbx] <- Exception expected here
			0x48, 0x83, 0xC4, 0x20,             // add rsp, 0x20 (cleanup, likely skipped)
		};
		add_nop_int3 ( test.bytes );
		g_exception_tests.push_back ( test );
	}

	// --- Privileged Instruction (#GP) ---
	{
		ExceptionTestShellcode test;
		test.name = "Privileged Instruction (#GP)";
		test.expected_exception_code = EXCEPTION_PRIV_INSTRUCTION; // 0xC0000096
		test.notes = "Executes HLT in user mode (CPL=3).";
		test.bytes = {
			0xF4, // hlt <- Exception expected here
			0xCC  // int3 marker
		};
		g_exception_tests.push_back ( test );
	}

	// --- Stack Overflow (Manual Write Below RSP) ---
	{
		ExceptionTestShellcode test;
		test.name = "Stack Overflow (Manual Write)";
		// Use AV as the expected code, as guard page hit -> AV is more common than specific SO code from OS
		test.expected_exception_code = EXCEPTION_ACCESS_VIOLATION; // 0xC0000005 (likely result)
		// test.expected_exception_code = EXCEPTION_STACK_OVERFLOW; // 0xC00000FD (less likely from hardware/OS directly)
		test.notes = "Writes significantly below RSP. Emulator stack bounds check or host AV should trigger.";
		test.bytes = {
			// mov qword ptr [rsp - 0x10000], rax
			// Encoding: 48 89 84 24 lo_dword -> 48 89 84 24 00 00 FF FF
			0x48, 0x89, 0x84, 0x24, 0x00, 0x00, 0xFF, 0xFF, // mov [rsp-0x10000], rax <- Exception expected here
		};
		add_nop_int3 ( test.bytes );
		g_exception_tests.push_back ( test );
	}

	// --- Array Bounds Exceeded (#BR) ---
	{
		ExceptionTestShellcode test;
		test.name = "Array Bounds Exceeded (#BR)";
		test.expected_exception_code = EXCEPTION_ARRAY_BOUNDS_EXCEEDED; // 0xC000008C
		test.notes = "Uses BOUND instruction with an out-of-bounds index. Handler MUST detect. 32-bit only";
		test.bytes = {
			0x48, 0x83, 0xEC, 0x10,                         // sub rsp, 16
			0xC7, 0x04, 0x24, 0x0A, 0x00, 0x00, 0x00,       // mov dword ptr [rsp], 10 (lower)
			0xC7, 0x44, 0x24, 0x04, 0x14, 0x00, 0x00, 0x00, // mov dword ptr [rsp+4], 20 (upper)
			0xB8, 0x05, 0x00, 0x00, 0x00,                   // mov eax, 5 (index)
			0x62, 0x04, 0x24,                               // bound eax, [rsp] <- Exception expected here
			0x48, 0x83, 0xC4, 0x10,                         // add rsp, 16 (cleanup, likely skipped)
		};
		add_nop_int3 ( test.bytes );
		g_exception_tests.push_back ( test );
	}

	// --- SSE Invalid Operation (#XF -> Invalid Op) ---
	{
		ExceptionTestShellcode test;
		test.name = "SSE Invalid Operation (#XF)";
		test.expected_exception_code = EXCEPTION_FLT_INVALID_OPERATION; // 0xC0000090
		test.notes = "Calculates sqrt(-1.0) after unmasking invalid operation in MXCSR. SQRTSS handler MUST update MXCSR status.";
		test.bytes = {
			0x48, 0x83, 0xEC, 0x10,                         // sub rsp, 16
			// Setup MXCSR with IM=0 (unmasked invalid operation)
			0x0F, 0xAE, 0x5C, 0x24, 0x08,                   // stmxcsr [rsp+8] (Save default)
			0x8B, 0x44, 0x24, 0x08,                         // mov eax, [rsp+8]
			0x83, 0xE0, 0x7F,                               // and al, 0x7F <- Clears bit 7 (IM)
			0x89, 0x44, 0x24, 0x04,                         // mov [rsp+4], eax (Store modified)
			0x0F, 0xAE, 0x54, 0x24, 0x04,                   // ldmxcsr [rsp+4] (Load modified)
			// Prepare -1.0f
			0xB8, 0x00, 0x00, 0x80, 0xBF,                   // mov eax, 0xBF800000 (-1.0f)
			0x89, 0x04, 0x24,                               // mov [rsp], eax
			0xF3, 0x0F, 0x10, 0x04, 0x24,                   // movss xmm0, [rsp]
			// Trigger exception
			0xF3, 0x0F, 0x51, 0xC0,                         // sqrtss xmm0, xmm0 <- Exception expected (post-check)
			// Cleanup (likely skipped)
			0x0F, 0xAE, 0x5C, 0x24, 0x08,                   // ldmxcsr [rsp+8] (restore)
			0x48, 0x83, 0xC4, 0x10,                         // add rsp, 16
		};
		add_nop_int3 ( test.bytes );
		g_exception_tests.push_back ( test );
	}

	// --- No Exception Expected (Simple Arithmetic) ---
	{
		ExceptionTestShellcode test;
		test.name = "No Exception Expected";
		test.expected_exception_code = 0; // 0 means no exception expected before INT3 marker
		test.notes = "Simple arithmetic, should finish at the INT3 marker.";
		test.bytes = {
			0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
			0x48, 0xC7, 0xC3, 0x05, 0x00, 0x00, 0x00, // mov rbx, 5
			0x48, 0x01, 0xD8,                         // add rax, rbx
			0x48, 0x29, 0xD8,                         // sub rax, rbx
		};
		add_nop_int3 ( test.bytes ); // Expect execution to reach here
		g_exception_tests.push_back ( test );
	}

} // End of initialize_exception_tests
int main ( ) {
	initialize_exception_tests ( );

	std::println ( "Running {} exception tests...", g_exception_tests.size ( ) );
	int passed = 0;
	int failed = 0;

	for ( const auto& test : g_exception_tests ) {
		std::println ( "------------------------------------------" );
		std::println ( "Executing Test: {}", test.name );
		std::println ( "Notes: {}", test.notes );

		TestResult result = run_test_shellcode ( test );

		std::println ( "Result: {}", result.message );
		std::println ( "Stopped at RIP: 0x{:016x}", result.stop_rip );
		if ( result.exception_occurred ) {
			std::println ( "Captured Exception: Code=0x{:X}, Addr=0x{:016x}, VA=0x{:016x}",
				result.captured_exception.ExceptionCode,
				result.captured_exception.ExceptionAddress,
				result.captured_exception.FaultingVa );
		}

		if ( result.success ) {
			std::println ( "Status: PASSED" );
			passed++;
		}
		else {
			std::println ( "Status: FAILED" );
			failed++;
		}
	}

	std::println ( "==========================================" );
	std::println ( "Test Summary: Passed={}, Failed={}", passed, failed );
	std::println ( "==========================================" );

	return ( failed == 0 ) ? 0 : 1;
}
#include <shared/context.hpp>        // Defines EmulationContext, GuestExceptionInfo, etc.
#include <shared/capstone++.hpp>     // Defines capstone::Instruction
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>             // For unique_ptr
#include <malloc.h>           // For _aligned_malloc/_aligned_free (Windows specific)
// Or use std::aligned_alloc if available and preferred on your platform
#include <Windows.h>          // For EXCEPTION_CODES, VirtualAlloc/Free

// --- Forward Declarations of necessary functions ---
// (Ensure these are linked or defined in this file/project)

// Exception checking framework
extern InstructionExceptionInfo g_instruction_exception_table[X86_INS_ENDING];

void populate_pre_check_info(PreCheckInfo& check_info, EmulationContext& state, const capstone::Instruction& instr, const InstructionExceptionInfo& baseInfo);
GuestExceptionInfo check_instruction_exceptions(EmulationContext& state, const capstone::Instruction& instr, const PreCheckInfo& check_info);
GuestExceptionInfo check_post_execution_arithmetic(EmulationContext& state, const InstructionExceptionInfo& baseInfo, uint64_t ip, uint8_t op_size);
GuestExceptionInfo check_post_execution_fpu_simd(EmulationContext& state, const InstructionExceptionInfo& baseInfo, uint64_t ip);
// (You might not need the actual dispatch function for testing, just the checkers)
// void setup_guest_exception_dispatch(EmulationContext& state, const GuestExceptionInfo& ex_info);

// Shellcode test structure (assumed defined elsewhere)
struct ExceptionTestShellcode {
    std::string name;
    DWORD expected_exception_code; // 0 if no exception expected before marker INT3
    std::vector<uint8_t> bytes;
    std::string notes;
    bool requires_ac_flag = false; // Flag to indicate if RFLAGS.AC=1 needs setting
};

// Test result structure
struct TestResult {
    bool success = false;
    bool exception_occurred = false; // Did the emulator *detect* a guest exception?
    GuestExceptionInfo captured_exception = {}; // Details if exception occurred
    uint64_t stop_rip = 0;          // RIP where execution stopped
    std::string message = "";       // Status or error message
};

// Helper to get operand size (simplified)
uint8_t get_primary_operand_size(const capstone::Instruction& instr) {
    if (instr.operand_count() > 0) {
        return instr.operands()[0].size;
    }
    // Guess based on common instructions if needed, but size is usually in op[0]
    switch (instr.mnemonic()) {
    case X86_INS_PUSHFQ:
    case X86_INS_POPFQ: return 8;
        // ... other implicit size cases ...
    default: return 8; // Default guess
    }
}
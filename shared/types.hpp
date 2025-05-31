#pragma once

#include <cstdint>
#include <immintrin.h>
#include <string>
#include <bit>
#include <numeric>
#include <format>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <print>
#include <variant>
#include <intrin.h>
#include <functional>
#include <concepts>

#include "capstone++.hpp"

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cfenv>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

struct EmulationContext;

namespace mp = boost::multiprecision;
using int128_t = mp::int128_t;
using uint128_t = mp::uint128_t;
using uint256_t = mp::uint256_t;
using uint512_t = mp::uint512_t;
using float80_t = mp::number<mp::cpp_bin_float<
  64, // Number of significand bits (including explicit leading bit when non-zero)
  mp::digit_base_2, // Binary representation
  void, std::int16_t, // Use 16-bit exponent type
  -16382, 16383      // Min/Max exponent values
>, mp::et_off>;    // Disable expression templates for simplicity

static constexpr uint8_t FPU_TAG_VALID = 0b00;
static constexpr uint8_t FPU_TAG_ZERO = 0b01;
static constexpr uint8_t FPU_TAG_SPECIAL = 0b10;
static constexpr uint8_t FPU_TAG_EMPTY = 0b11;
static constexpr uint16_t FSW_IE = ( 1 << 0 );
static constexpr uint16_t FSW_DE = ( 1 << 1 );
static constexpr uint16_t FSW_ZE = ( 1 << 2 );
static constexpr uint16_t FSW_OE = ( 1 << 3 );
static constexpr uint16_t FSW_UE = ( 1 << 4 );
static constexpr uint16_t FSW_PE = ( 1 << 5 );
static constexpr uint16_t FSW_SF = ( 1 << 6 );
static constexpr uint16_t FSW_ES = ( 1 << 7 );
static constexpr uint16_t FSW_C0 = ( 1 << 8 );
static constexpr uint16_t FSW_C1 = ( 1 << 9 );
static constexpr uint16_t FSW_C2 = ( 1 << 10 );
static constexpr uint16_t FSW_TOP_SHIFT = 11;
static constexpr uint16_t FSW_TOP_MASK = ( 0b111 << FSW_TOP_SHIFT );
static constexpr uint16_t FSW_C3 = ( 1 << 14 );
static constexpr uint16_t FSW_B = ( 1 << 15 );
static constexpr uint16_t FCW_IM = ( 1 << 0 );
static constexpr uint16_t FCW_DM = ( 1 << 1 );
static constexpr uint16_t FCW_ZM = ( 1 << 2 );
static constexpr uint16_t FCW_OM = ( 1 << 3 );
static constexpr uint16_t FCW_UM = ( 1 << 4 );
static constexpr uint16_t FCW_PM = ( 1 << 5 );
// Bits 8-9: Precision Control (PC) - 00=24b, 01=N/A, 10=53b, 11=64b
static constexpr uint16_t FCW_PC_SHIFT = 8;
static constexpr uint16_t FCW_PC_MASK = ( 0b11 << FCW_PC_SHIFT );
static constexpr uint16_t FCW_RC_SHIFT = 10;
static constexpr uint16_t FCW_RC_MASK = ( 0b11 << FCW_RC_SHIFT );

struct ExceptCategories {
  bool MEMORY : 1 = false; // Checks for general non-stack memory operands ([mem])
  bool STACK : 1 = false; // Checks specifically related to RSP and stack accesses
  bool ARITHMETIC : 1 = false; // Checks for integer calculation errors (#DE, #BR, #OF)
  bool INVALID_USAGE : 1 = false; // Checks for privilege, I/O, LOCK, invalid forms, traps (#UD, #GP, #BP, #DB, #NM)
  bool ALIGNMENT : 1 = false; // Checks for memory alignment requirements (#AC, intrinsic #GP)
  bool FPU_SIMD : 1 = false; // Checks for FPU/MMX/SSE/AVX errors (#MF, #XF)
  bool CONTROL_FLOW : 1 = false; // Checks for branch target validity (less common exception source)
};

struct MemExcepConditions {
  // --- Segment Related (User-Mode) ---
  bool CHECK_NULL_FS_SELECTOR : 1 = false; // Usage of FS override with NULL FS selector -> #GP(0) -> AV
  bool CHECK_NULL_GS_SELECTOR : 1 = false; // Usage of GS override with NULL GS selector -> #GP(0) -> AV
  // --- Address Related ---
  bool CHECK_CANONICAL_ADDRESS : 1 = false; // Effective Address is non-canonical -> #GP(0) -> AV
  // General page faults (#PF) and segment protection (#GP writing read-only) -> Handled by Host OS AV
};

struct StackExcepConditions {
  bool CHECK_STACK_BOUNDS : 1 = false; // RSP change or access exceeds TEB StackLimit/StackBase -> StackOverflow/AV
  bool CHECK_STACK_ALIGNMENT : 1 = false; // RSP not correctly aligned for operation (PUSH/POP/CALL/RET/SSE stack mem) -> #AC or #SS -> AV/Misaligned
  bool CHECK_NULL_SS_SELECTOR : 1 = false; // SS Selector is NULL -> #SS(0) -> AV (Less likely in 64-bit user mode unless explicitly loaded)
  bool CHECK_CANONICAL_STACK_ADDRESS : 1 = false; // RSP becomes non-canonical -> #SS(0) -> AV
};

struct ArithExcepConditions {
  bool CHECK_DIVIDE_ERROR : 1 = false; // DIV/IDIV divisor=0 or quotient overflow -> #DE -> DivByZero
  bool CHECK_BOUND_RANGE : 1 = false; // BOUND index < lower or index > upper -> #BR -> BoundsExceeded
  bool CHECK_INTO_OVERFLOW : 1 = false; // INTO executed when RFLAGS.OF=1 -> #OF -> Overflow
};

struct InvalidUsageExcepConditions {
  // --- Privilege & I/O ---
  bool CHECK_PRIVILEGED_INSTRUCTION : 1 = false; // HLT, LGDT, MOV CRn etc. from CPL=3 -> #GP(0) -> PrivInstr
  bool CHECK_IO_INSTRUCTION : 1 = false; // IN/OUT/INS/OUTS without permission -> #GP(0) -> PrivInstr

  // --- LOCK Prefix ---
  bool CHECK_INVALID_LOCK_PREFIX : 1 = false; // LOCK on invalid instruction or non-mem dest -> #UD -> IllegalInstr

  // --- Opcode/Instruction Form ---
  bool CHECK_INVALID_OPCODE_FORM : 1 = false; // Undefined opcode, invalid operands, missing mandatory prefix (VEX/EVEX etc.) -> #UD -> IllegalInstr
  bool CHECK_OPERAND_SIZE_MISMATCH : 1 = false; // e.g., String ops with mismatched operand sizes if not allowed -> #UD? or #GP? (Check specific instr)

  // --- Traps ---
  bool CHECK_INT3_BREAKPOINT : 1 = false; // INT 3 encountered -> #BP -> Breakpoint
  bool CHECK_DEBUG_TRAP : 1 = false; // Debug register match or RF=1 or TF=1 (if emulating) -> #DB -> SingleStep/DebugTrap

  // --- FPU/SIMD State ---
  bool CHECK_FPU_DEVICE_NOT_AVAILABLE : 1 = false; // Access FPU/MMX/SSE when CR0.TS=1 or CR0.EM=1 -> #NM -> DeviceNotAvailable
};

struct AlignExcepConditions {
  bool CHECK_GENERAL_AC_FLAG : 1 = false; // Unaligned access + CPL=3 + RFLAGS.AC=1 + CR0.AM=1 -> #AC -> Misaligned
  bool CHECK_INTRINSIC_ALIGNMENT : 1 = false; // Instruction requires specific alignment (MOVAPS/DQA, FXSAVE, etc.) regardless of AC flag -> #GP(0) -> AV (often)
};

struct FpuSimdExcepConditions {
  // These are typically checked *after* execution based on status flags and control masks
  bool CHECK_X87_FAULT_MF : 1 = false; // Unmasked x87 exception occurred (check FSW vs FCW) -> #MF -> FPUError
  bool CHECK_SIMD_FP_FAULT_XF : 1 = false; // Unmasked SIMD FP exception occurred (check MXCSR status vs mask) -> #XF -> SIMDFPError
};

struct ControlFlowExcepConditions {
  // These often result in AV due to bad memory access, but represent control flow logic errors
  bool CHECK_NON_CANONICAL_TARGET : 1 = false; // JMP/CALL target address is non-canonical -> #GP(0) -> AV
  bool CHECK_RETURN_STACK_MISMATCH : 1 = false; // RET executed when stack pointer is invalid (not a direct exception, but leads to crash/AV)
};

struct InstructionExceptionInfo {
  ExceptCategories categories {}; // Default categories based on mnemonic

  // --- Intrinsic Properties ---
  bool is_privileged : 1 = false;
  bool is_io : 1 = false;
  bool is_int3 : 1 = false;
  bool is_invalid_by_default : 1 = false;
  bool is_fpu_related : 1 = false; // Touches x87 state
  bool is_mmx_related : 1 = false; // Touches MMX state
  bool is_sse_avx_related : 1 = false; // Touches SSE/AVX state

  bool lock_prefix_allowed : 1 = false;
  bool lock_prefix_always_invalid : 1 = false;

  bool is_divide : 1 = false;
  bool is_bound : 1 = false;
  bool is_into : 1 = false;

  bool requires_intrinsic_alignment : 1 = false;
  uint8_t intrinsic_alignment_bytes : 4 = 0; // e.g., 8, 16, 32, 64

  bool is_explicit_push : 1 = false;
  bool is_explicit_pop : 1 = false;
  bool uses_string_registers : 1 = false; // Uses RSI/RDI implicitly (MOVS, etc.)
  bool modifies_rsp_implicitly : 1 = false; // CALL, RET, PUSH, POP, ENTER, LEAVE
};

struct GuestExceptionInfo {
  bool exception_occurred = false;

  // Fields matching EXCEPTION_RECORD
  DWORD    ExceptionCode = 0;
  DWORD    ExceptionFlags = 0; // e.g., EXCEPTION_NONCONTINUABLE
  uint64_t ExceptionAddress = 0; // RIP of faulting instruction
  DWORD    NumberParameters = 0;
  std::array<ULONG_PTR, EXCEPTION_MAXIMUM_PARAMETERS> ExceptionInformation = { 0 };

  // Additional info needed for CONTEXT setup or dispatch
  uint64_t FaultingVa = 0; // VA causing fault (used for Param[1] in AV)

  // --- Helper methods to populate for standard exceptions ---
  void set_exception ( DWORD code, uint64_t rip, uint64_t fault_va = 0 ) {
    exception_occurred = true;
    ExceptionCode = code;
    ExceptionAddress = rip;
    FaultingVa = fault_va; // Store separately for potential use
    ExceptionFlags = 0;    // Hardware exceptions usually start continuable
    NumberParameters = 0;
    ExceptionInformation.fill ( 0 );

    // Populate standard parameters based on code
    if ( code == EXCEPTION_ACCESS_VIOLATION ) {
      NumberParameters = 2;
      ExceptionInformation [ 0 ] = 0; // Default to Read access violation
      ExceptionInformation [ 1 ] = fault_va;
    }
    else if ( code == EXCEPTION_STACK_OVERFLOW ) {
      // Kernel typically raises AV for guard page hit, but if we detect
      // stack bounds violation directly, we might use Stack Overflow code.
      // Parameters for Stack Overflow itself are often zero from hardware.
      NumberParameters = 0; // Or potentially ExceptionInformation[0] = fault_va; Check MSDN/tests.
    }
    else if ( code == EXCEPTION_DATATYPE_MISALIGNMENT ||
            code == EXCEPTION_ILLEGAL_INSTRUCTION ||
            code == EXCEPTION_PRIV_INSTRUCTION ||
            code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
            code == EXCEPTION_BREAKPOINT ||
            code == EXCEPTION_ARRAY_BOUNDS_EXCEEDED || // For #BR
            code == EXCEPTION_INT_OVERFLOW ) {         // For #OF (INTO)
      NumberParameters = 0;
    }
  }

  // Specific helper for Access Violation to set read/write/exec type
  void set_access_violation ( uint64_t rip, uint64_t va, bool is_write, bool is_execute = false ) {
    set_exception ( EXCEPTION_ACCESS_VIOLATION, rip, va );
    ExceptionInformation [ 0 ] = is_write ? 1 : ( is_execute ? 8 : 0 ); // Write=1, Exec=8, Read=0
    ExceptionInformation [ 1 ] = va;
    NumberParameters = 2;
  }

  // Helper to simulate RaiseException (if needed later)
  void set_from_raise_exception ( DWORD code, DWORD flags, DWORD num_params, const ULONG_PTR* params, uint64_t rip ) {
    exception_occurred = true;
    ExceptionCode = code;
    ExceptionFlags = flags;
    ExceptionAddress = rip; // Address of RaiseException call site
    FaultingVa = 0; // Not applicable directly
    NumberParameters = ( num_params > EXCEPTION_MAXIMUM_PARAMETERS ) ? EXCEPTION_MAXIMUM_PARAMETERS : num_params;
    ExceptionInformation.fill ( 0 );
    if ( params && NumberParameters > 0 ) {
      memcpy ( ExceptionInformation.data ( ), params, NumberParameters * sizeof ( ULONG_PTR ) );
    }
  }
};

struct PreCheckInfo {
  bool has_lock_prefix = false;
  bool has_mem_operand = false;
  uint64_t mem_effective_addr = 0;
  uint8_t mem_op_size = 0;
  x86_reg mem_segment_reg = X86_REG_INVALID;
  bool uses_fs = false;
  bool uses_gs = false;
  bool mem_is_write = false; // <<< ADDED
  bool is_stack_push = false;
  bool is_stack_pop = false;
  uint64_t stack_access_addr = 0;
  uint8_t stack_access_size = 0;
  bool alignment_required_by_ac = false;
  bool alignment_required_intrinsic = false;
  uint8_t required_alignment_bytes = 1;
};

inline int parity ( uint64_t x ) {
#ifdef _MSC_VER
  return static_cast< int >( __popcnt64 ( x ) & 1 );
#elif defined(__GNUC__) || defined(__clang__)
  return __builtin_popcountll ( x ) & 1;
#else
  // Portable fallback (can be slow)
  int count = 0;
  while ( x ) {
    count += ( x & 1 );
    x >>= 1;
  }
  return count & 1;
#endif
}

struct __NT_TIB64 {
  uint64_t ExceptionList;                                                //0x0
  uint64_t StackBase;                                                    //0x8
  uint64_t StackLimit;                                                   //0x10
  uint64_t SubSystemTib;                                                 //0x18
  union {
    uint64_t FiberData;                                                //0x20
    unsigned long Version;                                                      //0x20
  };
  uint64_t ArbitraryUserPointer;                                         //0x28
  uint64_t Self;                                                         //0x30
};

struct _CLIENT_ID64 {
  uint64_t UniqueProcess;                                                //0x0
  uint64_t UniqueThread;                                                 //0x8
};

struct _LIST_ENTRY64 {
  uint64_t Flink;
  uint64_t Blink;
};

struct _ACTIVATION_CONTEXT_STACK64 {
  uint64_t ActiveFrame;                                                  //0x0
  _LIST_ENTRY64 FrameListCache;                                     //0x8
  unsigned long Flags;                                                            //0x18
  unsigned long NextCookieSequenceNumber;                                         //0x1c
  unsigned long StackId;                                                          //0x20
};

struct _GDI_TEB_BATCH64 {
  ULONG Offset : 30;                                                        //0x0
  ULONG InProcessing : 1;                                                   //0x0
  ULONG HasRenderingCommand : 1;                                            //0x0
  ULONGLONG HDC;                                                          //0x8
  ULONG Buffer [ 310 ];                                                      //0x10
};

struct _STRING64 {
  USHORT Length;                                                          //0x0
  USHORT MaximumLength;                                                   //0x2
  ULONGLONG Buffer;                                                       //0x8
};

struct _TEB64 {
  __NT_TIB64 NtTib;                                                 //0x0
  uint64_t EnvironmentPointer;                                           //0x38
  _CLIENT_ID64 ClientId;                                           //0x40
  uint64_t ActiveRpcHandle;                                              //0x50
  uint64_t ThreadLocalStoragePointer;                                    //0x58
  uint64_t ProcessEnvironmentBlock;                                      //0x60
  unsigned long LastErrorValue;                                                   //0x68
  unsigned long CountOfOwnedCriticalSections;                                     //0x6c
  uint64_t CsrClientThread;                                              //0x70
  uint64_t Win32ThreadInfo;                                              //0x78
  unsigned long User32Reserved [ 26 ];                                               //0x80
  unsigned long UserReserved [ 5 ];                                                  //0xe8
  uint64_t WOW32Reserved;                                                //0x100
  unsigned long CurrentLocale;                                                    //0x108
  unsigned long FpSoftwareStatusRegister;                                         //0x10c
  uint64_t ReservedForDebuggerInstrumentation [ 16 ];                       //0x110
  uint64_t SystemReserved1 [ 25 ];                                          //0x190
  uint64_t HeapFlsData;                                                  //0x258
  uint64_t RngState [ 4 ];                                                  //0x260
  
  CHAR PlaceholderCompatibilityMode;                                      //0x280
  UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
  CHAR PlaceholderReserved [ 10 ];                                           //0x282
  unsigned long ProxiedProcessId;                                                 //0x28c
  _ACTIVATION_CONTEXT_STACK64 _ActivationStack;                    //0x290
  UCHAR WorkingOnBehalfTicket [ 8 ];                                         //0x2b8
  LONG ExceptionCode;                                                     //0x2c0
  UCHAR Padding0 [ 4 ];                                                      //0x2c4
  uint64_t ActivationContextStackPointer;                                //0x2c8
  uint64_t InstrumentationCallbackSp;                                    //0x2d0
  uint64_t InstrumentationCallbackPreviousPc;                            //0x2d8
  uint64_t InstrumentationCallbackPreviousSp;                            //0x2e0
  unsigned long TxFsContext;                                                      //0x2e8
  UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
  UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
  UCHAR Padding1 [ 2 ];                                                      //0x2ee
  _GDI_TEB_BATCH64 GdiTebBatch;                                    //0x2f0
  _CLIENT_ID64 RealClientId;                                       //0x7d8
  uint64_t GdiCachedProcessHandle;                                       //0x7e8
  unsigned long GdiClientPID;                                                     //0x7f0
  unsigned long GdiClientTID;                                                     //0x7f4
  uint64_t GdiThreadLocalInfo;                                           //0x7f8
  uint64_t Win32ClientInfo [ 62 ];                                          //0x800
  uint64_t glDispatchTable [ 233 ];                                         //0x9f0
  uint64_t glReserved1 [ 29 ];                                              //0x1138
  uint64_t glReserved2;                                                  //0x1220
  uint64_t glSectionInfo;                                                //0x1228
  uint64_t glSection;                                                    //0x1230
  uint64_t glTable;                                                      //0x1238
  uint64_t glCurrentRC;                                                  //0x1240
  uint64_t glContext;                                                    //0x1248
  unsigned long LastStatusValue;                                                  //0x1250
  UCHAR Padding2 [ 4 ];                                                      //0x1254
  _STRING64 StaticUnicodeString;                                   //0x1258
  WCHAR StaticUnicodeBuffer [ 261 ];                                         //0x1268
  UCHAR Padding3 [ 6 ];                                                      //0x1472
  uint64_t DeallocationStack;                                            //0x1478
  uint64_t TlsSlots [ 64 ];                                                 //0x1480
  LIST_ENTRY64 TlsLinks;                                           //0x1680
  uint64_t Vdm;                                                          //0x1690
  uint64_t ReservedForNtRpc;                                             //0x1698
  uint64_t DbgSsReserved [ 2 ];                                             //0x16a0
  unsigned long HardErrorMode;                                                    //0x16b0
  UCHAR Padding4 [ 4 ];                                                      //0x16b4
  uint64_t Instrumentation [ 11 ];                                          //0x16b8
  _GUID ActivityId;                                                //0x1710
  uint64_t SubProcessTag;                                                //0x1720
  uint64_t PerflibData;                                                  //0x1728
  uint64_t EtwTraceData;                                                 //0x1730
  uint64_t WinSockData;                                                  //0x1738
  unsigned long GdiBatchCount;                                                    //0x1740
  union {
    _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
    unsigned long IdealProcessorValue;                                          //0x1744
    struct {
      UCHAR ReservedPad0;                                             //0x1744
      UCHAR ReservedPad1;                                             //0x1745
      UCHAR ReservedPad2;                                             //0x1746
      UCHAR IdealProcessor;                                           //0x1747
    };
  };
  unsigned long GuaranteedStackBytes;                                             //0x1748
  UCHAR Padding5 [ 4 ];                                                      //0x174c
  uint64_t ReservedForPerf;                                              //0x1750
  uint64_t ReservedForOle;                                               //0x1758
  unsigned long WaitingOnLoaderLock;                                              //0x1760
  UCHAR Padding6 [ 4 ];                                                      //0x1764
  uint64_t SavedPriorityState;                                           //0x1768
  uint64_t ReservedForCodeCoverage;                                      //0x1770
  uint64_t ThreadPoolData;                                               //0x1778
  uint64_t TlsExpansionSlots;                                            //0x1780
  uint64_t ChpeV2CpuAreaInfo;                                            //0x1788
  uint64_t Unused;                                                       //0x1790
  unsigned long MuiGeneration;                                                    //0x1798
  unsigned long IsImpersonating;                                                  //0x179c
  uint64_t NlsCache;                                                     //0x17a0
  uint64_t pShimData;                                                    //0x17a8
  unsigned long HeapData;                                                         //0x17b0
  UCHAR Padding7 [ 4 ];                                                      //0x17b4
  uint64_t CurrentTransactionHandle;                                     //0x17b8
  uint64_t ActiveFrame;                                                  //0x17c0
  uint64_t FlsData;                                                      //0x17c8
  uint64_t PreferredLanguages;                                           //0x17d0
  uint64_t UserPrefLanguages;                                            //0x17d8
  uint64_t MergedPrefLanguages;                                          //0x17e0
  unsigned long MuiImpersonation;                                                 //0x17e8
  union {
    volatile USHORT CrossTebFlags;                                      //0x17ec
    USHORT SpareCrossTebBits : 16;                                        //0x17ec
  };
  union {
    USHORT SameTebFlags;                                                //0x17ee
    struct {
      USHORT SafeThunkCall : 1;                                         //0x17ee
      USHORT InDebugPrint : 1;                                          //0x17ee
      USHORT HasFiberData : 1;                                          //0x17ee
      USHORT SkipThreadAttach : 1;                                      //0x17ee
      USHORT WerInShipAssertCode : 1;                                   //0x17ee
      USHORT RanProcessInit : 1;                                        //0x17ee
      USHORT ClonedThread : 1;                                          //0x17ee
      USHORT SuppressDebugMsg : 1;                                      //0x17ee
      USHORT DisableUserStackWalk : 1;                                  //0x17ee
      USHORT RtlExceptionAttached : 1;                                  //0x17ee
      USHORT InitialThread : 1;                                         //0x17ee
      USHORT SessionAware : 1;                                          //0x17ee
      USHORT LoadOwner : 1;                                             //0x17ee
      USHORT LoaderWorker : 1;                                          //0x17ee
      USHORT SkipLoaderInit : 1;                                        //0x17ee
      USHORT SkipFileAPIBrokering : 1;                                  //0x17ee
    };
  };
  uint64_t TxnScopeEnterCallback;                                        //0x17f0
  uint64_t TxnScopeExitCallback;                                         //0x17f8
  uint64_t TxnScopeContext;                                              //0x1800
  unsigned long LockCount;                                                        //0x1808
  LONG WowTebOffset;                                                      //0x180c
  uint64_t ResourceRetValue;                                             //0x1810
  uint64_t ReservedForWdf;                                               //0x1818
  uint64_t ReservedForCrt;                                               //0x1820
  _GUID EffectiveContainerId;                                      //0x1828
  uint64_t LastSleepCounter;                                             //0x1838
  unsigned long SpinCallCount;                                                    //0x1840
  UCHAR Padding8 [ 4 ];                                                      //0x1844
  uint64_t ExtendedFeatureDisableMask;                                   //0x1848
  uint64_t SchedulerSharedDataSlot;                                      //0x1850
  uint64_t HeapWalkContext;                                              //0x1858
  _GROUP_AFFINITY64 PrimaryGroupAffinity;                          //0x1860
  unsigned long Rcu [ 2 ];                                                           //0x1870
};

inline const wchar_t* driverName = L"\\Driver\\EasyAntiCheat_EOS";
inline const wchar_t* registryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\EasyAntiCheat_EOSSys";
struct _UNICODE_STRING {
  USHORT Length;                                                          //0x0
  USHORT MaximumLength;                                                   //0x2
  WCHAR* Buffer;                                                          //0x8
};
struct _DRIVER_OBJECT {
  SHORT Type;                                                             //0x0
  SHORT Size;                                                             //0x2
  struct _DEVICE_OBJECT* DeviceObject;                                    //0x8
  ULONG Flags;                                                            //0x10
  VOID* DriverStart;                                                      //0x18
  ULONG DriverSize;                                                       //0x20
  VOID* DriverSection;                                                    //0x28
  struct _DRIVER_EXTENSION* DriverExtension;                              //0x30
  struct _UNICODE_STRING DriverName;                                      //0x38
  struct _UNICODE_STRING* HardwareDatabase;                               //0x48
  struct _FAST_IO_DISPATCH* FastIoDispatch;                               //0x50
  LONG ( *DriverInit )( struct _DRIVER_OBJECT* arg1, struct _UNICODE_STRING* arg2 ); //0x58
  VOID ( *DriverStartIo )( struct _DEVICE_OBJECT* arg1, struct _IRP* arg2 );  //0x60
  VOID ( *DriverUnload )( struct _DRIVER_OBJECT* arg1 );                      //0x68
  LONG ( *MajorFunction [ 28 ] )( struct _DEVICE_OBJECT* arg1, struct _IRP* arg2 ); //0x70
};

struct MXCSRFlags {
  uint32_t IE : 1;  // Bit 0: Invalid Operation Exception
  uint32_t DE : 1;  // Bit 1: Denormal Exception
  uint32_t ZE : 1;  // Bit 2: Divide-by-Zero Exception
  uint32_t OE : 1;  // Bit 3: Overflow Exception
  uint32_t UE : 1;  // Bit 4: Underflow Exception
  uint32_t PE : 1;  // Bit 5: Precision Exception
  uint32_t DAZ : 1;  // Bit 6: Denormals Are Zero
  uint32_t IM : 1;  // Bit 7: Invalid Operation Mask
  uint32_t DM : 1;  // Bit 8: Denormal Mask
  uint32_t ZM : 1;  // Bit 9: Zero-Divide Mask
  uint32_t OM : 1;  // Bit 10: Overflow Mask
  uint32_t UM : 1;  // Bit 11: Underflow Mask
  uint32_t PM : 1;  // Bit 12: Precision Mask
  uint32_t RC : 2;  // Bits 13-14: Rounding Control (00=RN, 01=RD, 10=RU, 11=RZ)
  uint32_t FZ : 1;  // Bit 15: Flush to Zero
  uint32_t reserved : 16; // Bits 16-31: Reserved (0)
};

struct RFLAGS {
  uint64_t CF : 1;  // Bit 0: Carry Flag
  uint64_t reserved1 : 1;  // Bit 1: Always 1
  uint64_t PF : 1;  // Bit 2: Parity Flag
  uint64_t reserved2 : 1;  // Bit 3: Reserved (0)
  uint64_t AF : 1;  // Bit 4: Auxiliary Carry Flag
  uint64_t reserved3 : 1;  // Bit 5: Reserved (0)
  uint64_t ZF : 1;  // Bit 6: Zero Flag
  uint64_t SF : 1;  // Bit 7: Sign Flag
  uint64_t TF : 1;  // Bit 8: Trap Flag
  uint64_t IF : 1;  // Bit 9: Interrupt Enable Flag (if is reserved, so if_)
  uint64_t DF : 1;  // Bit 10: Direction Flag
  uint64_t OF : 1;  // Bit 11: Overflow Flag
  uint64_t IOPL : 2;  // Bits 12-13: I/O Privilege Level
  uint64_t NT : 1;  // Bit 14: Nested Task
  uint64_t reserved4 : 1;  // Bit 15: Reserved (0)
  uint64_t RF : 1;  // Bit 16: Resume Flag
  uint64_t VM : 1;  // Bit 17: Virtual-8086 Mode
  uint64_t AC : 1;  // Bit 18: Alignment Check
  uint64_t VIF : 1;  // Bit 19: Virtual Interrupt Flag
  uint64_t VIP : 1;  // Bit 20: Virtual Interrupt Pending
  uint64_t ID : 1;  // Bit 21: Identification Flag
  uint64_t reserved5 : 10; // Bits 22-31: Reserved (0)
  uint64_t reserved6 : 32; // Bits 32-63: Reserved (0)
};

struct CallFrame {
  uint64_t return_addr;              // Address to return to
  int64_t rsp_before_call;           // RSP before the call
  std::unordered_map<x86_reg, uint64_t> caller_saved_regs; // Save caller-saved registers
};


struct InstructionEffect {
  std::string instr_str;
  std::vector<std::string> changes;
  std::unordered_set<x86_reg> modified_regs;
  std::unordered_set<uint64_t> modified_mem;
  bool is_no_op = false;
  bool no_log = false;

  void normalize_registers ( EmulationContext* ctx );
  void push_to_changes ( const EmulationContext& ctx, const std::string& data );
  void push_to_changes ( const EmulationContext* ctx, const std::string& data );
  void push_to_changes ( const std::string& data );
};

struct LoadedModule {
  HMODULE handle;
  uint64_t base_address;
  uint64_t size;
  std::unique_ptr<capstone::Decoder> decoder;
};

struct FPUStack {
  std::array<float80_t, 8> fpu_stack;
  uint16_t fpu_tag_word = 0xFFFF;
  uint16_t fpu_status_word = 0;         // Includes B, C3-C0, TOP, ES, SF, PE, UE, OE, ZE, DE, IE
  uint16_t fpu_control_word = 0x037F;   // Default masks, RC=0 (nearest), PC=3 (64b)
  uint16_t mxcsr_control = 0x1F80;
  uint8_t fpu_top = 0;
};

struct CPUFlags {
  RFLAGS flags; // TODO: default init based on HW
  MXCSRFlags mxcsr = {
          .IE = 0,
          .DE = 0,
          .ZE = 0,
          .OE = 0,
          .UE = 0,
          .PE = 0,
          .DAZ = 0,
          .IM = 1,
          .DM = 1,
          .ZM = 1,
          .OM = 1,
          .UM = 1,
          .PM = 1, // Masks default to 1 (masked)
          .RC = 0,
          .FZ = 0,
          .reserved = 0
  };
};


enum KGPR {
  // General-purpose registers (64-bit)
  KRAX,
  KRBX,
  KRCX,
  KRDX,
  KRSI,
  KRDI,
  KRBP,
  KRSP,
  KR8,
  KR9,
  KR10,
  KR11,
  KR12,
  KR13,
  KR14,
  KR15,
  KRIP, // Instruction pointer

  // Debug registers
  KDR0,
  KDR1,
  KDR2,
  KDR3,
  KDR4,
  KDR5,
  KDR6,
  KDR7,

  // Control registers
  KCR0, // Flags
  KCR2, // Page fault linear address
  KCR3, // Page table base
  KCR4, // CPU features/extensions
  KCR8, // CPU priority, interrupts

  // Segment registers
  KCS,
  KDS,
  KES,
  KFS,
  KGS,
  KSS,

  KGPR_COUNT // Total count for array sizing
};
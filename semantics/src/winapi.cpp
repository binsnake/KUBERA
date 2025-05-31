#include "pch.hpp"

#include <cstddef>       // For std::size_t
#include <type_traits>   // For std::integral_constant, std::is_void_v, etc.
#include <array>
#include <string>
#include <tuple>         // For std::tuple, std::tuple_element_t
#include <utility>       // For std::index_sequence, std::make_index_sequence
#include <vector>        // For parsing argument types in log
#include <print>         // C++23 Printing library
#include <concepts>      // For std::integral constraint
#include <algorithm>     // For std::transform (in logging)
#include <iterator>      // For std::back_inserter (in logging)
#include <format>        // For std::format

void kb_forward ( capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect, uint64_t target ) {
  auto it = state.windows->imports.find ( target );
  if ( it == state.windows->imports.end ( ) ) {
    std::print ( "Direct call to unknown address {:016x}h\n", target );
    state.set_reg ( X86_REG_RAX, 0x0, 8, effect );
    return;
  }
  std::string dll_name = it->second.first;
  std::string func_name = it->second.second;
  std::print ( "Direct call to {}!{}\n", dll_name, func_name );

  HMODULE hMod = GetModuleHandleA ( dll_name.c_str ( ) );
  if ( !hMod ) hMod = LoadLibraryA ( dll_name.c_str ( ) );
  if ( !hMod ) {
    std::print ( "Failed to load {}\n", dll_name );
    state.set_reg ( X86_REG_RAX, 0x0, 8, effect );
    return;
  }

  FARPROC proc = GetProcAddress ( hMod, func_name.c_str ( ) );
  if ( !proc ) {
    std::print ( "Failed to resolve {}!{}\n", dll_name, func_name );
    state.set_reg ( X86_REG_RAX, 0x0, 8, effect );
    return;
  }

  std::println ( "[{}] - {} -> unhandled api call", dll_name, func_name );
  //capstone::Decoder new_decoder ( reinterpret_cast< uint8_t* >( hMod ), 0x1000, 0x0 );
  //new_decoder.set_ip ( reinterpret_cast< uint64_t >( proc ) );
  //auto old_decoder = std::exchange ( state.decoder, &new_decoder );
  //
  //std::exchange ( state.decoder, old_decoder );
}

#define _GET_NTH_ARG_PRIVATE(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...) N
#define COUNT_ARGS_IMPL(...) _GET_NTH_ARG_PRIVATE(dummy, ##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define COUNT_ARGS(...) (std::integral_constant<std::size_t, COUNT_ARGS_IMPL(__VA_ARGS__)>::value)
#define KB_PREFIX(name) kb_##name
#define STRINGIFY_VA_ARGS_SAFE(...) "" #__VA_ARGS__ // Keep this helper

// --- Function Traits Helper ---
template<typename T> struct function_traits; // Primary template

template<typename R, typename... Args> // Specialization for WINAPI function pointers
struct function_traits<R ( WINAPI* )( Args... )> {
  using return_type = R;
  using argument_tuple = std::tuple<Args...>;
  static constexpr std::size_t arity = sizeof...( Args );

  template <std::size_t N>
  using argument_type = std::tuple_element_t<N, argument_tuple>;
};

// --- Casting Helper ---
template <typename TargetType>
TargetType safe_arg_cast ( uint64_t raw_value ) {
  if constexpr ( std::is_pointer_v<TargetType> ) {
    return reinterpret_cast< TargetType >( raw_value );
  }
  else if constexpr ( std::is_integral_v<TargetType> || std::is_enum_v<TargetType> ) {
    // Use static_cast for integrals/enums - handles size differences safely
    return static_cast< TargetType >( raw_value );
  }
  else {
    // Add handling for other types (float, double, structs) if needed for your ABI
    static_assert( std::is_pointer_v<TargetType> || std::is_integral_v<TargetType> || std::is_enum_v<TargetType>,
                  "Unsupported argument type in safe_arg_cast for WRAP_WINAPI. Add support if needed." );
    // Fallback (use with caution, might be incorrect for non-pod types)
    return reinterpret_cast< TargetType >( raw_value );
  }
}

// --- invoke_winapi_internal Helper (Fixed to properly manage function types) ---
template <typename Func, typename RetType, std::size_t N, std::size_t... Is>
RetType invoke_winapi_internal (
    Func func,
    const std::array<uint64_t, ( N > 0 ? N : 1 )>& packed_args,
    std::index_sequence<Is...> ) {
  using traits = function_traits<Func>;
  static_assert( traits::arity == N, "Argument count mismatch in invoke_winapi_internal" );
  static_assert( traits::arity == sizeof...( Is ), "Index sequence size mismatch in invoke_winapi_internal" );

  if constexpr ( std::is_void_v<RetType> ) {
    func ( safe_arg_cast< typename std::tuple_element<Is, typename traits::argument_tuple>::type >( packed_args [ Is ] )... );
  }
  else {
    return func ( safe_arg_cast< typename std::tuple_element<Is, typename traits::argument_tuple>::type >( packed_args [ Is ] )... );
  }
}

template <typename VoidFuncPtrType>
void call_and_log_void_return (
    VoidFuncPtrType pfnApi,
    const std::array<uint64_t, ( function_traits<VoidFuncPtrType>::arity > 0 ? function_traits<VoidFuncPtrType>::arity : 1 )>& args_raw ) {
  using traits = function_traits<VoidFuncPtrType>;
  constexpr std::size_t N = traits::arity;

  invoke_winapi_internal<VoidFuncPtrType, void, N> (
      pfnApi,
      args_raw,
      std::make_index_sequence<N>{}
  );

  std::print ( "void" );
}

template <typename NonVoidFuncPtrType>
void call_and_log_non_void_return (
    NonVoidFuncPtrType pfnApi,
    const std::array<uint64_t, ( function_traits<NonVoidFuncPtrType>::arity > 0 ? function_traits<NonVoidFuncPtrType>::arity : 1 )>& args_raw,
    EmulationContext& state ) {
  using traits = function_traits<NonVoidFuncPtrType>;
  using RetType = typename traits::return_type;
  constexpr std::size_t N = traits::arity;

  static_assert( !std::is_void_v<RetType>, "Non-void helper called with void function pointer type" );

  RetType ret_val = invoke_winapi_internal<NonVoidFuncPtrType, RetType, N> (
      pfnApi,
      args_raw,
      std::make_index_sequence<N>{}
  );

  // Set RAX register
  InstructionEffect effect {};
  state.set_reg ( X86_REG_RAX, (uint64_t)ret_val, 8, effect );

  // Log the return value
  if constexpr ( std::is_pointer_v<RetType> ) {
    std::print ( "{:p}", static_cast< const void* >( ret_val ) );
  }
  else if constexpr ( std::is_same_v<RetType, bool> ) {
    std::print ( "{}", ret_val );
  }
  else if constexpr ( std::is_integral_v<RetType> || std::is_enum_v<RetType> ) {
    std::print ( "0x{:x}", ( uint64_t ) ( ret_val ) );
  }
  else {
    std::print ( "{}", ret_val );
  }
}

#define WRAP_WINAPI(api_name, ret_type, ...) \
void KB_PREFIX(api_name) (capstone::Instruction& instr, EmulationContext& state, InstructionEffect& effect, uint64_t target) { \
    /* Define function pointer type using the specific API name and return type */ \
    using func_ptr_type = ret_type(WINAPI *)(__VA_ARGS__); \
    /* Use function_traits to get the correct arity */ \
    using traits = function_traits<func_ptr_type>; \
    constexpr std::size_t arg_count = traits::arity; /* <-- Use traits::arity */ \
    \
    /* Get function pointer to the actual API */ \
    func_ptr_type pfnApi = ::api_name; \
    \
    /* Array to hold arguments (size >= 1 avoids zero-size array issues) */ \
    /* Now uses the correctly determined arg_count */ \
    std::array<uint64_t, (arg_count > 0 ? arg_count : 1)> args_raw{}; \
    \
    /* Read arguments from registers and stack */ \
    if constexpr (arg_count > 0) { \
        constexpr std::array<x86_reg, 4> arg_regs = { X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }; \
        /* Corrected loop bounds */ \
        constexpr std::size_t reg_arg_limit = std::min(arg_count, arg_regs.size()); \
        for (std::size_t i = 0; i < reg_arg_limit; ++i) { \
            args_raw[i] = state.get_reg(arg_regs[i]); \
        } \
        /* Corrected stack argument loop */ \
        constexpr std::size_t stack_arg_count = (arg_count > arg_regs.size()) ? (arg_count - arg_regs.size()) : 0; \
        uint64_t stack_base = state.get_reg(X86_REG_RSP) + 8; /* Skip return address */ \
        for (std::size_t i = 0; i < stack_arg_count; ++i) { \
            /* Index in args_raw is reg_arg_limit + i */ \
            /* Address on stack is stack_base + i * 8 */ \
            args_raw[reg_arg_limit + i] = state.get_memory(stack_base + i * 8, 8); \
        } \
    } \
    \
    /* Declare string for logging args */ \
    const std::string args_as_string{ STRINGIFY_VA_ARGS_SAFE(__VA_ARGS__) }; \
    \
    /* --- Start Logging --- */ \
    std::print("[API] {} (", #api_name); \
    /* Argument parsing and printing logic (existing code seems okay) */ \
    if constexpr (arg_count > 0) { \
        std::vector<std::string> arg_type_names; \
        std::size_t current_pos = 0; int template_level = 0; \
        /* Edge case: handle empty __VA_ARGS__ for arg_count = 0 */ \
        if (!args_as_string.empty()) { \
            for (std::size_t i = 0; i < arg_count; ++i) { \
                std::size_t comma_pos = current_pos; \
                while (comma_pos < args_as_string.length()) { \
                     if (args_as_string[comma_pos] == '<') template_level++; \
                     else if (args_as_string[comma_pos] == '>') template_level--; \
                     else if (args_as_string[comma_pos] == ',' && template_level == 0) break; \
                     comma_pos++; \
                } \
                if (i == arg_count - 1) comma_pos = args_as_string.length(); \
                std::string type_str = args_as_string.substr(current_pos, comma_pos - current_pos); \
                type_str.erase(0, type_str.find_first_not_of(" \t\n\r\f\v")); \
                type_str.erase(type_str.find_last_not_of(" \t\n\r\f\v") + 1); \
                arg_type_names.push_back(type_str); \
                current_pos = comma_pos + 1; \
             } \
         } \
        for (std::size_t i = 0; i < arg_count; ++i) { \
            const std::string& type_name = arg_type_names[i]; \
            uint64_t arg_val = args_raw[i]; \
            bool is_pointer_type = type_name.find('*') != std::string::npos || \
                                   type_name.find("HANDLE") != std::string::npos || \
                                   /* Add other pointer-like types if needed */ \
                                   type_name.find("LP") == 0 || type_name.find("P") == 0; \
            if (type_name.find("LPCSTR") != std::string::npos || type_name.find("char*") != std::string::npos) { \
                 std::print("{}", arg_val ? std::format("\"{}\"", (char*)arg_val) : "NULL"); \
            } else if (type_name.find("LPCWSTR") != std::string::npos || type_name.find("wchar_t*") != std::string::npos) { \
                 if (arg_val) { \
                     std::wstring wstr((wchar_t*)arg_val); std::string narrow_str; \
                     std::transform(wstr.begin(), wstr.end(), std::back_inserter(narrow_str), [](wchar_t wc){ return static_cast<char>(wc); }); /* Safer cast */ \
                     std::print("L\"{}\"", narrow_str); \
                 } else { std::print("NULL"); } \
            } else if (is_pointer_type) { std::print("{:p}", (void*)arg_val); \
            } else { std::print("0x{:x}", arg_val); } \
            if (i < arg_count - 1) std::print(", "); \
        } \
    } \
    std::print(") -> "); /* Print separator before return value */ \
    \
    /* --- Call API and Handle Return using Updated Helpers --- */ \
    /* This part should now work because args_raw has the correct size */ \
    if constexpr (std::is_void_v<ret_type>) { \
        call_and_log_void_return(pfnApi, args_raw); \
    } else { \
        call_and_log_non_void_return(pfnApi, args_raw, state); \
    } \
    \
    std::println(""); /* End the log line */ \
    \
    /* Update RSP offset based on __cdecl calling convention */ \
    /* Note: x64 uses a shadow space, args passed in regs don't affect RSP directly */ \
    /* For __cdecl on x86, caller cleans up stack, but here we model the call */ \
    /* In x64, the called function doesn't change RSP for args passed in regs. */ \
    /* Stack args occupy space, but typically managed within the called func prologue/epilogue */ \
    /* Let's assume for emulation, we don't need to adjust RSP here unless */ \
    /* the called function explicitly manipulates it beyond the standard ABI */ \
    /*state.rsp_offsetmodification might be unnecessary or incorrect here for x64 ABI */ \
}

/* --- Remove or comment out the COUNT_ARGS macros if no longer needed elsewhere ---
#define _GET_NTH_ARG_PRIVATE(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...) N
#define COUNT_ARGS_IMPL(...) _GET_NTH_ARG_PRIVATE(dummy, ##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define COUNT_ARGS(...) (std::integral_constant<std::size_t, COUNT_ARGS_IMPL(__VA_ARGS__)>::value)
*/
uint64_t __fastcall RtlInitializeCriticalSectionEx ( PRTL_CRITICAL_SECTION a1, DWORD a2, uint64_t a3, uint64_t a4 ) {
  return 0;
}
uint64_t __fastcall RtlInitializeCriticalSectionAndSpinCount ( PRTL_CRITICAL_SECTION a1, DWORD a2, uint64_t a3, uint64_t a4 ) {
  return 0;
}
uint64_t __fastcall RtlEnterCriticalSection ( PRTL_CRITICAL_SECTION a1 ) {
  return 0;
}uint64_t __fastcall RtlLeaveCriticalSection ( PRTL_CRITICAL_SECTION a1 ) {
  return 0;
}uint64_t __fastcall RtlDeleteCriticalSection ( PRTL_CRITICAL_SECTION* a1 ) {
  return 0;
}
WRAP_WINAPI ( LoadLibraryA, HMODULE, LPCSTR );
WRAP_WINAPI ( LoadLibraryW, HMODULE, LPCWSTR );
WRAP_WINAPI ( LoadLibraryExA, HMODULE, LPCSTR, HANDLE, DWORD );
WRAP_WINAPI ( LoadLibraryExW, HMODULE, LPCWSTR, HANDLE, DWORD );
WRAP_WINAPI ( GetProcAddress, FARPROC, HMODULE, LPCSTR );
WRAP_WINAPI ( InitializeCriticalSectionAndSpinCount, BOOL, LPCRITICAL_SECTION, DWORD );
WRAP_WINAPI ( InitializeCriticalSectionEx, BOOL, LPCRITICAL_SECTION, DWORD, DWORD );
WRAP_WINAPI ( RtlInitializeCriticalSectionEx, uint64_t, PRTL_CRITICAL_SECTION, DWORD, uint64_t, uint64_t );
WRAP_WINAPI ( RtlInitializeCriticalSectionAndSpinCount, uint64_t, PRTL_CRITICAL_SECTION, DWORD, uint64_t, uint64_t );
WRAP_WINAPI ( RtlEnterCriticalSection, uint64_t, PRTL_CRITICAL_SECTION );
WRAP_WINAPI ( RtlLeaveCriticalSection, uint64_t, PRTL_CRITICAL_SECTION );
WRAP_WINAPI ( RtlDeleteCriticalSection, uint64_t, PRTL_CRITICAL_SECTION* );
WRAP_WINAPI ( FlsAlloc, DWORD, PFLS_CALLBACK_FUNCTION );
WRAP_WINAPI ( FlsGetValue, PVOID, DWORD );
WRAP_WINAPI ( FlsSetValue, BOOL, DWORD, PVOID );
WRAP_WINAPI ( FlsFree, BOOL, DWORD );
WRAP_WINAPI ( TlsAlloc, DWORD );
WRAP_WINAPI ( TlsGetValue, LPVOID, DWORD );
WRAP_WINAPI ( TlsSetValue, BOOL, DWORD, LPVOID );
WRAP_WINAPI ( TlsFree, BOOL, DWORD );
WRAP_WINAPI ( VirtualProtect, BOOL, LPVOID, SIZE_T, DWORD, PDWORD );
WRAP_WINAPI ( InitializeSListHead, void, PSLIST_HEADER );
WRAP_WINAPI ( GetProcessHeap, HANDLE );
WRAP_WINAPI ( IsProcessorFeaturePresent, BOOL, DWORD );
WRAP_WINAPI ( GetLastError, DWORD );

void helpers::bind_winapi ( ) {
  BINDW ( forward );
  BINDW ( LoadLibraryA );
  BINDW ( LoadLibraryW );
  BINDW ( LoadLibraryExA );
  BINDW ( LoadLibraryExW );
  BINDW ( GetProcAddress );

  BINDW ( InitializeCriticalSectionAndSpinCount );
  BINDW ( InitializeCriticalSectionEx );
  BINDW ( RtlInitializeCriticalSectionEx );
  BINDW ( RtlInitializeCriticalSectionAndSpinCount );
  BINDW ( RtlEnterCriticalSection );
  BINDW ( RtlLeaveCriticalSection );
  BINDW ( RtlDeleteCriticalSection );

  BINDW ( InitializeSListHead );

  BINDW ( FlsAlloc );
  BINDW ( FlsGetValue );
  BINDW ( FlsSetValue );
  BINDW ( FlsFree );
  
  BINDW ( TlsAlloc );
  BINDW ( TlsGetValue );
  BINDW ( TlsSetValue );
  BINDW ( TlsFree );

  BINDW ( VirtualProtect );
  BINDW ( GetProcessHeap );

  BINDW ( IsProcessorFeaturePresent );
  BINDW ( GetLastError );
}
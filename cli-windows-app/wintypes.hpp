#pragma once

#include <cstdint>
#include <context/x86.hpp>

namespace windows
{
	constexpr uint16_t code_segment = 0x33;
	constexpr uint16_t data_segment = 0x2B;
	constexpr uint16_t e_segment = 0x2B;
	constexpr uint16_t g_segment = 0x2B;
	constexpr uint16_t file_segment = 0x53;
	constexpr uint16_t segment_selector = 0x2B;
	constexpr x86::Flags rflags { .value = 0x0000000000000300 };
	constexpr x86::Mxcsr mxcsr { .value = 0x00001F80};
	constexpr x86::FPUControlWord fpu_control_word { .value = 0x027F };
	constexpr x86::FPUStatusWord fpu_status_word = { .value = 0x0 };

	inline uint64_t ldr_initialize_thunk = 0ULL;
	inline uint64_t rtl_user_thread_start = 0ULL;
	inline uint64_t ki_user_apc_dispatcher = 0ULL;
	inline uint64_t ki_user_exception_dispatcher = 0ULL;
	inline void* ntdll = nullptr;

	void* get_module_handle ( const char* name );
	void* get_proc_address ( void* bin, const char* name );
};
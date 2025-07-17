#include "wintypes.hpp"
#include <Windows.h>

void* windows::get_module_handle ( const char* name ) {
	return reinterpret_cast< void* >( GetModuleHandleA ( name ) );
}

void* windows::get_proc_address ( void* bin, const char* name ) {
	return GetProcAddress ( reinterpret_cast< HMODULE >( bin ), name );
}
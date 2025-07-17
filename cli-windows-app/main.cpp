#include <context/KUBERA.hpp>
#include <print>
#include <sstream>
#include <chrono>
#include <Windows.h>
#pragma comment(lib, "KUBERA.lib")
#pragma comment(lib, "platform.lib")

namespace windows
{
	uint64_t ldr_initialize_thunk = 0ULL;
	uint64_t rtl_user_thread_start = 0ULL;
};

int main ( ) {
}
#include "wintypes.hpp"
#define NOMINMAX
#include <Windows.h>
#include <context/KUBERA.hpp>
#include "peb.hpp"

void windows::setup_fake_peb ( kubera::KUBERA& ctx, uint64_t image_base ) {
	auto* vm = ctx.get_virtual_memory ( );
	peb_address = vm->alloc ( sizeof ( PEB64 ), kubera::VirtualMemory::READ | kubera::VirtualMemory::WRITE );
	auto* mem = static_cast< PEB64* >( vm->translate ( peb_address, kubera::VirtualMemory::WRITE ) );
	std::memset ( mem, 0, sizeof ( PEB64 ) );
	mem->BeingDebugged = 0;
	mem->ImageBaseAddress = image_base;
	mem->HeapSegmentReserve = 0x0000000000100000ULL;
	mem->HeapSegmentCommit = 0x0000000000002000ULL;
	mem->HeapDeCommitTotalFreeThreshold = 0x0000000000010000ULL;
	mem->HeapDeCommitFreeBlockThreshold = 0x0000000000001000ULL;
	mem->NumberOfHeaps = 0;
	mem->MaximumNumberOfHeaps = 0x10;
	mem->OSPlatformId = 2;
	mem->OSMajorVersion = 0xA;
	mem->OSBuildNumber = 0x6c51;
}
#include "wintypes.hpp"
#define NOMINMAX
#include <Windows.h>
#include <context/KUBERA.hpp>

inline windows::PEB64* NtCurrentPeb ( ) {
	return reinterpret_cast< windows::PEB64* >( __readgsqword ( 0x60 ) );
}

inline windows::TEB64* NtCurrentTeb64 ( ) {
	return reinterpret_cast< windows::TEB64* >( __readgsqword ( offsetof ( windows::_NT_TIB64, Self ) ) );
}

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

	auto* real_peb = NtCurrentPeb ( );

	struct API_SET_NAMESPACE {
		uint32_t Version;
		uint32_t Size;
		uint32_t Flags;
		uint32_t Count;
		uint32_t EntryOffset;
		uint32_t HashOffset;
		uint32_t HashFactor;
	} api_set {};

	auto* real_api_set_map = reinterpret_cast<API_SET_NAMESPACE*>(real_peb->ApiSetMap);
	memcpy ( &api_set, real_api_set_map, sizeof ( API_SET_NAMESPACE ) );
	uint64_t api_set_addr = vm->alloc ( sizeof ( API_SET_NAMESPACE ), kubera::VirtualMemory::READ | kubera::VirtualMemory::WRITE );
	std::memcpy ( vm->translate ( api_set_addr, kubera::VirtualMemory::WRITE ), &api_set, sizeof ( api_set ) );
	mem->ApiSetMap = api_set_addr;
}
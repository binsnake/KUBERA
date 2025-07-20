#include "wintypes.hpp"
#define NOMINMAX
#include <Windows.h>
#include <context/KUBERA.hpp>
#include <ratio>
#include <chrono>

inline windows::PEB64* NtCurrentPeb ( ) {
	return reinterpret_cast< windows::PEB64* >( __readgsqword ( 0x60 ) );
}

inline windows::TEB64* NtCurrentTeb64 ( ) {
	return reinterpret_cast< windows::TEB64* >( __readgsqword ( offsetof ( windows::_NT_TIB64, Self ) ) );
}

void windows::setup_fake_peb ( kubera::KUBERA& ctx, uint64_t image_base ) {
	auto* vm = ctx.get_virtual_memory ( );
	peb_address = vm->alloc ( sizeof ( PEB64 ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	auto* mem = static_cast< PEB64* >( vm->translate ( peb_address, kubera::PageProtection::WRITE ) );
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

	auto* real_api_set_map = reinterpret_cast< API_SET_NAMESPACE* >( real_peb->ApiSetMap );
	memcpy ( &api_set, real_api_set_map, sizeof ( API_SET_NAMESPACE ) );
	uint64_t api_set_addr = vm->alloc ( sizeof ( API_SET_NAMESPACE ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( api_set_addr, kubera::PageProtection::WRITE ), &api_set, sizeof ( api_set ) );
	mem->ApiSetMap = api_set_addr;
}

constexpr auto HUNDRED_NANOSECONDS_IN_ONE_SECOND = 10000000LL;
constexpr auto EPOCH_DIFFERENCE_1601_TO_1970_SECONDS = 11644473600LL;
constexpr auto WINDOWS_EPOCH_DIFFERENCE = EPOCH_DIFFERENCE_1601_TO_1970_SECONDS * HUNDRED_NANOSECONDS_IN_ONE_SECOND;

windows::_KSYSTEM_TIME convert_to_ksystem_time ( const std::chrono::system_clock::time_point& tp ) {
	const auto duration = tp.time_since_epoch ( );
	const auto ns_duration = std::chrono::duration_cast< std::chrono::nanoseconds >( duration );

	const auto total_ticks = ns_duration.count ( ) / 100 + WINDOWS_EPOCH_DIFFERENCE;

	windows::_KSYSTEM_TIME time {};
	time.LowPart = static_cast< uint32_t >( total_ticks );
	time.High1Time = static_cast< int32_t >( total_ticks >> 32 );
	time.High2Time = time.High1Time;

	return time;
}

void user_shared_data_hook ( kubera::VirtualMemory* vm, uint64_t address, std::size_t size ) {
	auto addr = reinterpret_cast< windows::_KUSER_SHARED_DATA* >( vm->translate_bypass ( address ) );
	if ( addr ) {
		auto time = std::chrono::system_clock::now ( );
		auto ksystem_time = convert_to_ksystem_time ( time );
		memcpy ( ( void* ) &addr->SystemTime, &ksystem_time, sizeof ( windows::_KSYSTEM_TIME ) );
	}
}

void windows::setup_user_shared_data ( kubera::KUBERA& ctx ) {
	auto* real_data = reinterpret_cast< _KUSER_SHARED_DATA* >( 0x7ffe0000 );

	// sogen
	_KUSER_SHARED_DATA kusd = { 0 };
	kusd.TickCountMultiplier = 0x0fa00000;
	kusd.InterruptTime.LowPart = 0x17bd9547;
	kusd.InterruptTime.High1Time = 0x0000004b;
	kusd.InterruptTime.High2Time = 0x0000004b;
	kusd.SystemTime.LowPart = 0x7af9da99;
	kusd.SystemTime.High1Time = 0x01db27b9;
	kusd.SystemTime.High2Time = 0x01db27b9;
	kusd.TimeZoneBias.LowPart = 0x3c773000;
	kusd.TimeZoneBias.High1Time = -17;
	kusd.TimeZoneBias.High2Time = -17;
	kusd.TimeZoneId = 0x00000002;
	kusd.LargePageMinimum = 0x00200000;
	kusd.RNGSeedVersion = 0x0000000000000013;
	kusd.TimeZoneBiasStamp = 0x00000004;
	kusd.NtBuildNumber = 0x00006c51;
	kusd.NtProductType = NtProductWinNt;
	kusd.ProductTypeIsValid = 0x01;
	kusd.NativeProcessorArchitecture = 0x0009;
	kusd.NtMajorVersion = 0x0000000a;
	kusd.BootId = 0x0000000b;
	kusd.SystemExpirationDate.QuadPart = 0x01dc26860a9ff300;
	kusd.SuiteMask = 0x00000110;
	kusd.MitigationPolicies = 0x0a;
	kusd.NXSupportPolicy = 0x02;
	kusd.SEHValidationPolicy = 0x02;
	kusd.CyclesPerYield = 0x0064;
	kusd.DismountCount = 0x00000006;
	kusd.ComPlusPackage = 0x00000001;
	kusd.LastSystemRITEventTickCount = 0x01ec1fd3;
	kusd.NumberOfPhysicalPages = 0x00bf0958;
	kusd.FullNumberOfPhysicalPages = 0x0000000000bf0958;
	kusd.TickCount.LowPart = 0x001f7f05;
	kusd.TickCountQuad = 0x00000000001f7f05;
	kusd.Cookie = 0x1c3471da;
	kusd.ConsoleSessionForegroundProcessId = 0x00000000000028f4;
	kusd.TimeUpdateLock = 0x0000000002b28586;
	kusd.BaselineSystemTimeQpc = 0x0000004b17cd596c;
	kusd.BaselineInterruptTimeQpc = 0x0000004b17cd596c;
	kusd.QpcSystemTimeIncrement = 0x8000000000000000;
	kusd.QpcInterruptTimeIncrement = 0x8000000000000000;
	kusd.QpcSystemTimeIncrementShift = 0x01;
	kusd.QpcInterruptTimeIncrementShift = 0x01;
	kusd.UnparkedProcessorCount = 0x000c;
	kusd.TelemetryCoverageRound = 0x00000001;
	kusd.LangGenerationCount = 0x00000003;
	kusd.InterruptTimeBias = 0x00000015a5d56406;
	kusd.ActiveProcessorCount = 0x0000000c;
	kusd.ActiveGroupCount = 0x01;
	kusd.TimeZoneBiasEffectiveStart.QuadPart = 0x01db276e654cb2ff;
	kusd.TimeZoneBiasEffectiveEnd.QuadPart = 0x01db280b8c3b2800;
	kusd.XState.EnabledFeatures = 0x000000000000001f;
	kusd.XState.EnabledVolatileFeatures = 0x000000000000000f;
	kusd.XState.Size = 0x000003c0;
	kusd.QpcData = 0x0083;
	kusd.QpcBypassEnabled = 0x83;
	kusd.QpcBias = 0x000000159530c4af;
	kusd.QpcFrequency = std::chrono::steady_clock::time_point::duration::period::den;

	constexpr std::u16string_view root_dir { u"C:\\WINDOWS" };
	memcpy ( &kusd.NtSystemRoot [ 0 ], root_dir.data ( ), root_dir.size ( ) * 2 );

	kusd.ImageNumberLow = IMAGE_FILE_MACHINE_I386;
	kusd.ImageNumberHigh = IMAGE_FILE_MACHINE_AMD64;
	//0x7ffdffa20000
	auto* vm = ctx.get_virtual_memory ( );
	auto kuser_shared_data = vm->alloc_at ( 0x7ffe0000, sizeof ( _KUSER_SHARED_DATA ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	vm->write_bytes ( kuser_shared_data, &kusd, sizeof ( _KUSER_SHARED_DATA ) );
	vm->protect ( kuser_shared_data, sizeof ( _KUSER_SHARED_DATA ), kubera::PageProtection::READ );
	vm->set_read_hook ( kuser_shared_data, user_shared_data_hook );
}

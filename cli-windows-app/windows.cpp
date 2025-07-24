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

windows::_RTL_USER_PROCESS_PARAMETERS* NtCurrentProcessParameters ( ) {
	auto* peb = NtCurrentPeb ( );
	return reinterpret_cast< windows::_RTL_USER_PROCESS_PARAMETERS* >( peb->ProcessParameters );
}

void setup_process_parameters ( kubera::KUBERA& ctx, windows::_RTL_USER_PROCESS_PARAMETERS* mem ) {
	using namespace windows;
	auto* vm = ctx.get_virtual_memory ( );
	std::memset ( mem, 0, sizeof ( _RTL_USER_PROCESS_PARAMETERS ) );
	auto* real_params = NtCurrentProcessParameters ( );

	// Initialize core fields
	mem->MaximumLength = sizeof ( _RTL_USER_PROCESS_PARAMETERS );
	mem->Length = sizeof ( _RTL_USER_PROCESS_PARAMETERS );
	mem->Flags = 0x00000001; // Normalized (indicates parameters are normalized)
	mem->DebugFlags = 0;

	// Initialize CurrentDirectory
	wchar_t current_directory [ 256 ] { 0 };
	GetCurrentDirectoryW ( 256, current_directory ); // Example current directory
	size_t dir_len = wcslen ( current_directory ) * sizeof ( wchar_t );
	uint64_t dir_buffer_addr = vm->alloc ( dir_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( dir_buffer_addr, kubera::PageProtection::WRITE ), current_directory, dir_len + sizeof ( wchar_t ) );
	mem->CurrentDirectory.DosPath.Length = static_cast< USHORT >( dir_len );
	mem->CurrentDirectory.DosPath.MaximumLength = static_cast< USHORT >( dir_len + sizeof ( wchar_t ) );
	mem->CurrentDirectory.DosPath.Buffer = reinterpret_cast< char16_t* >( dir_buffer_addr );
	mem->CurrentDirectory.Handle = nullptr;

	// Initialize ImagePathName
	std::wstring current_dir = current_directory;
	auto image_path = ( current_dir + L"\\bomboclad.exe" ).c_str ( );
	size_t image_path_len = wcslen ( image_path ) * sizeof ( wchar_t );
	uint64_t image_path_buffer_addr = vm->alloc ( image_path_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( image_path_buffer_addr, kubera::PageProtection::WRITE ), image_path, image_path_len + sizeof ( wchar_t ) );
	mem->ImagePathName.Length = static_cast< USHORT >( image_path_len );
	mem->ImagePathName.MaximumLength = static_cast< USHORT >( image_path_len + sizeof ( wchar_t ) );
	mem->ImagePathName.Buffer = reinterpret_cast< char16_t* >( image_path_buffer_addr );

	// Initialize CommandLine
	wchar_t command_line [ ] = L"bomboclad.exe";
	size_t cmd_len = sizeof ( command_line );
	uint64_t cmd_buffer_addr = vm->alloc ( cmd_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( cmd_buffer_addr, kubera::PageProtection::WRITE ), command_line, cmd_len + sizeof ( wchar_t ) );
	mem->CommandLine.Length = static_cast< USHORT >( cmd_len );
	mem->CommandLine.MaximumLength = static_cast< USHORT >( cmd_len + sizeof ( wchar_t ) );
	mem->CommandLine.Buffer = reinterpret_cast< char16_t* >( cmd_buffer_addr );

	// Initialize DllPath (copy from real parameters)
	if ( real_params->DllPath.Buffer ) {
		size_t dll_path_len = real_params->DllPath.Length;
		uint64_t dll_path_buffer_addr = vm->alloc ( dll_path_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
		std::memcpy ( vm->translate ( dll_path_buffer_addr, kubera::PageProtection::WRITE ), real_params->DllPath.Buffer, dll_path_len + sizeof ( wchar_t ) );
		mem->DllPath.Length = real_params->DllPath.Length;
		mem->DllPath.MaximumLength = real_params->DllPath.MaximumLength;
		mem->DllPath.Buffer = reinterpret_cast< char16_t* >( dll_path_buffer_addr );
	}

	// Initialize Environment (copy from real parameters)
	if ( real_params->Environment ) {
		mem->EnvironmentSize = real_params->EnvironmentSize;
		uint64_t env_buffer_addr = vm->alloc ( mem->EnvironmentSize, kubera::PageProtection::READ | kubera::PageProtection::WRITE );
		if ( mem->EnvironmentSize ) {
			std::memcpy ( vm->translate ( env_buffer_addr, kubera::PageProtection::WRITE ), real_params->Environment, mem->EnvironmentSize );
		}
		mem->Environment = reinterpret_cast< void* >( env_buffer_addr );
		mem->EnvironmentVersion = real_params->EnvironmentVersion;
	}

	// Initialize console and window settings
	mem->ConsoleHandle = nullptr;
	mem->ConsoleFlags = 0;
	mem->StandardInput = nullptr;
	mem->StandardOutput = nullptr;
	mem->StandardError = nullptr;
	mem->StartingX = 0;
	mem->StartingY = 0;
	mem->CountX = 80; // Default console width
	mem->CountY = 25; // Default console height
	mem->CountCharsX = 80;
	mem->CountCharsY = 25;
	mem->FillAttribute = 0x07; // Default text attribute (white on black)
	mem->WindowFlags = 0;
	mem->ShowWindowFlags = 1; // SW_SHOWNORMAL

	// Initialize WindowTitle
	const wchar_t* window_title = L"BOMBOCLAAAAD";
	size_t title_len = wcslen ( window_title ) * sizeof ( wchar_t );
	uint64_t title_buffer_addr = vm->alloc ( title_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( title_buffer_addr, kubera::PageProtection::WRITE ), window_title, title_len + sizeof ( wchar_t ) );
	mem->WindowTitle.Length = static_cast< USHORT >( title_len );
	mem->WindowTitle.MaximumLength = static_cast< USHORT >( title_len + sizeof ( wchar_t ) );
	mem->WindowTitle.Buffer = reinterpret_cast< char16_t* >( title_buffer_addr );

	// Initialize DesktopInfo and ShellInfo
	const wchar_t* desktop_info = L"WinSta0\\Default";
	size_t desktop_len = wcslen ( desktop_info ) * sizeof ( wchar_t );
	uint64_t desktop_buffer_addr = vm->alloc ( desktop_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( desktop_buffer_addr, kubera::PageProtection::WRITE ), desktop_info, desktop_len + sizeof ( wchar_t ) );
	mem->DesktopInfo.Length = static_cast< USHORT >( desktop_len );
	mem->DesktopInfo.MaximumLength = static_cast< USHORT >( desktop_len + sizeof ( wchar_t ) );
	mem->DesktopInfo.Buffer = reinterpret_cast< char16_t* >( desktop_buffer_addr );

	const wchar_t* shell_info = L"";
	size_t shell_len = wcslen ( shell_info ) * sizeof ( wchar_t );
	uint64_t shell_buffer_addr = vm->alloc ( shell_len + sizeof ( wchar_t ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	std::memcpy ( vm->translate ( shell_buffer_addr, kubera::PageProtection::WRITE ), shell_info, shell_len + sizeof ( wchar_t ) );
	mem->ShellInfo.Length = static_cast< USHORT >( shell_len );
	mem->ShellInfo.MaximumLength = static_cast< USHORT >( shell_len + sizeof ( wchar_t ) );
	mem->ShellInfo.Buffer = reinterpret_cast< char16_t* >( shell_buffer_addr );

	// Initialize remaining fields
	mem->ProcessGroupId = real_params->ProcessGroupId;
	mem->LoaderThreads = 1; // Single loader thread
	mem->DefaultThreadpoolCpuSetMaskCount = 0;
	mem->DefaultThreadpoolThreadMaximum = 0;
	mem->HeapMemoryTypeMask = 0;
}

void windows::setup_fake_peb ( kubera::KUBERA& ctx, uint64_t image_base ) {
	auto* vm = ctx.get_virtual_memory ( );
	peb_address = vm->alloc_at ( 0xE00000, sizeof ( PEB64 ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
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
	auto process_params = vm->alloc ( sizeof ( windows::_RTL_USER_PROCESS_PARAMETERS ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	setup_process_parameters ( ctx, reinterpret_cast< windows::_RTL_USER_PROCESS_PARAMETERS* >( vm->translate ( process_params, kubera::PageProtection::WRITE ) ) );
	mem->ProcessParameters = reinterpret_cast< windows::_RTL_USER_PROCESS_PARAMETERS* >( process_params );
	auto ldr = vm->alloc ( sizeof ( windows::_PEB_LDR_DATA ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	mem->Ldr = reinterpret_cast< windows::_PEB_LDR_DATA* >( ldr );
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

void windows::setup_fake_teb ( kubera::KUBERA& ctx ) {
	auto* vm = ctx.get_virtual_memory ( );
	teb_address = vm->alloc_at ( 0xC00000, sizeof ( TEB64 ), kubera::PageProtection::READ | kubera::PageProtection::WRITE );
	auto* mem = static_cast< TEB64* >( vm->translate ( teb_address, kubera::PageProtection::WRITE ) );
	std::memset ( mem, 0, sizeof ( TEB64 ) );
	auto* real_teb = NtCurrentTeb64 ( );
	mem->NtTib.Self = teb_address; // TEB points to itself
	mem->NtTib.StackBase = ctx.stack_base ( ); // Provided stack base
	mem->NtTib.StackLimit = ctx.stack_limit ( ); // Provided stack limit
	mem->ProcessEnvironmentBlock = peb_address; // Link to the fake PEB
	mem->ClientId.UniqueThread = real_teb->ClientId.UniqueThread; // Copy real thread ID
	mem->ClientId.UniqueProcess = real_teb->ClientId.UniqueProcess; // Copy real process ID
	mem->RealClientId = mem->ClientId; // RealClientId mirrors ClientId
	mem->LastErrorValue = 0; // Initialize last error to 0
	mem->CurrentLocale = 0x409; // US English locale (0x409)
	mem->InitialThread = 1; // Mark as initial thread
	mem->SessionAware = 1; // Enable session awareness

	// Initialize StaticUnicodeString
	mem->StaticUnicodeString.Length = 0;
	mem->StaticUnicodeString.MaximumLength = sizeof ( mem->StaticUnicodeBuffer );
	mem->StaticUnicodeString.Buffer = teb_address + offsetof ( TEB64, StaticUnicodeBuffer );

	// Initialize ActivationContextStack
	mem->_ActivationStack.Flags = 0;
	mem->ActivationContextStackPointer = 0;

	// Initialize Group Affinity (default to all CPUs in group 0)
	mem->PrimaryGroupAffinity.Mask = 0xFFFFFFFFFFFFFFFFULL;
	mem->PrimaryGroupAffinity.Group = 0;

	// Initialize GUID for ActivityId (generate a simple mock GUID)
	mem->ActivityId.Data1 = 0x12345678;
	mem->ActivityId.Data2 = 0x1234;
	mem->ActivityId.Data3 = 0x5678;
	std::memcpy ( mem->ActivityId.Data4, "\x01\x02\x03\x04\x05\x06\x07\x08", 8 );

	// Initialize TLS Links (empty list)
	mem->TlsLinks.Flink = teb_address + offsetof ( TEB64, TlsLinks );
	mem->TlsLinks.Blink = teb_address + offsetof ( TEB64, TlsLinks );
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

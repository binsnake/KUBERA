#include "syscalls.hpp"
#include <format>
#include <print>
#include <algorithm>
#include <cctype>
#include <print>
#include "process.hpp"
#include "wintypes.hpp"

using namespace kubera;

#define GET_RSP(ctx) ctx.get_reg_internal<KubRegister::RSP, Register::RSP, uint64_t>()
#define TRANSLATE(x, y) (uint64_t)kubera::memory->translate(x, y, true)
#define ARG1(ctx) ctx.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t>()
#define ARG2(ctx) ctx.get_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t>()
#define ARG3(ctx) ctx.get_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t>()
#define ARG4(ctx) ctx.get_reg_internal<kubera::KubRegister::R9, Register::R9, uint64_t>()
#define ARG5(ctx) *(uint64_t*)(TRANSLATE(GET_RSP(ctx) + 0x28, PageProtection::READ))
#define ARG6(ctx) *(uint64_t*)(TRANSLATE(GET_RSP(ctx) + 0x30, PageProtection::READ))
#define SET_RETURN(ctx, value) ctx.set_reg_internal<KubRegister::RAX, Register::RAX, uint64_t>(value)

constexpr uint64_t CURRENT_PROCESS = ~0ULL;
constexpr uint32_t STATUS_SUCCESS = 0x0;
constexpr uint32_t STATUS_NOT_SUPPORTED = 0xC00000BBL;
constexpr uint32_t STATUS_INVALID_PAGE_PROTECTION = 0xC0000018L;
constexpr uint32_t STATUS_INVALID_ADDRESS = 0xC0000008L;
constexpr uint32_t STATUS_OBJECT_NAME_EXISTS = 0x40000000L;
constexpr uint32_t STATUS_BUFFER_TOO_SMALL = 0xC0000023L;
constexpr uint32_t STATUS_INVALID_HANDLE = 0xC0000008L;

// Template suggestion for pointer translation (not implemented)
template<typename T>
concept PointerType = std::is_pointer_v<T>;

template<PointerType T>
T translate_pointer ( uint64_t arg ) {
	if ( arg == 0 ) return nullptr;
	return reinterpret_cast< T >( kubera::memory->translate ( arg, PageProtection::READ | PageProtection::WRITE ) );
}

// Central dispatcher type
using SyscallHandler = void( * )( uint32_t, kubera::KUBERA& );

// Handler definitions in Windows NT API format
namespace windows
{
	NTSTATUS NtCreateEvent (
			PHANDLE EventHandle,
			ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,
			EVENT_TYPE EventType,
			BOOLEAN InitialState
	) {
		auto* attributes = ObjectAttributes ? reinterpret_cast< windows::_OBJECT_ATTRIBUTES* >( kubera::memory->translate_bypass ( ( uint64_t ) ObjectAttributes ) ) : nullptr;
		std::u16string name;
		if ( attributes && attributes->ObjectName ) {
			name.resize ( attributes->ObjectName->Length / 2 );
			memcpy ( name.data ( ), attributes->ObjectName->Buffer, attributes->ObjectName->Length );
		}

		if ( !name.empty ( ) ) {
			for ( auto& entry : process::event_mgr ) {
				if ( entry.second->name == name ) {
					++entry.second->ref_count;
					*EventHandle = process::make_handle ( entry.first ).bits;
					return STATUS_OBJECT_NAME_EXISTS;
				}
			}
		}

		std::println ( "[syscall - NtCreateEvent] Creating event {}", process::helpers::u16_to_string ( name ) );
		process::WinEvent e { name, EventType, InitialState };
		auto object_exp = process::event_mgr.create_object ( name, EventType, InitialState );
		if ( object_exp.has_value ( ) ) {
			*EventHandle = object_exp->bits;
			return STATUS_SUCCESS;
		}

		return STATUS_NOT_SUPPORTED;
	}

	NTSTATUS NtSetEvent (
		HANDLE EventHandle,
		PLONG PreviousState
	) {
		auto* entry = process::event_mgr.get ( EventHandle );
		if ( !entry ) {
			std::println ( "[syscall - NtSetEvent] Invalid event handle" );
			return STATUS_INVALID_HANDLE;
		}

		if ( PreviousState ) {
			*PreviousState = static_cast< LONG >( entry->signaled );
		}
		const_cast< process::WinEvent* >( entry )->signaled = true;
		return STATUS_SUCCESS;
	}

	NTSTATUS NtManageHotPatch (
			PVOID Unknown1,
			PVOID Unknown2,
			PVOID Unknown3,
			PVOID Unknown4
	) {
		return STATUS_NOT_SUPPORTED;
	}

	NTSTATUS NtQueryVirtualMemory (
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			MEMORY_INFORMATION_CLASS MemoryInformationClass,
			PVOID MemoryInformation,
			SIZE_T MemoryInformationLength,
			PSIZE_T ReturnLength
	) {
		if ( ProcessHandle.bits != CURRENT_PROCESS ) {
			std::println ( "[syscall - NtQueryVirtualMemory] Attempted on foreign process" );
			return STATUS_NOT_SUPPORTED;
		}

		switch ( MemoryInformationClass ) {
			case MemoryWorkingSetExInformation:
			case MemoryImageExtensionInformation:
				std::println ( "[syscall - NtQueryVirtualMemory] Unsupported class {:#x}", static_cast< uint32_t >( MemoryInformationClass ) );
				return STATUS_NOT_SUPPORTED;
			case MemoryBasicInformation:
				if ( ReturnLength ) *ReturnLength = sizeof ( WinMemoryBasicInformation );
				if ( MemoryInformationLength < sizeof ( WinMemoryBasicInformation ) ) {
					return STATUS_BUFFER_TOO_SMALL;
				}
				{
					auto mbi = kubera::memory->get_memory_basic_information ( ( uint64_t ) BaseAddress );
					memcpy ( MemoryInformation, &mbi, sizeof ( WinMemoryBasicInformation ) );
					return STATUS_SUCCESS;
				}
			case MemoryImageInformation:
				if ( ReturnLength ) *ReturnLength = sizeof ( WinMemoryImageInformation );
				if ( MemoryInformationLength < sizeof ( WinMemoryImageInformation ) ) {
					return STATUS_BUFFER_TOO_SMALL;
				}
				{
					auto mod = process::mm.get_module_by_address ( ( uint64_t ) BaseAddress );
					WinMemoryImageInformation mii { 0 };
					mii.ImageBase = mod.base;
					mii.SizeOfImage = mod.size;
					memcpy ( MemoryInformation, &mii, sizeof ( WinMemoryImageInformation ) );
					return STATUS_SUCCESS;
				}
			default:
				std::println ( "[syscall - NtQueryVirtualMemory] Unsupported class {:#x}", static_cast< uint32_t >( MemoryInformationClass ) );
				__debugbreak ( );
				return STATUS_NOT_SUPPORTED;
		}
	}

	NTSTATUS NtAccessCheck (
			PVOID SecurityDescriptor,
			HANDLE ClientToken,
			ACCESS_MASK DesiredAccess,
			PVOID GenericMapping,
			PVOID PrivilegeSet,
			PULONG PrivilegeSetLength,
			PACCESS_MASK GrantedAccess,
			PBOOLEAN AccessStatus
	) {
		return STATUS_NOT_SUPPORTED;
	}

	NTSTATUS NtQueryInformationProcess (
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
	) {
		if ( ProcessHandle.bits != CURRENT_PROCESS ) {
			std::println ( "[syscall - NtQueryInformationProcess] Attempted on foreign process" );
			return STATUS_NOT_SUPPORTED;
		}

		if ( !ProcessInformation ) {
			std::println ( "[syscall - NtQueryInformationProcess] ProcessInformation invalid!" );
			return STATUS_INVALID_ADDRESS;
		}

		switch ( ProcessInformationClass ) {
			case ProcessDebugPort:
			case ProcessDeviceMap:
				*( uint64_t* ) ProcessInformation = 0;
				return STATUS_SUCCESS;
			case ProcessBasicInformation:
				if ( ProcessInformationLength < sizeof ( windows::_PROCESS_BASIC_INFORMATION ) ) {
					std::println ( "[syscall - NtQueryInformationProcess] Buffer too small for ProcessBasicInformation" );
					return STATUS_BUFFER_TOO_SMALL;
				}
				{
					auto* pbi = reinterpret_cast< windows::_PROCESS_BASIC_INFORMATION* > ( ProcessInformation );
					pbi->PebBaseAddress = reinterpret_cast< windows::PEB64* > ( windows::peb_address );
					pbi->UniqueProcessId = windows::HANDLE { .bits = 2432 };
					return STATUS_SUCCESS;
				}
			case ProcessCookie:
				if ( ProcessInformationLength < sizeof ( uint32_t ) ) {
					std::println ( "[syscall - NtQueryInformationProcess] Buffer too small for ProcessCookie" );
					return STATUS_BUFFER_TOO_SMALL;
				}
				*reinterpret_cast< uint32_t* > ( ProcessInformation ) = 0x1234567;
				return STATUS_SUCCESS;
			default:
				std::println ( "unsupported" );
				return STATUS_NOT_SUPPORTED;
		}
	}

	NTSTATUS NtTerminateProcess (
			HANDLE ProcessHandle,
			NTSTATUS ExitStatus
	) {
		if ( ProcessHandle.bits != CURRENT_PROCESS ) {
			std::println ( "[syscall - NtTerminateProcess] Attempted on foreign process" );
			return STATUS_NOT_SUPPORTED;
		}

		std::println ( "[syscall - NtTerminateProcess] Terminating emulation!" );
		__debugbreak ( );
		return STATUS_SUCCESS;
	}

	NTSTATUS NtQueryPerformanceCounter (
			PLARGE_INTEGER PerformanceCounter,
			PLARGE_INTEGER PerformanceFrequency
	) {
		auto* ksd = reinterpret_cast< windows::_KUSER_SHARED_DATA* >( kubera::memory->translate ( 0x7ffe0000, PageProtection::READ ) );
		if ( PerformanceCounter ) {
			*PerformanceCounter =
				LARGE_INTEGER { .QuadPart = std::chrono::system_clock::now ( ).time_since_epoch ( ).count ( ) };
		}
		if ( PerformanceFrequency ) {
			*PerformanceFrequency = LARGE_INTEGER { .QuadPart = ksd->QpcFrequency };
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS NtProtectVirtualMemory (
			HANDLE ProcessHandle,
			PVOID* BaseAddress,
			PSIZE_T NumberOfBytesToProtect,
			ULONG NewAccessProtection,
			PULONG OldAccessProtection
	) {
		if ( ProcessHandle.bits != CURRENT_PROCESS ) {
			std::println ( "[syscall - NtProtectVirtualMemory] Attempted on foreign process" );
			return STATUS_NOT_SUPPORTED;
		}

		const auto orig_start = *BaseAddress;
		const auto orig_length = *NumberOfBytesToProtect;
		const auto aligned_start = ( uint64_t ) orig_start & ~( kubera::memory->page_size - 1 );
		const auto aligned_length = ( ( ( uint64_t ) orig_start + orig_length + kubera::memory->page_size - 1 ) & ~( kubera::memory->page_size - 1 ) ) - aligned_start;

		*BaseAddress = reinterpret_cast< PVOID >( aligned_start );
		*NumberOfBytesToProtect = aligned_length;

		uint8_t requested_protection = 0;
		if ( NewAccessProtection & 0x40 ) { // PAGE_EXECUTE_READWRITE
			requested_protection = PageProtection::READ | PageProtection::WRITE | PageProtection::EXEC;
		}
		else if ( NewAccessProtection & 0x20 ) { // PAGE_EXECUTE_READ
			requested_protection = PageProtection::READ | PageProtection::EXEC;
		}
		else if ( NewAccessProtection & 0x04 ) { // PAGE_READWRITE
			requested_protection = PageProtection::READ | PageProtection::WRITE;
		}
		else if ( NewAccessProtection & 0x02 ) { // PAGE_READONLY
			requested_protection = PageProtection::READ;
		}
		else {
			std::println ( "[syscall - NtProtectVirtualMemory] Invalid protection {:#x}", NewAccessProtection );
			return STATUS_INVALID_PAGE_PROTECTION;
		}

		uint32_t old_protection_value = kubera::memory->map_to_win_protect ( aligned_start );
		if ( !kubera::memory->protect ( aligned_start, static_cast< std::size_t >( aligned_length ), requested_protection ) ) {
			std::println ( "[syscall - NtProtectVirtualMemory] Failed to protect memory at {:#x}", aligned_start );
			return STATUS_INVALID_ADDRESS;
		}

		*OldAccessProtection = old_protection_value;
		return STATUS_SUCCESS;
	}

	NTSTATUS NtQuerySystemInformation (
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
	) {
		switch ( SystemInformationClass ) {
			case SystemBasicInformation:
			case SystemEmulationBasicInformation:
				if ( SystemInformationLength < sizeof ( windows::_SYSTEM_BASIC_INFORMATION ) ) {
					if ( ReturnLength ) *ReturnLength = sizeof ( windows::_SYSTEM_BASIC_INFORMATION );
					std::println ( "[syscall - NtQuerySystemInformation] Buffer too small for SystemBasicInformation" );
					return STATUS_BUFFER_TOO_SMALL;
				}
				{
					auto* sbi = reinterpret_cast< windows::_SYSTEM_BASIC_INFORMATION* > ( SystemInformation );
					if ( !sbi ) {
						std::println ( "[syscall - NtQuerySystemInformation] Invalid buffer for SystemBasicInformation" );
						return STATUS_INVALID_ADDRESS;
					}
					sbi->NumberOfProcessors = 1;
					sbi->PageSize = 0x1000;
					sbi->LowestPhysicalPageNumber = 0;
					sbi->HighestPhysicalPageNumber = 0xFFFFFFFF;
					sbi->AllocationGranularity = 0x10000;
					sbi->MinimumUserModeAddress = 0x0000000000010000ULL;
					sbi->MaximumUserModeAddress = 0x00007ffffffeffffULL;
					sbi->ActiveProcessorsAffinityMask = 0x1;
					return STATUS_SUCCESS;
				}
			default:
				std::println ( "[syscall - NtQuerySystemInformation] Unsupported class {:#x}", static_cast< uint32_t >( SystemInformationClass ) );
				return STATUS_NOT_SUPPORTED;
		}
	}

	NTSTATUS NtTraceEvent (
			HANDLE TraceHandle,
			ULONG Flags,
			ULONG FieldSize,
			PVOID Fields
	) {
		return STATUS_SUCCESS;
	}

	NTSTATUS NtSetInformationProcess (
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength
	) {
		if ( ProcessHandle.bits != CURRENT_PROCESS ) {
			std::println ( "[syscall - NtSetInformationProcess] Attempted on foreign process" );
			return STATUS_NOT_SUPPORTED;
		}

		if ( ProcessInformationClass == ProcessSchedulerSharedData ||
				ProcessInformationClass == ProcessConsoleHostProcess ||
				ProcessInformationClass == ProcessFaultInformation ||
				ProcessInformationClass == ProcessDefaultHardErrorMode ||
				ProcessInformationClass == ProcessRaiseUMExceptionOnInvalidHandleClose ||
				ProcessInformationClass == ProcessDynamicFunctionTableInformation ||
				ProcessInformationClass == ProcessPriorityBoost ) {
			return STATUS_SUCCESS;
		}

		std::println ( "unsupported" );
		return STATUS_NOT_SUPPORTED;
	}
}

void map_syscalls ( ) {
	using namespace windows;
	using namespace syscall_handlers;
	handler_map [ syscall_map [ "NtCreateEvent" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtCreateEvent (
			reinterpret_cast< PHANDLE >( TRANSLATE ( ARG1 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			static_cast< ACCESS_MASK >( ARG2 ( ctx ) ),
			reinterpret_cast< POBJECT_ATTRIBUTES >( TRANSLATE ( ARG3 ( ctx ), PageProtection::READ ) ),
			static_cast< EVENT_TYPE >( ARG4 ( ctx ) ),
			static_cast< BOOLEAN >( ARG5 ( ctx ) )
		) );
	};
	handler_map [ syscall_map [ "NtManageHotPatch" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtManageHotPatch (
			reinterpret_cast< PVOID >( TRANSLATE ( ARG1 ( ctx ), PageProtection::READ ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG2 ( ctx ), PageProtection::READ ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG3 ( ctx ), PageProtection::READ ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG4 ( ctx ), PageProtection::READ ) )
		) );
	};
	handler_map [ syscall_map [ "NtQueryVirtualMemory" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtQueryVirtualMemory (
			HANDLE { .bits = ARG1 ( ctx ) },
			reinterpret_cast< PVOID >( ARG2 ( ctx ) ),
			static_cast< MEMORY_INFORMATION_CLASS >( ARG3 ( ctx ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG4 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			static_cast< SIZE_T >( ARG5 ( ctx ) ),
			reinterpret_cast< PSIZE_T >( TRANSLATE ( ARG6 ( ctx ), PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
	handler_map [ syscall_map [ "NtAccessCheck" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtAccessCheck (
			reinterpret_cast< PVOID >( TRANSLATE ( ARG1 ( ctx ), PageProtection::READ ) ),
			HANDLE { .bits = ARG2 ( ctx ) },
			static_cast< ACCESS_MASK >( ARG3 ( ctx ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG4 ( ctx ), PageProtection::READ ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG5 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			reinterpret_cast< PULONG >( TRANSLATE ( ARG6 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			reinterpret_cast< PACCESS_MASK >( TRANSLATE ( GET_RSP ( ctx ) + 0x38, PageProtection::READ | PageProtection::WRITE ) ),
			reinterpret_cast< PBOOLEAN >( TRANSLATE ( GET_RSP ( ctx ) + 0x40, PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
	handler_map [ syscall_map [ "NtQueryInformationProcess" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtQueryInformationProcess (
			HANDLE { .bits = ARG1 ( ctx ) },
			static_cast< PROCESSINFOCLASS >( ARG2 ( ctx ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG3 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			static_cast< ULONG >( ARG4 ( ctx ) ),
			reinterpret_cast< PULONG >( TRANSLATE ( ARG5 ( ctx ), PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
	handler_map [ syscall_map [ "NtTerminateProcess" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtTerminateProcess (
			HANDLE { .bits = ARG1 ( ctx ) },
			static_cast< NTSTATUS >( ARG2 ( ctx ) )
		) );
	};
	handler_map [ syscall_map [ "NtQueryPerformanceCounter" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtQueryPerformanceCounter (
			reinterpret_cast< PLARGE_INTEGER >( TRANSLATE ( ARG1 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			reinterpret_cast< PLARGE_INTEGER >( TRANSLATE ( ARG2 ( ctx ), PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
	handler_map [ syscall_map [ "NtProtectVirtualMemory" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtProtectVirtualMemory (
			HANDLE { .bits = ARG1 ( ctx ) },
			reinterpret_cast< PVOID* >( TRANSLATE ( ARG2 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			reinterpret_cast< PSIZE_T >( TRANSLATE ( ARG3 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			static_cast< ULONG >( ARG4 ( ctx ) ),
			reinterpret_cast< PULONG >( TRANSLATE ( ARG5 ( ctx ), PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
	handler_map [ syscall_map [ "NtQuerySystemInformation" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtQuerySystemInformation (
			static_cast< SYSTEM_INFORMATION_CLASS >( ARG1 ( ctx ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG2 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			static_cast< ULONG >( ARG3 ( ctx ) ),
			reinterpret_cast< PULONG >( TRANSLATE ( ARG4 ( ctx ), PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
	handler_map [ syscall_map [ "NtTraceEvent" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtTraceEvent (
			HANDLE { .bits = ARG1 ( ctx ) },
			static_cast< ULONG >( ARG2 ( ctx ) ),
			static_cast< ULONG >( ARG3 ( ctx ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG4 ( ctx ), PageProtection::READ ) )
		) );
	};
	handler_map [ syscall_map [ "NtSetInformationProcess" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtSetInformationProcess (
			HANDLE { .bits = ARG1 ( ctx ) },
			static_cast< PROCESSINFOCLASS >( ARG2 ( ctx ) ),
			reinterpret_cast< PVOID >( TRANSLATE ( ARG3 ( ctx ), PageProtection::READ | PageProtection::WRITE ) ),
			static_cast< ULONG >( ARG4 ( ctx ) )
		) );
	};

	handler_map [ syscall_map [ "NtSetEvent" ] ] = [ ] ( uint32_t, kubera::KUBERA& ctx )
	{
		SET_RETURN ( ctx, NtSetEvent (
			HANDLE { .bits = ARG1 ( ctx ) },
			reinterpret_cast< PLONG >( TRANSLATE ( ARG2 ( ctx ), PageProtection::READ | PageProtection::WRITE ) )
		) );
	};
}

template<>
void syscall_handlers::init<true> ( ) {
	( *kubera::instruction_dispatch_table ) [ static_cast< size_t >( Mnemonic::Syscall ) ] = syscall_handlers::dispatcher_verbose;
	map_syscalls ( );
}

template<>
void syscall_handlers::init<false> ( ) {
	( *kubera::instruction_dispatch_table ) [ static_cast< size_t >( Mnemonic::Syscall ) ] = syscall_handlers::dispatcher;
	map_syscalls ( );
}

void syscall_handlers::build_syscall_map ( kubera::KUBERA& ctx, ModuleManager& mm ) {
	const char* mods [ ] = { "C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\win32u.dll" };
	for ( const auto& mod : mods ) {
		const auto* table = mm.get_exports_public ( mod );
		if ( !table ) continue;
		for ( const auto& [name, addr] : *table ) {
			if ( name.size ( ) < 3 || name [ 0 ] != 'N' || name [ 1 ] != 't' ) {
				continue;
			}
			auto* ptr = static_cast< const uint8_t* >( kubera::memory->translate ( addr, kubera::PageProtection::READ | kubera::PageProtection::EXEC ) );
			if ( !ptr ) continue;
			iced::Decoder decoder ( ptr, 32, addr, false );
			bool found = false;
			uint32_t idx = 0;
			for ( int i = 0; i < 16; i++ ) {
				auto& ins = decoder.decode ( );
				if ( !ins.valid ( ) ) break;
				if ( ins.mnemonic ( ) == Mnemonic::Mov &&
						ins.op0_kind ( ) == OpKindSimple::Register &&
						( ins.op0_reg ( ) == Register::EAX || ins.op0_reg ( ) == Register::RAX ) &&
						ins.op1_kind ( ) == OpKindSimple::Immediate ) {
					idx = static_cast< uint32_t > ( ins.immediate ( ) );
				}
				if ( ins.mnemonic ( ) == Mnemonic::Syscall ) {
					found = true;
					break;
				}
				if ( ins.mnemonic ( ) == Mnemonic::Jmp || ins.mnemonic ( ) == Mnemonic::Ret )
					break;
			}
			if ( found ) {
				syscall_map [ name ] = idx;
				handler_name_map [ idx ] = name;
			}
		}
	}
}

void syscall_handlers::dispatcher ( const iced::Instruction& instr, KUBERA& ctx ) {
	const auto syscall_id = ctx.get_reg_internal<KubRegister::RAX, Register::EAX, uint32_t> ( );
	if ( handler_map.contains ( syscall_id ) ) {
		handler_map [ syscall_id ] ( syscall_id, ctx );
	}
}

void syscall_handlers::dispatcher_verbose ( const iced::Instruction& instr, kubera::KUBERA& ctx ) {
	const auto syscall_id = ctx.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( );
	const auto handler_available = handler_map.contains ( syscall_id );
	const auto has_name = handler_name_map.contains ( syscall_id );
	if ( handler_available && has_name ) {
		std::println ( "[syscall - {}] {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
				handler_name_map [ syscall_id ], ARG1 ( ctx ), ARG2 ( ctx ), ARG3 ( ctx ), ARG4 ( ctx ), ARG5 ( ctx ), ARG6 ( ctx ) );
	}

	if ( handler_available ) {
		handler_map [ syscall_id ] ( syscall_id, ctx );
		std::println ( "\t\t-> {:#X}", ctx.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( ) );
	}
	else {
		if ( has_name ) {
			std::println ( "[syscall - {}] No handler! {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
					handler_name_map [ syscall_id ], ARG1 ( ctx ), ARG2 ( ctx ), ARG3 ( ctx ), ARG4 ( ctx ), ARG5 ( ctx ), ARG6 ( ctx ) );
		}
		else {
			std::println ( "[syscall - {:#x}] No handler! {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
					syscall_id, ARG1 ( ctx ), ARG2 ( ctx ), ARG3 ( ctx ), ARG4 ( ctx ), ARG5 ( ctx ), ARG6 ( ctx ) );
		}
		__debugbreak ( );
	}
}
#include "syscalls.hpp"
#include <format>
#include <print>
#include <algorithm>
#include <cctype>
#include "process.hpp"
#include "syscall_host.hpp"
#include "wintypes.hpp"
using namespace kubera;

#define SYSCALL_REG_DUMP(ctx) \
ctx.get_reg_internal<KubRegister::R10, Register::R10, uint64_t>(), \
ctx.get_reg_internal<KubRegister::RDX, Register::RDX, uint64_t>(), \
ctx.get_reg_internal<KubRegister::R8, Register::R8, uint64_t>(), \
ctx.get_reg_internal<KubRegister::R9, Register::R9, uint64_t>()

#define GET_RSP(ctx) ctx.get_reg_internal<KubRegister::RSP, Register::RSP, uint64_t> ( )
#define TRANSLATE(ctx, x, y) (uint64_t)ctx.get_virtual_memory ( )->translate(x, y) 
#define ARG1(ctx) ctx.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( )
#define ARG2(ctx) ctx.get_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( )
#define ARG3(ctx) ctx.get_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t> ( )
#define ARG4(ctx) ctx.get_reg_internal<kubera::KubRegister::R9, Register::R9, uint64_t> ( )
#define ARG5(ctx) *(uint64_t*)(TRANSLATE (ctx, GET_RSP(ctx) + 0x28, PageProtection::READ ))
#define ARG6(ctx) *(uint64_t*)(TRANSLATE (ctx, GET_RSP(ctx) + 0x30, PageProtection::READ ))
#define SET_ARG1(ctx, val) ctx.set_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( val )
#define SET_ARG2(ctx, val) ctx.set_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( val )
#define SET_ARG3(ctx, val) ctx.set_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t> ( val )
#define SET_ARG4(ctx, val) ctx.set_reg_internal<kubera::KubRegister::R9, Register::R9, uint64_t> ( val )
#define SET_ARG5(ctx, val) *(uint64_t*)(TRANSLATE (ctx, GET_RSP(ctx) + 0x28, PageProtection::READ | PageProtection::WRITE ) ) = val
#define SET_ARG6(ctx, val) *(uint64_t*)(TRANSLATE (ctx, GET_RSP(ctx) + 0x30, PageProtection::READ | PageProtection::WRITE ) ) = val
#define SET_RETURN(ctx, value) ctx.set_reg_internal<KubRegister::RAX, Register::RAX, uint64_t>( value )

constexpr uint64_t CURRENT_PROCESS = ~0ULL;
constexpr uint32_t STATUS_SUCCESS = 0x0;
constexpr uint32_t STATUS_NOT_SUPPORTED = 0xC00000BBL;
constexpr uint32_t STATUS_INVALID_PAGE_PROTECTION = 0xC0000018L;
constexpr uint32_t STATUS_INVALID_ADDRESS = 0xC0000008L;
constexpr uint32_t STATUS_OBJECT_NAME_EXISTS = 0x40000000L;
constexpr uint32_t STATUS_BUFFER_TOO_SMALL = 0xC0000023L;

void NtCreateEvent ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	auto* vm = ctx.get_virtual_memory ( );
	auto* attributes = reinterpret_cast< windows::_OBJECT_ATTRIBUTES* >( vm->translate_bypass ( ARG3 ( ctx ) ) );
	std::u16string name;
	if ( attributes ) {
		if ( attributes->ObjectName ) {
			name.resize ( attributes->ObjectName->Length / 2 );
			memcpy ( name.data ( ), attributes->ObjectName->Buffer, attributes->ObjectName->Length );
		}
	}

	if ( !name.empty ( ) ) {
		for ( auto& entry : process::event_mgr ) {
			if ( entry.second->name == name ) {
				++entry.second->ref_count;
				auto handle = process::make_handle ( entry.first ).bits;
				SET_ARG1 ( ctx, handle );
				return SET_RETURN ( ctx, STATUS_OBJECT_NAME_EXISTS );
			}
		}
	}

	std::println ( "[syscall - NtCreateEvent] Creating event {}", process::helpers::u16_to_string ( name ) );
	process::WinEvent e { name, static_cast< process::EVENT_TYPE >( ARG4 ( ctx ) ), static_cast< bool >( ARG5 ( ctx ) ) };
	auto object_exp = process::event_mgr.create_object ( name, static_cast< process::EVENT_TYPE >( ARG4 ( ctx ) ), static_cast< bool >( ARG5 ( ctx ) ) );
	if ( object_exp.has_value ( ) ) {
		SET_ARG1 ( ctx, object_exp->bits );
		return SET_RETURN ( ctx, STATUS_SUCCESS );
	}

	SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
}

void NtManageHotPatch ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
}

void NtQueryVirtualMemory ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	if ( ARG1 ( ctx ) != CURRENT_PROCESS ) {
		std::println ( "[syscall - NtQueryVirtualMemory] Attempted on foreign process" );
		return SET_RETURN ( ctx, 0xC00000BBL );
	}
	auto rsp = GET_RSP ( ctx );
	auto base_address = ARG2 ( ctx );
	auto info_class = ARG3 ( ctx );
	auto memory_buffer = ARG4 ( ctx );
	auto buffer_len = ARG5 ( ctx );
	auto return_length = ARG6 ( ctx );

	switch ( info_class ) {
		case MemoryWorkingSetExInformation:
		case MemoryImageExtensionInformation:
		{
			std::println ( "[syscall - NtQueryVirtualMemory] Unsupported class {:#x}", info_class );
			return SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
		}
		case MemoryBasicInformation:
		{
			if ( return_length != 0 ) {
				SET_ARG6 ( ctx, sizeof ( WinMemoryBasicInformation ) );
			}

			if ( buffer_len < sizeof ( WinMemoryBasicInformation ) ) {
				return SET_RETURN ( ctx, STATUS_BUFFER_TOO_SMALL );
			}

			auto* vm = ctx.get_virtual_memory ( );
			auto mbi = vm->get_memory_basic_information ( base_address );
			auto mbi_addr = vm->translate ( memory_buffer, PageProtection::READ | PageProtection::WRITE );
			memcpy ( mbi_addr, &mbi, sizeof ( WinMemoryBasicInformation ) );

			return SET_RETURN ( ctx, STATUS_SUCCESS );
		}
		case MemoryImageInformation:
		{
			if ( return_length != 0 ) {
				SET_ARG6 ( ctx, sizeof ( WinMemoryImageInformation ) );
			}

			if ( buffer_len < sizeof ( WinMemoryImageInformation ) ) {
				return SET_RETURN ( ctx, STATUS_BUFFER_TOO_SMALL );
			}

			auto mod = process::mm.get_module_by_address ( ARG2 ( ctx ) );
			WinMemoryImageInformation mii { 0 };
			mii.ImageBase = mod.base;
			mii.SizeOfImage = mod.size;
			auto* vm = ctx.get_virtual_memory ( );
			auto mii_addr = vm->translate ( ARG4 ( ctx ), PageProtection::READ | PageProtection::WRITE );
			memcpy ( mii_addr, &mii, sizeof ( WinMemoryImageInformation ) );

			return SET_RETURN ( ctx, STATUS_SUCCESS );
		}
		default:
			std::println ( "[syscall - NtQueryVirtualMemory] Unsupported class {:#x}", info_class );
			__debugbreak ( );
	}

	ctx.set_reg_internal<KubRegister::RAX, Register::EAX, uint32_t> ( 0xC00000BBL );
}

void NtAccessCheck ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
}

void NtQueryInformationProcess ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	if ( ARG1 ( ctx ) != CURRENT_PROCESS ) {
		std::println ( "[syscall - NtQueryInformationProcess] Attempted on foreign process" );
		SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
		return;
	}

	switch ( ARG2 ( ctx ) ) {
		case 7: // DebugPort
		case 23: // DeviceMap
		{
			ctx.get_virtual_memory ( )->write ( ARG3 ( ctx ), 0 );
			break;
		};
		default:
			std::println ( "unsupported" );
			SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
	}

	SET_RETURN ( ctx, STATUS_SUCCESS );
}

void NtTerminateProcess ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	if ( ARG1 ( ctx ) != ~0UL ) {
		std::println ( "[syscall - NtTerminateProcess] Attempted on foreign process" );
		SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
		return;
	}

	std::println ( "[syscall - NtTerminateProcess] Terminating emulation!" );
	__debugbreak ( );
}

void NtQueryPerformanceCounter ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	auto* vm = ctx.get_virtual_memory ( );
	auto* ksd = reinterpret_cast< windows::_KUSER_SHARED_DATA* >( vm->translate ( 0x7ffe0000, PageProtection::READ ) );
	if ( ARG1 ( ctx ) ) {
		SET_ARG1 ( ctx, std::chrono::system_clock::now ( ).time_since_epoch ( ).count ( ) );
	}

	if ( ARG2 ( ctx ) ) {
		SET_ARG2 ( ctx, ksd->QpcFrequency );
	}

	SET_RETURN ( ctx, STATUS_SUCCESS );
}

void NtProtectVirtualMemory ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	const auto process_handle = ARG1 ( ctx );
	const auto base_address_ptr = ARG2 ( ctx );
	const auto bytes_to_protect_ptr = ARG3 ( ctx );
	const auto protection = static_cast< uint32_t >( ARG4 ( ctx ) );
	const auto old_protection_ptr = ARG5 ( ctx );

	if ( process_handle != CURRENT_PROCESS ) {
		std::println ( "[syscall - NtProtectVirtualMemory] Attempted on foreign process" );
		SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
		return;
	}

	auto* vm = ctx.get_virtual_memory ( );
	const auto orig_start = vm->read<uint64_t> ( base_address_ptr );
	const auto orig_length = vm->read<uint32_t> ( bytes_to_protect_ptr );
	const auto aligned_start = orig_start & ~( vm->page_size - 1 );
	const auto aligned_length = ( ( orig_start + orig_length + vm->page_size - 1 ) & ~( vm->page_size - 1 ) ) - aligned_start;

	vm->write<uint64_t> ( base_address_ptr, aligned_start );
	vm->write<uint32_t> ( bytes_to_protect_ptr, static_cast< uint32_t >( aligned_length ) );

	uint8_t requested_protection = 0;
	if ( protection & 0x40 ) { // PAGE_EXECUTE_READWRITE
		requested_protection = PageProtection::READ | PageProtection::WRITE | PageProtection::EXEC;
	}
	else if ( protection & 0x20 ) { // PAGE_EXECUTE_READ
		requested_protection = PageProtection::READ | PageProtection::EXEC;
	}
	else if ( protection & 0x04 ) { // PAGE_READWRITE
		requested_protection = PageProtection::READ | PageProtection::WRITE;
	}
	else if ( protection & 0x02 ) { // PAGE_READONLY
		requested_protection = PageProtection::READ;
	}
	else {
		std::println ( "[syscall - NtProtectVirtualMemory] Invalid protection {:#x}", protection );
		SET_RETURN ( ctx, STATUS_INVALID_PAGE_PROTECTION );
		return;
	}

	uint32_t old_protection_value = vm->map_to_win_protect ( aligned_start );
	if ( !vm->protect ( aligned_start, static_cast< std::size_t >( aligned_length ), requested_protection ) ) {
		std::println ( "[syscall - NtProtectVirtualMemory] Failed to protect memory at {:#x}", aligned_start );
		SET_RETURN ( ctx, STATUS_INVALID_ADDRESS );
		return;
	}

	vm->write<uint32_t> ( old_protection_ptr, old_protection_value );

	SET_RETURN ( ctx, STATUS_SUCCESS );
}

void NtQuerySystemInformation ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
}

void NtTraceEvent ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	SET_RETURN ( ctx, STATUS_SUCCESS );
}

void NtSetInformationProcess ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	if ( ARG1 ( ctx ) != CURRENT_PROCESS ) {
		std::println ( "[syscall - NtSetInformationProcess] Attempted on foreign process" );
		SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
		return;
	}

	auto info_class = ARG2 ( ctx );
	if ( info_class == ProcessSchedulerSharedData                     //
			|| info_class == ProcessConsoleHostProcess                   //
			|| info_class == ProcessFaultInformation                     //
			|| info_class == ProcessDefaultHardErrorMode                 //
			|| info_class == ProcessRaiseUMExceptionOnInvalidHandleClose //
			|| info_class == ProcessDynamicFunctionTableInformation      //
			|| info_class == ProcessPriorityBoost ) {
		return SET_RETURN ( ctx, STATUS_SUCCESS );
	}

	std::println ( "unsupported" );
	SET_RETURN ( ctx, STATUS_NOT_SUPPORTED );
}


void map_syscalls ( ) {
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtCreateEvent" ] ] = NtCreateEvent;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtManageHotPatch" ] ] = NtManageHotPatch;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtQueryVirtualMemory" ] ] = NtQueryVirtualMemory;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtTerminateProcess" ] ] = NtTerminateProcess;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtAccessCheck" ] ] = NtAccessCheck;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtQueryPerformanceCounter" ] ] = NtQueryPerformanceCounter;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtProtectVirtualMemory" ] ] = NtProtectVirtualMemory;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtQuerySystemInformation" ] ] = NtQuerySystemInformation;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtTraceEvent" ] ] = NtTraceEvent;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtQueryInformationProcess" ] ] = NtQueryInformationProcess;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtSetInformationProcess" ] ] = NtSetInformationProcess;
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
			if ( name.size ( ) < 3 ) {
				continue;
			}
			if ( name [ 0 ] != 'N' || name [ 1 ] != 't' ) {
				continue;
			}
			auto* ptr = static_cast< const uint8_t* >( ctx.get_virtual_memory ( )->translate ( addr, kubera::PageProtection::READ | kubera::PageProtection::EXEC ) );
			if ( !ptr ) {
				continue;
			}
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
	std::string fmt;
	const auto syscall_id = ctx.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( );
	const auto handler_available = handler_map.contains ( syscall_id );
	const auto has_name = handler_name_map.contains ( syscall_id );
	if ( handler_available && handler_name_map.contains ( syscall_id ) ) {
		std::println ( "[syscall - {}] {:#x} {:#x} {:#x} {:#x}", handler_name_map [ syscall_id ], SYSCALL_REG_DUMP ( ctx ) );
	}

	if ( handler_available ) {
		handler_map [ syscall_id ] ( syscall_id, ctx );
		std::println ( "\t\t-> {:#X}", ctx.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( ) );
	}
	else {
		if ( has_name ) {
			std::println ( "[syscall - {}] No handler! {:#x} {:#x} {:#x} {:#x}", handler_name_map [ syscall_id ], SYSCALL_REG_DUMP ( ctx ) );
		}
		else {
			std::println ( "[syscall - {:#x}] No handler! {:#x} {:#x} {:#x} {:#x}", syscall_id, SYSCALL_REG_DUMP ( ctx ) );
		}
		__debugbreak ( );
	}
}

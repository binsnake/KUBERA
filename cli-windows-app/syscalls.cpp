#include "syscalls.hpp"
#include <format>
#include <print>
#include <algorithm>
#include <cctype>
#include "process.hpp"
#include "syscall_host.hpp"
using namespace kubera;

#define SYSCALL_REG_DUMP(ctx) \
ctx.get_reg_internal<KubRegister::R10, Register::R10, uint64_t>(), \
ctx.get_reg_internal<KubRegister::RDX, Register::RDX, uint64_t>(), \
ctx.get_reg_internal<KubRegister::R8, Register::R8, uint64_t>(), \
ctx.get_reg_internal<KubRegister::R9, Register::R9, uint64_t>()

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
		std::println ( "[syscall - {}] {:#x} {:#x} {:#x} {:#x}", handler_name_map[syscall_id], SYSCALL_REG_DUMP ( ctx ) );
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

#define ARG1(ctx) ctx.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( )
#define ARG2(ctx) ctx.get_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( )
#define ARG3(ctx) ctx.get_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t> ( )
#define ARG4(ctx) ctx.get_reg_internal<kubera::KubRegister::R9, Register::R9, uint64_t> ( )
#define ARG5(ctx) *(uint64_t*)(ctx.get_virtual_memory ( )->translate ( ctx.get_reg ( Register::RSP, 8 ) + 0x28, PageProtection::READ ) )
#define ARG6(ctx) *(uint64_t*)(ctx.get_virtual_memory ( )->translate ( ctx.get_reg ( Register::RSP, 8 ) + 0x30, PageProtection::READ ) )
#define SET_ARG1(ctx, val) ctx.set_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( val )
#define SET_ARG2(ctx, val) ctx.set_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( val )
#define SET_ARG3(ctx, val) ctx.set_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t> ( val )
#define SET_ARG4(ctx, val) ctx.set_reg_internal<kubera::KubRegister::R9, Register::R9, uint64_t> ( val )
#define SET_ARG5(ctx, val) *(uint64_t*)(ctx.get_virtual_memory ( )->translate ( ctx.get_reg ( Register::RSP, 8 ) + 0x28, PageProtection::READ | PageProtection::WRITE ) ) = val
#define SET_ARG6(ctx, val) *(uint64_t*)(ctx.get_virtual_memory ( )->translate ( ctx.get_reg ( Register::RSP, 8 ) + 0x30, PageProtection::READ | PageProtection::WRITE ) ) = val
#define SET_RETURN(ctx, value) ctx.set_reg_internal<KubRegister::RAX, Register::RAX, uint64_t>( value )

void NtCreateEvent ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	dispatch_syscall<5> ( syscall_id, ctx );
}

void NtManageHotPatch ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	SET_RETURN ( ctx, 0xC00000BBL );
}

void NtQueryVirtualMemory ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	if ( ARG1 ( ctx ) != ~0ULL ) {
		SET_RETURN ( ctx, 0xC00000BBL );
		std::println ( "[syscall - NtQueryVirtualMemory] Attempted on foreign process" );
		return;
	}

	auto info_class = ARG3 ( ctx );
	if ( info_class == 4 || // MemoryWorkingSetExInformation
			 info_class == 14 ) {// MemoryImageExtensionInformation
		SET_RETURN ( ctx, 0xC00000BBL );
		return;
	}

	switch ( info_class ) {
		case 4: // MemoryWorkingSetExInformation
		case 14: // MemoryImageExtensionInformation
		{
			SET_RETURN ( ctx, 0xC00000BBL );
			std::println ( "[syscall - NtQueryVirtualMemory] Unsupported class {:#x}", info_class );
			return;
		}
		case 3: // MemoryBasicInformation
		{
			if ( ARG6 ( ctx ) != 0 ) {
				SET_ARG6 ( ctx, sizeof ( WinMemoryBasicInformation ) );
			}

			if ( ARG5 ( ctx ) < sizeof ( WinMemoryBasicInformation ) ) {
				return SET_RETURN ( ctx, 0xC0000023L );// STATUS_BUFFER_TOO_SMALL
			}

			auto* vm = ctx.get_virtual_memory ( );
			auto mbi = vm->get_memory_basic_information ( ARG2 ( ctx ) );
			auto mbi_addr = vm->translate ( ARG4 ( ctx ), PageProtection::READ | PageProtection::WRITE );
			memcpy ( mbi_addr, &mbi, sizeof ( WinMemoryBasicInformation ) );

			return SET_RETURN ( ctx, 0x0 ); // STATUS_SUCCESS
		}
		case 6:
		{
			if ( ARG6 ( ctx ) != 0 ) {
				SET_ARG6 ( ctx, sizeof ( WinMemoryImageInformation ) );
			}

			if ( ARG5 ( ctx ) < sizeof ( WinMemoryImageInformation ) ) {
				return SET_RETURN ( ctx, 0xC0000023L );// STATUS_BUFFER_TOO_SMALL
			}

			auto mod = process::mm.get_module_by_address ( ARG2 ( ctx ) );
			WinMemoryImageInformation mii { 0 };
			mii.ImageBase = mod.base;
			mii.SizeOfImage = mod.size;
			auto* vm = ctx.get_virtual_memory ( );
			auto mii_addr = vm->translate ( ARG4 ( ctx ), PageProtection::READ | PageProtection::WRITE );
			memcpy ( mii_addr, &mii, sizeof ( WinMemoryImageInformation ) );

			return SET_RETURN ( ctx, 0x0 ); // STATUS_SUCCESS
		}
		default:
			std::println ( "[syscall - NtQueryVirtualMemory] Unsupported class {:#x}", info_class );
			__debugbreak ( );
	}

	ctx.set_reg_internal<KubRegister::RAX, Register::EAX, uint32_t> ( 0xC00000BBL );
}

void NtTerminateProcess ( uint32_t syscall_id, kubera::KUBERA& ctx ) {
	if ( ARG1 ( ctx ) != ~0UL ) {
		SET_RETURN ( ctx, 0xC00000BBL );
		std::println ( "[syscall - NtTerminateProcess] Attempted on foreign process" );
		return;
	}

	std::println ( "[syscall - NtTerminateProcess] Terminating emulation!" );
	__debugbreak ( );
}

void map_syscalls ( ) {
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtCreateEvent" ] ] = NtCreateEvent;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtManageHotPatch" ] ] = NtManageHotPatch;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtQueryVirtualMemory" ] ] = NtQueryVirtualMemory;
	syscall_handlers::handler_map [ syscall_handlers::syscall_map [ "NtTerminateProcess" ] ] = NtTerminateProcess;
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
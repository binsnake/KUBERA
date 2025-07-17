#include "syscalls.hpp"
#include <format>
#include <print>
#include <algorithm>
#include <cctype>
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
			auto* ptr = static_cast< const uint8_t* >( ctx.get_virtual_memory ( )->translate ( addr, kubera::VirtualMemory::READ | kubera::VirtualMemory::EXEC ) );
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
			}
		}
	}
}

void syscall_handlers::dispatcher ( const iced::Instruction& instr, KUBERA& ctx ) {
	const auto syscall_id = ctx.get_reg_internal<KubRegister::RAX, Register::EAX, uint32_t> ( );
	if ( handler_map.contains ( syscall_id ) ) {
		handler_map [ syscall_id ] ( instr, ctx );
	}
}

void syscall_handlers::dispatcher_verbose ( const iced::Instruction& instr, kubera::KUBERA& ctx ) {
	std::string fmt;
	const auto syscall_id = ctx.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( );
	const auto handler_available = handler_map.contains ( syscall_id );
	if ( handler_available && handler_name_map.contains ( syscall_id ) ) {
		std::println ( "[syscall - {:#x}] {:#X} {:#X} {:#X} {:#X}", syscall_id, SYSCALL_REG_DUMP ( ctx ) );
	}

	if ( handler_available ) {
		if ( fmt.empty ( ) ) {
			std::println ( "[syscall - {:#x}] {:#X} {:#X} {:#X} {:#X}", syscall_id, SYSCALL_REG_DUMP ( ctx ) );
		}

		handler_map [ syscall_id ] ( instr, ctx );
		std::println ( "\t\t-> {:#X}", ctx.get_reg_internal<KubRegister::RAX, Register::RAX, uint32_t> ( ) );
	}
	else {
		std::println ( "[syscall - {:#x}] No handler!", syscall_id );
	}
}

template<>
void syscall_handlers::init<true> ( ) {
	( *kubera::instruction_dispatch_table ) [ static_cast< size_t >( Mnemonic::Syscall ) ] = syscall_handlers::dispatcher_verbose;
}

template<>
void syscall_handlers::init<false> ( ) {
	( *kubera::instruction_dispatch_table ) [ static_cast< size_t >( Mnemonic::Syscall ) ] = syscall_handlers::dispatcher;
}
#include <context/KUBERA.hpp>
#include <print>
#include <sstream>
#include <chrono>
#pragma comment(lib, "KUBERA.lib")
#pragma comment(lib, "platform.lib")
#include "wintypes.hpp"
#include "syscalls.hpp"
#include "module_manager.hpp"

#define NOMINMAX
#include <Windows.h>
using namespace kubera;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

void save_cpu_state ( KUBERA& ctx, CONTEXT& context ) {
	if ( ( context.ContextFlags & CONTEXT_DEBUG_REGISTERS ) == CONTEXT_DEBUG_REGISTERS ) {
		context.Dr0 = ctx.get_reg ( Register::DR0 );
		context.Dr1 = ctx.get_reg ( Register::DR1 );
		context.Dr2 = ctx.get_reg ( Register::DR2 );
		context.Dr3 = ctx.get_reg ( Register::DR3 );
		context.Dr6 = ctx.get_reg ( Register::DR6 );
		context.Dr7 = ctx.get_reg ( Register::DR7 );
	}

	if ( ( context.ContextFlags & CONTEXT_CONTROL ) == CONTEXT_CONTROL ) {
		context.SegSs = ctx.get_reg_internal<KubRegister::SS, Register::SS, uint16_t> ( );
		context.SegCs = ctx.get_reg_internal<KubRegister::CS, Register::CS, uint16_t> ( );
		context.Rip = ctx.get_reg ( Register::RIP );
		context.Rsp = ctx.get_reg ( Register::RSP );
		context.EFlags = static_cast< uint32_t >( ctx.get_rflags ( ) );
	}

	if ( ( context.ContextFlags & CONTEXT_INTEGER ) == CONTEXT_INTEGER ) {
		context.Rax = ctx.get_reg ( Register::RAX );
		context.Rbx = ctx.get_reg ( Register::RBX );
		context.Rcx = ctx.get_reg ( Register::RCX );
		context.Rdx = ctx.get_reg ( Register::RDX );
		context.Rbp = ctx.get_reg ( Register::RBP );
		context.Rsi = ctx.get_reg ( Register::RSI );
		context.Rdi = ctx.get_reg ( Register::RDI );
		context.R8 = ctx.get_reg ( Register::R8 );
		context.R9 = ctx.get_reg ( Register::R9 );
		context.R10 = ctx.get_reg ( Register::R10 );
		context.R11 = ctx.get_reg ( Register::R11 );
		context.R12 = ctx.get_reg ( Register::R12 );
		context.R13 = ctx.get_reg ( Register::R13 );
		context.R14 = ctx.get_reg ( Register::R14 );
		context.R15 = ctx.get_reg ( Register::R15 );
	}

	if ( ( context.ContextFlags & CONTEXT_SEGMENTS ) == CONTEXT_SEGMENTS ) {
		context.SegDs = ctx.get_reg_internal<KubRegister::DS, Register::DS, uint16_t> ( );
		context.SegEs = ctx.get_reg_internal<KubRegister::ES, Register::ES, uint16_t> ( );
		context.SegFs = ctx.get_reg_internal<KubRegister::FS, Register::FS, uint16_t> ( );
		context.SegGs = ctx.get_reg_internal<KubRegister::GS, Register::GS, uint16_t> ( );
	}

	if ( ( context.ContextFlags & CONTEXT_FLOATING_POINT ) == CONTEXT_FLOATING_POINT ) {
		auto& fpu = ctx.get_fpu ( );
		context.FltSave.ControlWord = fpu.fpu_control_word.value;
		context.FltSave.StatusWord = fpu.fpu_status_word.value;
		context.FltSave.TagWord = static_cast< BYTE >( fpu.fpu_tag_word.value );
		for ( int i = 0; i < 8; i++ ) {

		}
	}

	if ( ( context.ContextFlags & CONTEXT_INTEGER ) == CONTEXT_INTEGER ) {
		context.MxCsr = ctx.get_mxcsr ( ).value;
		for ( int i = 0; i < 16; i++ ) {

		}
	}
}

void setup_context ( KUBERA& ctx, uint64_t start_address ) {
	syscall_handlers::init<true> ( );
	ctx.set_reg_internal<KubRegister::CS, Register::CS> ( windows::code_segment );
	ctx.set_reg_internal<KubRegister::DS, Register::DS> ( windows::data_segment );
	ctx.set_reg_internal<KubRegister::ES, Register::ES> ( windows::e_segment );
	ctx.set_reg_internal<KubRegister::FS, Register::FS> ( windows::file_segment );
	ctx.set_reg_internal<KubRegister::SS, Register::SS> ( windows::segment_selector );
	ctx.set_reg_internal<KubRegister::GS, Register::GS> ( windows::g_segment );
	ctx.set_rflags ( windows::rflags.value );
	ctx.get_mxcsr ( ) = windows::mxcsr;
	auto& fpu = ctx.get_fpu ( );
	fpu.fpu_status_word = windows::fpu_status_word;
	fpu.fpu_control_word = windows::fpu_control_word;

	CONTEXT winctx {};
	winctx.ContextFlags = CONTEXT_ALL;

	ctx.unalign_stack ( );
	save_cpu_state ( ctx, winctx );

	winctx.Rip = windows::rtl_user_thread_start;
	winctx.Rcx = start_address;
	winctx.Rdx = 0;

	CONTEXT* winctx_stack = ctx.allocate_on_stack<CONTEXT> ( );
	memcpy ( ctx.get_virtual_memory ( )->translate ( reinterpret_cast< uint64_t >( winctx_stack ), VirtualMemory::READ ), &winctx, sizeof ( CONTEXT ) );
	ctx.unalign_stack ( );

	ctx.rip ( ) = windows::ldr_initialize_thunk;
	ctx.set_reg ( Register::RCX, reinterpret_cast< uint64_t >( winctx_stack ), 8 );
	ctx.set_reg ( Register::RDX, reinterpret_cast< uint64_t >( windows::ntdll ), 8 );
}

int main ( ) {
	KUBERA ctx { };
	ModuleManager mm { ctx.get_virtual_memory ( ) };

	windows::emu_module = reinterpret_cast< void* >( mm.load_module ( "D:\\binsnake\\kubera\\emu.exe" ) );
	windows::ntdll = reinterpret_cast< void* >( mm.load_module ( "C:\\Windows\\System32\\ntdll.dll" ) );
	windows::win32u = reinterpret_cast< void* >( mm.load_module ( "C:\\Windows\\System32\\win32u.dll" ) );

	windows::ldr_initialize_thunk =
		mm.get_export_address_public ( "C:\\Windows\\System32\\ntdll.dll", "LdrInitializeThunk" );

	windows::rtl_user_thread_start =
		mm.get_export_address_public ( "C:\\Windows\\System32\\ntdll.dll", "RtlUserThreadStart" );

	windows::ki_user_apc_dispatcher =
		mm.get_export_address_public ( "C:\\Windows\\System32\\ntdll.dll", "KiUserApcDispatcher" );

	windows::ki_user_exception_dispatcher =
		mm.get_export_address_public ( "C:\\Windows\\System32\\ntdll.dll", "KiUserExceptionDispatcher" );

	syscall_handlers::build_syscall_map ( ctx, mm );
	windows::setup_fake_peb ( ctx, reinterpret_cast< uint64_t >( windows::ntdll ) );

	char buf [ 128 ] { 0 };

	GetCurrentDirectoryA ( sizeof ( buf ), buf );
	std::println ( "{}", buf );
	setup_context ( ctx, mm.get_entry_point ( "D:\\binsnake\\kubera\\emu.exe" ) );

	std::println ( "ntdll base: {:#x}", ( uint64_t ) windows::emu_module );
	auto vm = ctx.get_virtual_memory ( );
	std::println ( "ntdll base real: {:#x}", ( uint64_t ) vm->translate ( ( uint64_t ) windows::emu_module, VirtualMemory::READ ) );
	while ( true ) {
		auto real_instruction_rip = ( uint64_t ) vm->translate ( ctx.rip ( ), VirtualMemory::READ );
		auto& instr = ctx.emulate ( );
		std::println ( "[{:#x} - {:#x}] {}", instr.ip, real_instruction_rip, instr.to_string ( ) );
		if ( !instr.valid ( ) ) {
			break;
		}
	}

	std::println ( "Emulation finished!" );
	std::getchar ( );
}
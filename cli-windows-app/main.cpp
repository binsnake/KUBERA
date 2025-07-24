#include <context/KUBERA.hpp>
#include <print>
#include <sstream>
#include <chrono>
#pragma comment(lib, "KUBERA.lib")
#pragma comment(lib, "platform.lib")
#include "wintypes.hpp"
#include "syscalls.hpp"
#include "module_manager.hpp"
#include "process.hpp"
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
		context.SegSs = windows::stack_segment;
		context.SegCs = windows::code_segment;
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
		context.SegDs = windows::data_segment;
		context.SegEs = windows::extra_segment;
		context.SegFs = windows::file_segment;
		context.SegGs = windows::g_segment;
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
	auto* vm = ctx.get_virtual_memory ( );
	auto gs = vm->alloc_at ( 0x30000, 0x1000, PageProtection::READ | PageProtection::WRITE );

	ctx.set_reg_internal<KubRegister::ES, Register::ES, uint64_t> ( 0 );
	ctx.set_reg_internal<KubRegister::CS, Register::CS, uint64_t> ( 0 );
	ctx.set_reg_internal<KubRegister::SS, Register::SS, uint64_t> ( 0 );
	ctx.set_reg_internal<KubRegister::DS, Register::DS, uint64_t> ( 0 );
	ctx.set_reg_internal<KubRegister::FS, Register::FS, uint64_t> ( 0 );
	ctx.set_reg_internal<KubRegister::GS, Register::GS, uint64_t> ( windows::teb_address );

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
	memcpy ( ctx.get_virtual_memory ( )->translate ( reinterpret_cast< uint64_t >( winctx_stack ), PageProtection::READ ), &winctx, sizeof ( CONTEXT ) );
	ctx.unalign_stack ( );

	ctx.rip ( ) = windows::ldr_initialize_thunk;
	ctx.set_reg ( Register::RCX, reinterpret_cast< uint64_t >( winctx_stack ), 8 );
	ctx.set_reg ( Register::RDX, reinterpret_cast< uint64_t >( windows::ntdll ), 8 );
}

int main ( ) {
	using namespace process;
	windows::emu_module = reinterpret_cast< void* >( mm.load_module ( "D:\\binsnake\\kubera\\emu.exe", 0x00007FFF50000000 ) );
	windows::ntdll = reinterpret_cast< void* >( mm.load_module ( "C:\\Windows\\System32\\ntdll.dll", 0x00007FFFFF000000 ) );
	//windows::win32u = reinterpret_cast< void* >( mm.load_module ( "C:\\Windows\\System32\\win32u.dll", 0x00007FFFFD000000 ) );

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
	windows::setup_fake_teb ( ctx );
	windows::setup_user_shared_data ( ctx );

	char buf [ 128 ] { 0 };

	GetCurrentDirectoryA ( sizeof ( buf ), buf );
	std::println ( "{}", buf );
	setup_context ( ctx, mm.get_entry_point ( "D:\\binsnake\\kubera\\emu.exe" ) );

	std::println ( "ntdll base: {:#x}", ( uint64_t ) windows::emu_module );
	auto vm = ctx.get_virtual_memory ( );
	std::println ( "ntdll base real: {:#x}", ( uint64_t ) vm->translate ( ( uint64_t ) windows::emu_module, PageProtection::READ ) );

	auto print_changes = [ ] ( const std::vector<std::string>& changes )
	{
		if ( changes.empty ( ) ) {
			return;
		}
		for ( const auto& change : changes ) {
			std::print ( "{} ", change );
		}
		std::println ( "" );
	};
	while ( true ) {
		auto real_instruction_rip = ( uint64_t ) vm->translate ( ctx.rip ( ), PageProtection::READ );
		auto old_regs = ctx.register_dump ( );
		auto old_flags = ctx.rflags_dump ( );
		auto old_mxcsr = ctx.mxcsr_dump ( );
		auto& instr = ctx.emulate ( );
		std::println ( "[{:#x} - {:#x}] {}", instr.ip, real_instruction_rip, instr.to_string ( ) );
		print_changes ( ctx.get_register_changes ( old_regs ) );
		print_changes ( ctx.get_rflags_changes ( old_flags ) );
		print_changes ( ctx.get_mxcsr_changes ( old_mxcsr ) );
		if ( !instr.valid ( ) ) {
			break;
		}
	}

	std::println ( "Emulation finished!" );
	std::getchar ( );
}
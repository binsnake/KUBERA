/*
 * Minimal KUBERA implementation for emulating a Windows DLL.
 * Configures emulator, executes at AddressOfEntryPoint, handles CRT, exceptions,
 * and logs execution time with optional verbose logging.
 */

#include <semantics/src/pch.hpp>
#include <shared/types.hpp>
#include <shared/context.hpp>
#include <shared/capstone++.hpp>
#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <print>
#include <thread>
#include <unordered_map>

#include "sig.hpp"
#include <Psapi.h>
DWORD get_dll_size ( HMODULE module ) {
	MODULEINFO info;
	if ( GetModuleInformation ( GetCurrentProcess ( ), module, &info, sizeof ( info ) ) ) {
		return info.SizeOfImage;
	}
	return 0;
}

/* Load module (DLL or EXE) */
static bool load_module ( const std::string& file_path, HMODULE& module, uint64_t& loaded_base, uint64_t& module_size ) {
	HANDLE hFile = CreateFileA ( file_path.c_str ( ), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE ) {
		std::print ( "Failed to open file: {}\n", GetLastError ( ) );
		return false;
	}

	HANDLE hMap = CreateFileMappingA ( hFile, nullptr, PAGE_READONLY, 0, 0x1000, nullptr );
	if ( !hMap ) {
		CloseHandle ( hFile );
		std::print ( "Failed to create mapping: {}\n", GetLastError ( ) );
		return false;
	}

	auto base = MapViewOfFile ( hMap, FILE_MAP_READ, 0, 0, 0x1000 );
	CloseHandle ( hMap );
	CloseHandle ( hFile );
	if ( !base ) {
		std::print ( "Failed to view headers: {}\n", GetLastError ( ) );
		return false;
	}

	auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( base );
	auto nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( ( uint8_t* ) base + dos->e_lfanew );
	bool isDll = ( nt->FileHeader.Characteristics & IMAGE_FILE_DLL ) != 0;
	UnmapViewOfFile ( base );

	if ( isDll ) {
		module = LoadLibraryExA ( file_path.c_str ( ), nullptr, DONT_RESOLVE_DLL_REFERENCES );
		if ( !module ) {
			std::print ( "DLL LoadLibraryExA failed: {}\n", GetLastError ( ) );
			return false;
		}
		loaded_base = reinterpret_cast< uint64_t >( module );
		module_size = parser ? parser->pe_info_.optional_header.size_of_image : 0x100000;
	}
	else {
		HANDLE f = CreateFileA ( file_path.c_str ( ), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
		if ( f == INVALID_HANDLE_VALUE ) return false;
		HANDLE m = CreateFileMappingA ( f, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr );
		CloseHandle ( f );
		if ( !m ) return false;
		auto fullBase = MapViewOfFile ( m, FILE_MAP_READ, 0, 0, 0 );
		CloseHandle ( m );
		if ( !fullBase ) return false;
		auto dos2 = reinterpret_cast< IMAGE_DOS_HEADER* >( fullBase );
		auto nt2 = reinterpret_cast< IMAGE_NT_HEADERS64* >( ( uint8_t* ) fullBase + dos2->e_lfanew );

		module = reinterpret_cast< HMODULE >( fullBase );
		loaded_base = reinterpret_cast< uint64_t >( fullBase );
		module_size = nt2->OptionalHeader.SizeOfImage;
	}

	auto new_parser = std::make_unique<PE::Parser> ( loaded_base );
	if ( parser ) parser.swap ( new_parser );
	else parser = std::move ( new_parser );

	std::print ( "Module loaded at {:016x}h, size: {:x}h\n", loaded_base, module_size );
	return true;
}

/* Initialize emulator state */
static void initialize_state ( EmulationContext& state, HMODULE module, uint64_t loaded_base, uint64_t module_size ) {
	state.decoder.emplace_back ( new capstone::Decoder ( ( uint8_t* ) module, module_size, loaded_base ) );
	state.decoder.back ( )->set_ip ( loaded_base + parser->pe_info_.optional_header.address_of_entry_point );
	//InstructionEffect effect { };
	//CONTEXT ctx { 0 };
	//state.save_context ( &ctx );
	//
	//ctx.Rip = state.windows->ldr_initialize_thunk;
	//ctx.Rcx = parser->get_entry_point ( );
	//ctx.Rdx = 0; // arg
	//PE::Parser ntdll_parser ( state.windows->ntdll_base );
	//
	//state.decoder.emplace_back ( new capstone::Decoder ( ( uint8_t* ) state.windows->ntdll_base, ntdll_parser.pe_info_.optional_header.size_of_image, state.windows->ntdll_base ) );
	//state.decoder.back ( )->set_ip ( state.windows->ldr_initialize_thunk );
	//
	//state.allocate_stack ( sizeof ( CONTEXT ), effect );
	//auto base = state.get_reg<uint64_t> ( X86_REG_RSP );
	//for ( auto i = sizeof(CONTEXT); i != 0; i -= 8 ) {
	//	state.set_stack ( base + i, *reinterpret_cast< uint64_t* > ( reinterpret_cast< uint8_t* > ( &ctx ) + i ), effect, 8 );
	//}

	state.windows->loaded_module = module;
	state.windows->loaded_base_address = loaded_base;
	state.windows->loaded_module_size = module_size;
}

#define SET_KERNEL_MODULE(x) multihook(#x, handlers::winapi::x)
void init_hooks ( EmulationContext& state ) {
	auto kernel32 = GetModuleHandleA ( "kernel32.dll" );
	auto kernelbase = GetModuleHandleA ( "kernelbase.dll" );

	if ( !kernel32 || !kernelbase ) {
		return;
	}

	const auto multihook = [ & ] ( const std::string& name, APIHandler handler )
	{
		auto [first, last] = state.windows->import_multi_map.equal_range ( name );
		size_t set = 0u;
		for ( auto it = first; it != last; ++it ) {
			state.windows->api_hooks.insert ( { it->second, handler } );
			std::print ( "{:x} ", it->second );
			++set;
		}

		auto ntdll_stub = ( uint64_t ) GetProcAddress ( reinterpret_cast< HMODULE >( state.windows->ntdll_base ), name.c_str ( ) );
		if ( ntdll_stub ) {
			state.windows->api_hooks.insert ( { ntdll_stub, handler } );
			std::print ( "{:x} ", ntdll_stub );
			++set;
		}

		auto kb_stub = ( uint64_t ) GetProcAddress ( kernelbase, name.c_str ( ) );
		if ( kb_stub ) {
			state.windows->api_hooks.insert ( { kb_stub, handler } );
			std::print ( "{:x} ", kb_stub );
			++set;
		}

		std::println ( "[{}] Hooked {} times across API", name, set );
	};

	//SET_KERNEL_MODULE ( GetProcAddress );
	//SET_KERNEL_MODULE ( LoadLibraryA );
	//SET_KERNEL_MODULE ( LoadLibraryW );
	//SET_KERNEL_MODULE ( LoadLibraryExA );
	//SET_KERNEL_MODULE ( LoadLibraryExW );
	////SET_KERNEL_MODULE ( InitializeCriticalSectionAndSpinCount );
	////SET_KERNEL_MODULE ( InitializeCriticalSectionEx );
	//SET_KERNEL_MODULE ( RtlInitializeCriticalSectionEx );
	//SET_KERNEL_MODULE ( RtlInitializeCriticalSectionAndSpinCount );
	//SET_KERNEL_MODULE ( RtlEnterCriticalSection );
	//SET_KERNEL_MODULE ( RtlLeaveCriticalSection );
	//SET_KERNEL_MODULE ( RtlDeleteCriticalSection );
	////SET_KERNEL_MODULE ( InitializeSListHead );
	//SET_KERNEL_MODULE ( FlsAlloc );
	//SET_KERNEL_MODULE ( FlsGetValue );
	//SET_KERNEL_MODULE ( FlsSetValue );
	//SET_KERNEL_MODULE ( FlsFree );
	//SET_KERNEL_MODULE ( TlsAlloc );
	//SET_KERNEL_MODULE ( TlsGetValue );
	//SET_KERNEL_MODULE ( TlsSetValue );
	//SET_KERNEL_MODULE ( TlsFree );
	//
	//SET_KERNEL_MODULE ( VirtualProtect );
	////SET_KERNEL_MODULE ( IsProcessorFeaturePresent );
	//SET_KERNEL_MODULE ( GetLastError );

	std::println ( "Applied {} API hooks!", state.windows->api_hooks.size ( ) );
}

std::string format_rva ( EmulationContext& state, uint64_t ip ) {
	for ( const auto& [base, module] : state.windows->loaded_modules ) {
		if ( ip >= base && ip < base + module.size ) {
			return std::format ( "{:#x}", ip - base + 0x180000000 );
		}
	}
	return std::format ( "{:#x}", ip );
}

/* Main emulation loop */
void run ( ) {
	std::string file_path = "maddi.dll";
	HMODULE module;
	uint64_t loaded_base, module_size;
	if ( !load_module ( file_path, module, loaded_base, module_size ) ) return;

	EmulationContext state;
	init_hooks ( state );
	initialize_state ( state, module, loaded_base, module_size );
	state.windows->add_module ( module, loaded_base, module_size, ( uint8_t* ) module );

	//state.decoder.emplace_back ( new capstone::Decoder ( ( uint8_t* ) module, module_size, loaded_base ) );
	state.options.enable_logging = true;

	auto execute_to_return = [ & ] ( InstructionEffect& effect )
	{
		while ( state.decoder.back ( )->can_decode ( ) ) {
			capstone::Instruction instr = state.decoder.back ( )->decode ( );
			state.set_reg ( X86_REG_RIP, instr.ip ( ) + instr.length ( ), 8, effect );

			GuestExceptionInfo current_exception;
			bool run_handler = true;
			bool handler_executed_cleanly = false;

			if ( !instr.is_valid ( ) ) {
				current_exception.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
				run_handler = false;
			}
			else {
				const InstructionExceptionInfo& baseInfo = g_instruction_exception_table [ instr.mnemonic ( ) ];
				PreCheckInfo check_info;
				populate_pre_check_info ( check_info, state, instr, baseInfo );
				current_exception = check_instruction_exceptions ( state, instr, check_info );
				if ( current_exception.exception_occurred ) run_handler = false;
			}

			if ( run_handler ) {
				effect = state.log_effect ( instr );
				effect.instr_str = instr.to_string ( );
				try {
					auto it = instruction_handlers.find ( static_cast< x86_insn >( instr.mnemonic ( ) ) );
					if ( it != instruction_handlers.end ( ) && *it->second ) {
						( *it->second )( instr, state, effect );
						handler_executed_cleanly = true;
					}
					else {
						current_exception.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
						run_handler = false;
					}
				}
				catch ( const GuestExceptionInfo& handler_ex ) {
					current_exception = handler_ex;
					run_handler = false;
					return false;
				}
				catch ( const std::exception& handler_host_ex ) {
					UNREFERENCED_PARAMETER ( handler_host_ex );
					current_exception.set_access_violation ( instr.ip ( ), 0, false );
					run_handler = false;
					return false;
				}
			}

			if ( run_handler && handler_executed_cleanly && !current_exception.exception_occurred ) {
				const InstructionExceptionInfo& baseInfo = g_instruction_exception_table [ instr.mnemonic ( ) ];
				uint8_t op_size = instr.operand_count ( ) > 0 ? instr.operands ( ) [ 0 ].size : 8;
				if ( baseInfo.categories.ARITHMETIC ) {
					std::println ( "Checking post-execution arithmetic for {}", instr.to_string ( ) );
					GuestExceptionInfo arith_ex = check_post_execution_arithmetic ( state, baseInfo, instr.ip ( ), op_size );
					if ( arith_ex.exception_occurred ) {
						std::println ( "Arithmetic exception: Code=0x{:X}, VA=0x{:016x}", arith_ex.ExceptionCode, arith_ex.FaultingVa );
						current_exception = arith_ex;
					}
				}
				if ( !current_exception.exception_occurred && baseInfo.categories.FPU_SIMD ) {
					std::println ( "Checking post-execution FPU/SIMD for {}", instr.to_string ( ) );
					GuestExceptionInfo fp_simd_ex = check_post_execution_fpu_simd ( state, baseInfo, instr.ip ( ) );
					if ( fp_simd_ex.exception_occurred ) {
						std::println ( "FPU/SIMD exception: Code=0x{:X}, VA=0x{:016x}", fp_simd_ex.ExceptionCode, fp_simd_ex.FaultingVa );
						current_exception = fp_simd_ex;
					}
				}
			}

			if ( current_exception.exception_occurred ) {
				std::println ( "Dispatching exception: Code=0x{:X}, IP=0x{:016x}, VA=0x{:016x}",
										 current_exception.ExceptionCode, current_exception.ExceptionAddress, current_exception.FaultingVa );
				setup_guest_exception_dispatch ( state, current_exception );
				std::println ( "Exception dispatch completed for IP=0x{:016x}", current_exception.ExceptionAddress );
				if ( state.exit_due_to_critical_error ) break;
				continue;
			}

			if ( run_handler && handler_executed_cleanly ) {
				state.increment_tsc ( );
				effect.normalize_registers ( &state );
				if ( instr.is_return ( ) && state.call_stack.empty ( ) ) break;
			}

			if ( state.exit_due_to_critical_error ) break;
		}
		return true;
	};

	InstructionEffect effect;

	// Handle TLS callbacks
	auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( loaded_base );
	auto nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( loaded_base + dos->e_lfanew );
	auto& opt = nt->OptionalHeader;
	if ( opt.DataDirectory [ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress ) {
		auto tls = reinterpret_cast< IMAGE_TLS_DIRECTORY64* >( loaded_base + opt.DataDirectory [ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress );
		auto cbArray = reinterpret_cast< PIMAGE_TLS_CALLBACK* >( tls->AddressOfCallBacks );
		for ( size_t i = 0; cbArray [ i ]; ++i ) {
			state.set_reg ( X86_REG_RCX, loaded_base, 8, effect );
			state.set_reg ( X86_REG_RDX, DLL_PROCESS_ATTACH, 8, effect );
			state.set_reg ( X86_REG_R8, 0ULL, 8, effect );
			state.decoder.back ( )->set_ip ( reinterpret_cast< uint64_t >( cbArray [ i ] ) );
			execute_to_return ( effect );
		}
	}

	// Handle static TLS data
	{
		auto ntdll = reinterpret_cast< std::uint8_t* >( GetModuleHandleA ( "ntdll.dll" ) );
		size_t ntdll_size = get_dll_size ( ( HMODULE ) ntdll );
		auto ntdll_end = ntdll + ntdll_size;
		std::uint8_t* ldrp_handle_tls_data = byte_scanner<"4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9">.search ( ntdll, ntdll_end );
		if ( !ldrp_handle_tls_data ) {
			ldrp_handle_tls_data = byte_scanner<"48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 54 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B C1">.search ( ntdll, ntdll_end );
		}
		char fake_ldr [ 0x130 ] { 0 };
		*( uint64_t* ) ( fake_ldr + 0x30 ) = loaded_base;
		//reinterpret_cast< void( * )( void* ) >( ldrp_handle_tls_data )( fake_ldr );
		state.set_reg ( X86_REG_RCX, reinterpret_cast< uint64_t >( fake_ldr ), 8, effect );
		state.set_reg ( X86_REG_RDX, 0ULL, 8, effect );
		state.decoder.emplace_back ( new capstone::Decoder ( ntdll, ntdll_size, ( uint64_t ) ntdll ) );

		state.push_call_frame ( 0xDEADBEEFDEADBEEF, effect );
		state.decoder.back ( )->set_ip ( ( uint64_t ) ldrp_handle_tls_data );
		if ( !execute_to_return ( effect ) ) {
			__debugbreak ( );
		}

		state.decoder.pop_back ( );
		state.decoder.pop_back ( );
	}
	// Resume at CRT entrypoint
	state.decoder.back ( )->set_ip ( loaded_base + 0x1E000 );
	state.options.enable_logging = true;

	state.set_reg ( X86_REG_R8, 0ULL, 8, effect );
	state.set_reg ( X86_REG_RDX, 1ULL, 8, effect );
	state.set_reg ( X86_REG_RCX, loaded_base, 8, effect );
	state.set_reg ( X86_REG_RSI, state.decoder.back ( )->ip ( ), 8, effect );
	state.set_reg ( X86_REG_RBX, state.get_reg<uint64_t> ( X86_REG_RSP ), 8, effect );

	auto rsp = state.get_reg<uint64_t> ( X86_REG_RSP );
	state.set_reg ( X86_REG_RSP, ( rsp & ~0xFFFFULL ) | ( ( rsp & 0xFFFF ) & 0xFF00 ), 8, effect );


	std::unordered_map<uint64_t, int> visit_count;
	const int max_loop_iterations = 1000;
	bool dllmain_phase = false;
	constexpr uint64_t dllMainRVA = 0x1000;
	constexpr uint64_t fake_ret_addr_value = 0xDEADBEEFBAADF00DULL;
	int instruction_count = 0;

	std::println ( "Starting execution at 0x{:016x}", state.decoder.back ( )->ip ( ) );
	auto start = std::chrono::high_resolution_clock::now ( );
	size_t control_ins = 0;
	bool run_handler = true;

	while ( state.decoder.back ( )->can_decode ( ) ) {
		uint64_t ip_before_decode = state.decoder.back ( )->ip ( );
		capstone::Instruction instr = state.decoder.back ( )->decode ( );
		state.set_reg ( X86_REG_RIP, instr.ip ( ) + instr.length ( ), 8, effect );

		GuestExceptionInfo current_exception;
		bool handler_executed_cleanly = false;
		std::println ( "[{}]{} ({}) {}", state.call_stack.size ( ), std::format ( "{:>{}}", "", state.call_stack.size ( ) ),
						 format_rva ( state, instr.ip ( ) ), instr.to_string ( ) );

		if ( !instr.is_valid ( ) ) {
			std::println ( "0x{:016x}: Invalid instruction, stopping.", ip_before_decode );
			current_exception.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, ip_before_decode );
			run_handler = false;
		}
		else {
			instruction_count++;
			visit_count [ instr.ip ( ) ]++;
			const InstructionExceptionInfo& baseInfo = g_instruction_exception_table [ instr.mnemonic ( ) ];
			PreCheckInfo check_info;
			populate_pre_check_info ( check_info, state, instr, baseInfo );
			current_exception = check_instruction_exceptions ( state, instr, check_info );
			if ( current_exception.exception_occurred ) {
				std::println ( "Pre-execution Exception: Code=0x{:X} @ IP=0x{:016x}, VA=0x{:016x}",
										 current_exception.ExceptionCode, current_exception.ExceptionAddress, current_exception.FaultingVa );
				run_handler = false;
			}
		}

		if ( run_handler ) {
			effect = state.log_effect ( instr );
			effect.instr_str = instr.to_string ( );
			try {
				auto it = instruction_handlers.find ( static_cast< x86_insn >( instr.mnemonic ( ) ) );
				if ( it != instruction_handlers.end ( ) && *it->second ) {
					( *it->second )( instr, state, effect );
					handler_executed_cleanly = true;
				}
				else {
					std::println ( "Emulator Error: Unhandled mnemonic: {}", instr.to_string ( ) );
					current_exception.set_exception ( EXCEPTION_ILLEGAL_INSTRUCTION, instr.ip ( ) );
					run_handler = false;
				}
			}
			catch ( const GuestExceptionInfo& handler_ex ) {
				std::println ( "Handler Guest Exception: Code=0x{:X} @ IP=0x{:016x}, VA=0x{:016x}",
										 handler_ex.ExceptionCode, handler_ex.ExceptionAddress, handler_ex.FaultingVa );
				state.dump_state ( );
				current_exception = handler_ex;
				run_handler = false;
				break;
			}
			catch ( const std::exception& handler_host_ex ) {
				std::println ( "Host Exception: {}", handler_host_ex.what ( ) );
				current_exception.set_access_violation ( instr.ip ( ), 0, false );
				run_handler = false;
				break;
			}
		}

		if ( run_handler && handler_executed_cleanly && !current_exception.exception_occurred ) {
			const InstructionExceptionInfo& baseInfo = g_instruction_exception_table [ instr.mnemonic ( ) ];
			uint8_t op_size = instr.operand_count ( ) > 0 ? instr.operands ( ) [ 0 ].size : 8;
			if ( baseInfo.categories.ARITHMETIC ) {
				std::println ( "Checking post-execution arithmetic for {}", instr.to_string ( ) );
				GuestExceptionInfo arith_ex = check_post_execution_arithmetic ( state, baseInfo, instr.ip ( ), op_size );
				if ( arith_ex.exception_occurred ) {
					std::println ( "Arithmetic exception: Code=0x{:X}, VA=0x{:016x}", arith_ex.ExceptionCode, arith_ex.FaultingVa );
					current_exception = arith_ex;
				}
			}
			if ( !current_exception.exception_occurred && baseInfo.categories.FPU_SIMD ) {
				std::println ( "Checking post-execution FPU/SIMD for {}", instr.to_string ( ) );
				GuestExceptionInfo fp_simd_ex = check_post_execution_fpu_simd ( state, baseInfo, instr.ip ( ) );
				if ( fp_simd_ex.exception_occurred ) {
					std::println ( "FPU/SIMD exception: Code=0x{:X}, VA=0x{:016x}", fp_simd_ex.ExceptionCode, fp_simd_ex.FaultingVa );
					current_exception = fp_simd_ex;
				}
			}
			if ( current_exception.exception_occurred ) {
				std::println ( "Post-execution Exception: Code=0x{:X} @ IP=0x{:016x}, VA=0x{:016x}",
										 current_exception.ExceptionCode, current_exception.ExceptionAddress, current_exception.FaultingVa );
			}
		}

		if ( current_exception.exception_occurred ) {
			std::println ( "Dispatching exception: Code=0x{:X}, IP=0x{:016x}, VA=0x{:016x}",
									 current_exception.ExceptionCode, current_exception.ExceptionAddress, current_exception.FaultingVa );
			setup_guest_exception_dispatch ( state, current_exception );
			std::println ( "Exception dispatch completed for IP=0x{:016x}", current_exception.ExceptionAddress );
			if ( state.exit_due_to_critical_error ) {
				std::println ( "Stopping due to critical error." );
				break;
			}
			continue;
		}

		if ( run_handler && handler_executed_cleanly ) {
			state.increment_tsc ( );
			if ( state.options.enable_logging ) {

				if ( !effect.changes.empty ( ) ) {
					for ( const auto& change : effect.changes ) {
						std::print ( "{} ", change );
					}
					std::print ( "\n" );
				}

			}
			effect.normalize_registers ( &state );

			if ( instr.is_return ( ) && state.call_stack.empty ( ) ) {
				state.set_reg ( X86_REG_RSP, state.get_reg<uint64_t> ( X86_REG_RBX ), 8, effect );

				std::println ( "DllMain finished; stopping trace at 0x{:016x}", instr.ip ( ) );
				break;
			}
			if ( state.options.exit_on_infinite_loop ) {
				if ( visit_count [ instr.ip ( ) ] >= max_loop_iterations &&
						instr.is_jump ( ) &&
						instr.branch_target ( ) <= instr.ip ( ) ) {
					std::println ( "Max loop iterations ({}) reached for backwards jump at 0x{:016x}, stopping.", max_loop_iterations, instr.ip ( ) );
					break;
				}
			}
		}

		if ( state.exit_due_to_critical_error ) {
			std::println ( "Emulation stopping due to critical error flag." );
			break;
		}
		++control_ins;
	}

	auto end = std::chrono::high_resolution_clock::now ( );
	auto end_us = std::chrono::duration_cast< std::chrono::nanoseconds >( end - start ).count ( );
	auto end_ms = std::chrono::duration_cast< std::chrono::milliseconds >( end - start ).count ( );

	std::println ( "Trace completed with {} instructions executed.", instruction_count );
	std::println ( "[+] Ran {} instructions in {} ns ({}ms)", control_ins, end_us, end_ms );
	std::println ( "[+] Throughput: {} instructions / second", control_ins / ( static_cast< float >( end_ms ) / 1000.f ) );
}


int main ( ) {
	run ( );
	std::cin.get ( );
}
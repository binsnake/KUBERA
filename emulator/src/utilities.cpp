#include "pch.hpp"

uint64_t EmulationContext::translate_reg ( x86_reg reg, uint64_t value, uint8_t op_size ) const noexcept {
	// Map sub-registers to their 64-bit parent and extract the right bits
	switch ( reg ) {
		// RAX family
		case X86_REG_RAX: return value;
		case X86_REG_EAX: return value & 0xFFFFFFFF;
		case X86_REG_AX:  return value & 0xFFFF;
		case X86_REG_AH:  return ( value >> 8 ) & 0xFF;
		case X86_REG_AL:  return value & 0xFF;

			// RBX family
		case X86_REG_RBX: return value;
		case X86_REG_EBX: return value & 0xFFFFFFFF;
		case X86_REG_BX:  return value & 0xFFFF;
		case X86_REG_BH:  return ( value >> 8 ) & 0xFF;
		case X86_REG_BL:  return value & 0xFF;

			// RCX family
		case X86_REG_RCX: return value;
		case X86_REG_ECX: return value & 0xFFFFFFFF;
		case X86_REG_CX:  return value & 0xFFFF;
		case X86_REG_CH:  return ( value >> 8 ) & 0xFF;
		case X86_REG_CL:  return value & 0xFF;

			// RDX family
		case X86_REG_RDX: return value;
		case X86_REG_EDX: return value & 0xFFFFFFFF;
		case X86_REG_DX:  return value & 0xFFFF;
		case X86_REG_DH:  return ( value >> 8 ) & 0xFF;
		case X86_REG_DL:  return value & 0xFF;

			// RSI family
		case X86_REG_RSI: return value;
		case X86_REG_ESI: return value & 0xFFFFFFFF;
		case X86_REG_SI:  return value & 0xFFFF;
		case X86_REG_SIL: return value & 0xFF;

			// RDI family
		case X86_REG_RDI: return value;
		case X86_REG_EDI: return value & 0xFFFFFFFF;
		case X86_REG_DI:  return value & 0xFFFF;
		case X86_REG_DIL: return value & 0xFF;

			// RBP family
		case X86_REG_RBP: return value;
		case X86_REG_EBP: return value & 0xFFFFFFFF;
		case X86_REG_BP:  return value & 0xFFFF;
		case X86_REG_BPL: return value & 0xFF;

			// RSP family
		case X86_REG_RSP: return value;
		case X86_REG_ESP: return value & 0xFFFFFFFF;
		case X86_REG_SP:  return value & 0xFFFF;
		case X86_REG_SPL: return value & 0xFF;

			// R8-R15 (64-bit and their sub-registers)
		case X86_REG_R8:  return value;
		case X86_REG_R8D: return value & 0xFFFFFFFF;
		case X86_REG_R8W: return value & 0xFFFF;
		case X86_REG_R8B: return value & 0xFF;

		case X86_REG_R9:  return value;
		case X86_REG_R9D: return value & 0xFFFFFFFF;
		case X86_REG_R9W: return value & 0xFFFF;
		case X86_REG_R9B: return value & 0xFF;

		case X86_REG_R10:  return value;
		case X86_REG_R10D: return value & 0xFFFFFFFF;
		case X86_REG_R10W: return value & 0xFFFF;
		case X86_REG_R10B: return value & 0xFF;

		case X86_REG_R11:  return value;
		case X86_REG_R11D: return value & 0xFFFFFFFF;
		case X86_REG_R11W: return value & 0xFFFF;
		case X86_REG_R11B: return value & 0xFF;

		case X86_REG_R12:  return value;
		case X86_REG_R12D: return value & 0xFFFFFFFF;
		case X86_REG_R12W: return value & 0xFFFF;
		case X86_REG_R12B: return value & 0xFF;

		case X86_REG_R13:  return value;
		case X86_REG_R13D: return value & 0xFFFFFFFF;
		case X86_REG_R13W: return value & 0xFFFF;
		case X86_REG_R13B: return value & 0xFF;

		case X86_REG_R14:  return value;
		case X86_REG_R14D: return value & 0xFFFFFFFF;
		case X86_REG_R14W: return value & 0xFFFF;
		case X86_REG_R14B: return value & 0xFF;

		case X86_REG_R15:  return value;
		case X86_REG_R15D: return value & 0xFFFFFFFF;
		case X86_REG_R15W: return value & 0xFFFF;
		case X86_REG_R15B: return value & 0xFF;

		default: return value; // Fallback, shouldnt hit this often
	}
}

// Helper to map sub-registers to their 64-bit parent for storage
x86_reg EmulationContext::to_64bit_reg ( x86_reg reg ) const noexcept {
	switch ( reg ) {
		case X86_REG_EAX: case X86_REG_AX: case X86_REG_AH: case X86_REG_AL:
			return X86_REG_RAX;
		case X86_REG_EBX: case X86_REG_BX: case X86_REG_BH: case X86_REG_BL:
			return X86_REG_RBX;
		case X86_REG_ECX: case X86_REG_CX: case X86_REG_CH: case X86_REG_CL:
			return X86_REG_RCX;
		case X86_REG_EDX: case X86_REG_DX: case X86_REG_DH: case X86_REG_DL:
			return X86_REG_RDX;
		case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
			return X86_REG_RSI;
		case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
			return X86_REG_RDI;
		case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
			return X86_REG_RBP;
		case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
			return X86_REG_RSP;
		case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B:
			return X86_REG_R8;
		case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B:
			return X86_REG_R9;
		case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B:
			return X86_REG_R10;
		case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B:
			return X86_REG_R11;
		case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B:
			return X86_REG_R12;
		case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B:
			return X86_REG_R13;
		case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B:
			return X86_REG_R14;
		case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B:
			return X86_REG_R15;
		default: return reg; // Already 64-bit or unhandled
	}
}

void EmulationContext::dump_state ( ) const {
	std::println ( "Registers:" );
	auto print_reg = [ & ] ( KGPR reg )
	{
		return cpu->registers [ reg ];
	};
	std::println ( "\tRAX: {:016x}  RBX: {:016x}  RCX: {:016x}  RDX: {:016x}  RSI: {:016x}  RDI: {:016x}",
							 print_reg ( KRAX ), print_reg ( KRBX ),
							 print_reg ( KRCX ), print_reg ( KRDX ),
							 print_reg ( KRSI ), print_reg ( KRDI ) );
	std::println ( "\tRSP: {:016x}  RBP: {:016x}  R8:  {:016x}  R9:  {:016x}  R10: {:016x}  R11: {:016x}",
							 print_reg ( KRSP ), print_reg ( KRBP ),
							 print_reg ( KR8 ), print_reg (  KR9 ),
							 print_reg ( KR10 ), print_reg ( KR11 ) );
	std::println ( "\tR12: {:016x}  R13: {:016x}  R14: {:016x}  R15: {:016x}",
							 print_reg ( KR12 ), print_reg ( KR13 ),
							 print_reg ( KR14 ), print_reg ( KR15 ) );
	std::println ( "Flags: CF={} PF={} ZF={} SF={} OF={}",
							 ( char ) cpu->cpu_flags.flags.CF, ( char ) cpu->cpu_flags.flags.PF, ( char ) cpu->cpu_flags.flags.ZF,
							 ( char ) cpu->cpu_flags.flags.SF, ( char ) cpu->cpu_flags.flags.OF );
	for ( auto start = ( int ) X86_REG_XMM0; start < ( int ) X86_REG_XMM15; ++start ) {
		std::print ( "XMM{}: {} ", start - X86_REG_XMM0, ( *cpu->avx_registers ) [ start - X86_REG_XMM0 ].convert_to<double> ( ) );
		if ( start % 5 == 0 ) {
			std::print ( "\n" );
		}
	}
	std::println ( "MXCSR Flags: IE={} DE={}, ZE={}, OE={}, UE={}, PE={}",
								 ( char ) cpu->cpu_flags.mxcsr.IE,
								 ( char ) cpu->cpu_flags.mxcsr.DE,
								 ( char ) cpu->cpu_flags.mxcsr.ZE,
								 ( char ) cpu->cpu_flags.mxcsr.OE,
								 ( char ) cpu->cpu_flags.mxcsr.UE,
								 ( char ) cpu->cpu_flags.mxcsr.PE );

	for ( int i = 0; i < 8; ++i ) {
		int phys_idx = get_fpu_phys_idx ( i );
		if ( get_fpu_tag ( phys_idx ) != FPU_TAG_EMPTY ) {
			double log_val = cpu->fpu.fpu_stack [ phys_idx ].convert_to<double> ( );
			std::println ( "[ST{}] - {}", i, log_val );
		}
		else {
			std::println ( "[ST{}] - <empty>", i );
		}
	}
	std::println ( "Stack (size={:x}):", stack_allocated );

	std::println ( "" );
}

void InstructionEffect::normalize_registers ( EmulationContext* ctx ) {
	std::unordered_set<x86_reg> normalized {};
	for ( auto reg : modified_regs ) {
		normalized.insert ( ctx->to_64bit_reg ( reg ) );
	}
	modified_regs = normalized;
}
static void map_all_sections ( EmulationContext& state, HMODULE mod ) {
	uint64_t base = ( uint64_t ) mod;
	PE::Parser secparser ( base );
	for ( auto& sec : secparser.pe_info_.section_headers ) {
		uint64_t rva = sec.virtual_address;
		uint64_t size = std::max<uint32_t> ( sec.virtual_size, sec.size_of_raw_data );
		uint8_t* data = reinterpret_cast< uint8_t* >( mod ) + rva;
		state.windows->add_module (
			/*handle=*/mod,
			/*va=*/base + rva,
			/*size=*/size,
			/*backing_ptr=*/data
		);
	}
}


// we need to resolve dependancies recursively, since on newer windows versions
// kernel32 calls into kernelbase, which we may not catch.
void EmulationContext::initialize_imports ( std::unique_ptr<PE::Parser>& parser ) {
	if ( !parser ) return;

	auto imports_data = parser->get_imports ( );
	std::unordered_set<std::string> modules_parsed {};
	for ( const auto& [dllName, funcs] : imports_data ) {
		HMODULE mod = GetModuleHandleA ( dllName.c_str ( ) );
		if ( !mod ) {
			mod = LoadLibraryExA (
				dllName.c_str ( ),
				nullptr,
				DONT_RESOLVE_DLL_REFERENCES
			);
		}
		modules_parsed.emplace ( dllName );
		if ( !mod ) {
			std::println ( "[!] Failed to map {}: {}", dllName, GetLastError ( ) );
			continue;
		}

		map_all_sections ( *this, mod );
		for ( const auto& entry : funcs ) {
			windows->import_multi_map.insert ( { entry.first, entry.second } );
		}

		PE::Parser modParser ( ( uint64_t ) mod );
		auto import_map = modParser.get_imports ( );
		for ( const auto& kv : import_map ) {
			const auto& key_name = kv.first;
			if ( modules_parsed.contains ( key_name ) ) {
				continue;
			}
			HMODULE sub_mod = GetModuleHandleA ( key_name.c_str ( ) );
			if ( !sub_mod ) {
				sub_mod = LoadLibraryExA (
				key_name.c_str ( ),
				nullptr,
				DONT_RESOLVE_DLL_REFERENCES
				);
			}
			if ( !sub_mod ) {
				continue;
			}

			map_all_sections ( *this, sub_mod );
			modules_parsed.emplace ( key_name );
			for ( const auto& entry : kv.second ) {
				windows->import_multi_map.insert ( { entry.first, entry.second } );
			}
		}

		auto [expDir, expEntries] = modParser.get_export_directory ( );

		for ( auto& [funcName, iatAddr] : funcs ) {
			uint32_t rva = 0;
			for ( auto const& entry : expEntries ) {
				if ( std::get<0> ( entry ) == funcName ) {
					rva = uint32_t ( std::get<3> ( entry ) - reinterpret_cast< uint64_t >( mod ) );
					break;
				}
			}
			if ( !rva ) {
				std::println ( "[!] {} does not export {}", dllName, funcName );
				continue;
			}

			//uint64_t emuVA = ( uint64_t ) mod + rva;
			//DWORD old;
			//VirtualProtect ( ( void* ) iatAddr, sizeof ( uint64_t ), PAGE_READWRITE, &old );
			//*reinterpret_cast< uint64_t* >( iatAddr ) = emuVA;
			//windows->import_multi_map.insert ( { funcName, emuVA } );
			//windows->import_multi_map.insert ( { funcName, iatAddr } );
			//
			//VirtualProtect ( ( void* ) iatAddr, sizeof ( uint64_t ), old, &old );
		}
	}
}



bool EmulationContext::is_string_at ( int64_t base, int64_t max_len ) const {
	__debugbreak ( );
	return false;
}
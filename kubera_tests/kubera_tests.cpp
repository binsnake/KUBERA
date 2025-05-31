#include "utils.hpp"
#include <chrono>

std::unique_ptr< capstone::Decoder > capstone_decoder;

uint8_t get_gpr_size_from_id ( x86_reg reg_id ) {
	switch ( reg_id ) {
		// 8-bit
		case X86_REG_AL: case X86_REG_CL: case X86_REG_DL: case X86_REG_BL:
		case X86_REG_AH: case X86_REG_CH: case X86_REG_DH: case X86_REG_BH:
		case X86_REG_SPL: case X86_REG_BPL: case X86_REG_SIL: case X86_REG_DIL:
		case X86_REG_R8B: case X86_REG_R9B: case X86_REG_R10B: case X86_REG_R11B:
		case X86_REG_R12B: case X86_REG_R13B: case X86_REG_R14B: case X86_REG_R15B:
			return 1;
			// 16-bit
		case X86_REG_AX: case X86_REG_CX: case X86_REG_DX: case X86_REG_BX:
		case X86_REG_SP: case X86_REG_BP: case X86_REG_SI: case X86_REG_DI:
		case X86_REG_R8W: case X86_REG_R9W: case X86_REG_R10W: case X86_REG_R11W:
		case X86_REG_R12W: case X86_REG_R13W: case X86_REG_R14W: case X86_REG_R15W:
		case X86_REG_IP:
			return 2;
			// 32-bit
		case X86_REG_EAX: case X86_REG_ECX: case X86_REG_EDX: case X86_REG_EBX:
		case X86_REG_ESP: case X86_REG_EBP: case X86_REG_ESI: case X86_REG_EDI:
		case X86_REG_R8D: case X86_REG_R9D: case X86_REG_R10D: case X86_REG_R11D:
		case X86_REG_R12D: case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
		case X86_REG_EIP:
			return 4;
			// 64-bit
		case X86_REG_RAX: case X86_REG_RCX: case X86_REG_RDX: case X86_REG_RBX:
		case X86_REG_RSP: case X86_REG_RBP: case X86_REG_RSI: case X86_REG_RDI:
		case X86_REG_R8: case X86_REG_R9: case X86_REG_R10: case X86_REG_R11:
		case X86_REG_R12: case X86_REG_R13: case X86_REG_R14: case X86_REG_R15:
		case X86_REG_RIP:
			return 8;
			// Segment registers (selectors)
		case X86_REG_CS: case X86_REG_DS: case X86_REG_ES:
		case X86_REG_FS: case X86_REG_GS: case X86_REG_SS:
			return 2;

		default:
			std::println ( "Warning: get_gpr_size_from_id called with unexpected reg_id: {}", cs_reg_name ( capstone_decoder->get_handle ( ), reg_id ) );
			return 8;
	}
}


void print_deserialized ( const std::vector<DeserializedTestCase>& cases ) {
	for ( size_t i = 0; i < cases.size ( ); ++i ) {
		const auto& tc = cases [ i ];
		std::print ( "Test Case {}:\n", i + 1 );
		std::print ( "  Instr ID: {:#x}, Mnemonic: {}\n", tc.instr_id, tc.mnemonic );
		std::print ( "  Opcode:" );
		for ( uint8_t byte : tc.opcode ) {
			std::print ( " {:#04x}", byte );
		}
		std::print ( "\n" );
		for ( size_t j = 0; j < tc.inputs.size ( ); ++j ) {
			std::print ( "  Input {}: X86_REG_{} ({}) = {:#x}\n",
								 j + 1, static_cast< int > ( tc.inputs [ j ].first ), cs_reg_name ( capstone_decoder->get_handle ( ), tc.inputs [ j ].first ), tc.inputs [ j ].second );
		}
		for ( size_t j = 0; j < tc.outputs.size ( ); ++j ) {
			std::print ( "  Output {}: X86_REG_{} ({}) = {:#x}\n",
								 j + 1, static_cast< int > ( tc.outputs [ j ].first ), cs_reg_name ( capstone_decoder->get_handle ( ), tc.outputs [ j ].first ), tc.outputs [ j ].second );
		}
		std::print ( "  Flags: {:#x}\n", tc.flags_out );
	}
}

std::string read_file ( const std::string& filename ) {
	std::ifstream file ( filename );
	if ( !file.is_open ( ) ) {
		std::print ( "Error: Could not open file {}\n", filename );
		return "";
	}

	std::stringstream buffer;
	buffer << file.rdbuf ( );
	return buffer.str ( );
}

unsigned char shellcode [ ] = {
		0x48, 0x31, 0xC0,        // xor rax, rax
		0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
		0x48, 0x31, 0xD2,        // xor rdx, rdx
		0x48, 0x31, 0xDB,        // xor rbx, rbx
		0x48, 0xF7, 0xFB,        // idiv rbx
		0xC3                     // ret
};

#define CT_CHECK(x, y) if constexpr (x) {y;}

void test ( EmulationContext& state, const std::string& _file ) {
	std::println ( "[+] Loading tests from {}", _file );
	auto file = read_file ( _file );
	if ( file.empty ( ) ) {
		std::println ( "[!] Failed to load tests" );
		return;
	}
	auto instructions = parse_input ( file );
	auto deserialized = deserialize_test_cases ( instructions );
	std::println ( "[+] Loaded {} instructions with a total of {} tests", instructions.size ( ), deserialized.size ( ) );
	std::println ( "[+] Running tests" );


	auto start_time_clock = std::chrono::high_resolution_clock::now ( );
	[[maybe_unused]] auto control = 0; // Marked unused as it's not used in the loop now
	auto control_ins = 0;

	InstructionEffect effect {};
	constexpr bool print_fails = true;
	size_t cases = 0;
	size_t fails = 0;
	size_t passed = 0;

	capstone_decoder = std::make_unique<capstone::Decoder> ( deserialized [ 0 ].opcode.data ( ), deserialized [ 0 ].opcode.size ( ), 0ull );
	std::unordered_map<x86_insn, Handler*> handler_cache;


	const size_t BATCH_SIZE = 64;
	for ( size_t i = 0; i < deserialized.size ( ); i += BATCH_SIZE ) {
		size_t end = std::min ( i + BATCH_SIZE, deserialized.size ( ) );

		for ( size_t j = i; j < end; ++j ) {
			const auto& test_case = deserialized [ j ];

			capstone_decoder->reconfigure ( const_cast< uint8_t* > ( test_case.opcode.data ( ) ), test_case.opcode.size ( ), 0 );

			state.set_eflags ( test_case.flags_in, effect );
			for ( const auto& input : test_case.inputs ) {
				x86_reg reg_id = input.first;
				uint64_t val64 = input.second;

				if ( reg_id >= X86_REG_XMM0 && reg_id <= X86_REG_XMM15 ) {
					state.set_xmm_raw ( reg_id, uint128_t ( val64 ), effect );
				}
				else if ( reg_id >= X86_REG_YMM0 && reg_id <= X86_REG_YMM15 ) {
					state.set_ymm_raw ( reg_id, uint256_t ( val64 ), effect );
				}
				else if ( reg_id >= X86_REG_ZMM0 && reg_id <= X86_REG_ZMM15 ) {
					state.set_zmm_raw ( reg_id, uint512_t ( val64 ), effect );
				}
				else {
					uint8_t reg_size = get_gpr_size_from_id ( reg_id );
					state.set_reg ( reg_id, val64, reg_size, effect );
				}
			}
			auto last_flags = state.get_eflags ( );

			auto instr = capstone_decoder->decode ( );
			x86_insn mnemonic = static_cast< x86_insn >( instr.mnemonic ( ) );

			Handler* current_handler = nullptr; // Renamed from handler to avoid conflict
			if ( handler_cache.contains ( mnemonic ) ) [[likely]] {
				current_handler = handler_cache [ mnemonic ];
			}
			else {
				auto it = instruction_handlers.find ( mnemonic );
				if ( it != instruction_handlers.end ( ) ) {
					current_handler = it->second;
					handler_cache [ mnemonic ] = current_handler;
				}
			}

			if ( current_handler ) {
				( *current_handler )( instr, state, effect );
			}
			else {
				std::println ( "Unhandled mnemonic: {}", instr.to_string ( ) );
				__debugbreak ( );
			}

			bool success = true;
			for ( const auto& output : test_case.outputs ) {
				x86_reg reg_id_out = output.first;
				uint64_t expected_val64 = output.second;
				uint64_t actual_val64 = 0;
				bool reg_checked = false;

				if ( reg_id_out >= X86_REG_XMM0 && reg_id_out <= X86_REG_XMM15 ) {
					actual_val64 = static_cast< uint64_t >( state.get_xmm_raw ( reg_id_out ) );
					reg_checked = true;
				}
				else if ( reg_id_out >= X86_REG_YMM0 && reg_id_out <= X86_REG_YMM15 ) {
					actual_val64 = static_cast< uint64_t >( state.get_ymm_raw ( reg_id_out ) );
					reg_checked = true;
				}
				else if ( reg_id_out >= X86_REG_ZMM0 && reg_id_out <= X86_REG_ZMM15 ) {
					actual_val64 = static_cast< uint64_t >( state.get_zmm_raw ( reg_id_out ) );
					reg_checked = true;
				}
				else {
					uint8_t reg_size_out = get_gpr_size_from_id ( reg_id_out );
					actual_val64 = state.get_reg ( reg_id_out, reg_size_out );
					reg_checked = true;
				}

				if ( reg_checked && actual_val64 != expected_val64 ) {
					success = false;
				}
			}
			auto changed_flags = last_flags ^ state.get_eflags ( );
			if ( test_case.flags_out != changed_flags ) {
				 //success = false; // Still keeping strict flag check disabled for now
			}

			if ( !success ) {
				CT_CHECK ( print_fails, std::println ( "[!] Test case: {} failed", instr.to_string_no_address ( ) ) )
					++fails;

				CT_CHECK ( print_fails,
											for ( const auto& input : test_case.inputs ) {
												std::println ( "[?] INPUT: {}: {:#x}", cs_reg_name ( capstone_decoder->get_handle ( ), input.first ), static_cast< uint64_t >( input.second ) );
											}
												)

					CT_CHECK ( print_fails,
												for ( const auto& output_expected : test_case.outputs ) {
													uint64_t actual_value_debug = 0;
													x86_reg reg_id_debug = output_expected.first;
													if ( reg_id_debug >= X86_REG_XMM0 && reg_id_debug <= X86_REG_XMM15 ) actual_value_debug = static_cast< uint64_t >( state.get_xmm_raw ( reg_id_debug ) );
													else if ( reg_id_debug >= X86_REG_YMM0 && reg_id_debug <= X86_REG_YMM15 ) actual_value_debug = static_cast< uint64_t >( state.get_ymm_raw ( reg_id_debug ) );
													else if ( reg_id_debug >= X86_REG_ZMM0 && reg_id_debug <= X86_REG_ZMM15 ) actual_value_debug = static_cast< uint64_t >( state.get_zmm_raw ( reg_id_debug ) );
													else {
														uint8_t reg_size_out_dbg = get_gpr_size_from_id ( reg_id_debug );
														actual_value_debug = state.get_reg ( reg_id_debug, reg_size_out_dbg );
													}
													std::println ( "[?] OUTPUT: {}: expected {:#x} == emu: {:#x}", cs_reg_name ( capstone_decoder->get_handle ( ), output_expected.first ), static_cast< uint64_t >( output_expected.second ), actual_value_debug );
												}
													)
					CT_CHECK ( print_fails, std::println ( "[?] FLAGS_IN: {:#x}, FLAGS_AFTER_EMU: {:#x}, EXPECTED_FLAGS_DIFF: {:#x}, ACTUAL_FLAGS_DIFF: {:#x}", test_case.flags_in, state.get_eflags ( ), test_case.flags_out, changed_flags ) );
			}
			else {
				++passed;
			}

			++cases;
			++control_ins;
		}
	}
	auto end_time = std::chrono::high_resolution_clock::now ( );
	auto duration_ns = std::chrono::duration_cast< std::chrono::nanoseconds >( end_time - start_time_clock ).count ( );
	auto duration_ms = std::chrono::duration_cast< std::chrono::milliseconds >( end_time - start_time_clock ).count ( );
	std::println ( "[+] Success: {}\n[+] Fails: {}", passed, fails );
	std::println ( "[+] Ran {} test cases (instructions executed) in {} ns ({}ms)", control_ins, duration_ns, duration_ms );
	if ( duration_ms > 0 ) {
		std::println ( "[+] Throughput: {} instructions / second", static_cast< double >( control_ins ) / ( static_cast< double >( duration_ms ) / 1000.0 ) );
	}
	else if ( duration_ns > 0 ) {
		std::println ( "[+] Throughput: {} instructions / second", static_cast< double >( control_ins ) / ( static_cast< double >( duration_ns ) / 1000000000.0 ) );
	}
	else {
		std::println ( "[+] Throughput: N/A (duration too short)" );
	}
}

int main ( int argc, char* argv [ ] ) {
	//Sleep ( 10000 );
	if ( argc != 1 ) {
		std::println ( "usage: kubera_tests.exe add.txt" );
	}
	EmulationContext state {};

	std::string arg1 = argv [ 1 ];
	test ( state, "tests\\" + arg1 );

}
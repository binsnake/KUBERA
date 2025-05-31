#pragma once

#include <semantics/src/pch.hpp>
#include <shared/context.hpp>
#include <shared/capstone++.hpp>
#include <unordered_map>
#include <print>
#include <iostream>
#include <format>
#include <sstream>

x86_reg to_64bit_reg ( x86_reg reg ) {
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

x86_reg resolve_register ( const std::string& reg_name ) {
	static const std::unordered_map<std::string, x86_reg> reg_map = {
		// RAX and its subregisters
		{"rax", X86_REG_RAX}, {"eax", X86_REG_EAX}, {"ax", X86_REG_AX}, {"ah", X86_REG_AH}, {"al", X86_REG_AL},
		// RBX and its subregisters
		{"rbx", X86_REG_RBX}, {"ebx", X86_REG_EBX}, {"bx", X86_REG_BX}, {"bh", X86_REG_BH}, {"bl", X86_REG_BL},
		// RCX and its subregisters
		{"rcx", X86_REG_RCX}, {"ecx", X86_REG_ECX}, {"cx", X86_REG_CX}, {"ch", X86_REG_CH}, {"cl", X86_REG_CL},
		// RDX and its subregisters
		{"rdx", X86_REG_RDX}, {"edx", X86_REG_EDX}, {"dx", X86_REG_DX}, {"dh", X86_REG_DH}, {"dl", X86_REG_DL},
		// RSI and its subregisters
		{"rsi", X86_REG_RSI}, {"esi", X86_REG_ESI}, {"si", X86_REG_SI}, {"sil", X86_REG_SIL},
		// RDI and its subregisters
		{"rdi", X86_REG_RDI}, {"edi", X86_REG_EDI}, {"di", X86_REG_DI}, {"dil", X86_REG_DIL},
		// RBP and its subregisters
		{"rbp", X86_REG_RBP}, {"ebp", X86_REG_EBP}, {"bp", X86_REG_BP}, {"bpl", X86_REG_BPL},
		// RSP and its subregisters
		{"rsp", X86_REG_RSP}, {"esp", X86_REG_ESP}, {"sp", X86_REG_SP}, {"spl", X86_REG_SPL},
		// R8 and its subregisters
		{"r8", X86_REG_R8}, {"r8d", X86_REG_R8D}, {"r8w", X86_REG_R8W}, {"r8b", X86_REG_R8B},
		// R9 and its subregisters
		{"r9", X86_REG_R9}, {"r9d", X86_REG_R9D}, {"r9w", X86_REG_R9W}, {"r9b", X86_REG_R9B},
		// R10 and its subregisters
		{"r10", X86_REG_R10}, {"r10d", X86_REG_R10D}, {"r10w", X86_REG_R10W}, {"r10b", X86_REG_R10B},
		// R11 and its subregisters
		{"r11", X86_REG_R11}, {"r11d", X86_REG_R11D}, {"r11w", X86_REG_R11W}, {"r11b", X86_REG_R11B},
		// R12 and its subregisters
		{"r12", X86_REG_R12}, {"r12d", X86_REG_R12D}, {"r12w", X86_REG_R12W}, {"r12b", X86_REG_R12B},
		// R13 and its subregisters
		{"r13", X86_REG_R13}, {"r13d", X86_REG_R13D}, {"r13w", X86_REG_R13W}, {"r13b", X86_REG_R13B},
		// R14 and its subregisters
		{"r14", X86_REG_R14}, {"r14d", X86_REG_R14D}, {"r14w", X86_REG_R14W}, {"r14b", X86_REG_R14B},
		// R15 and its subregisters
		{"r15", X86_REG_R15}, {"r15d", X86_REG_R15D}, {"r15w", X86_REG_R15W}, {"r15b", X86_REG_R15B},
		// XMM registers
		{"xmm0", X86_REG_XMM0}, {"xmm1", X86_REG_XMM1}, {"xmm2", X86_REG_XMM2}, {"xmm3", X86_REG_XMM3},
		{"xmm4", X86_REG_XMM4}, {"xmm5", X86_REG_XMM5}, {"xmm6", X86_REG_XMM6}, {"xmm7", X86_REG_XMM7},
		{"xmm8", X86_REG_XMM8}, {"xmm9", X86_REG_XMM9}, {"xmm10", X86_REG_XMM10}, {"xmm11", X86_REG_XMM11},
		{"xmm12", X86_REG_XMM12}, {"xmm13", X86_REG_XMM13}, {"xmm14", X86_REG_XMM14}, {"xmm15", X86_REG_XMM15},
		// YMM registers
		{"ymm0", X86_REG_YMM0}, {"ymm1", X86_REG_YMM1}, {"ymm2", X86_REG_YMM2}, {"ymm3", X86_REG_YMM3},
		{"ymm4", X86_REG_YMM4}, {"ymm5", X86_REG_YMM5}, {"ymm6", X86_REG_YMM6}, {"ymm7", X86_REG_YMM7},
		{"ymm8", X86_REG_YMM8}, {"ymm9", X86_REG_YMM9}, {"ymm10", X86_REG_YMM10}, {"ymm11", X86_REG_YMM11},
		{"ymm12", X86_REG_YMM12}, {"ymm13", X86_REG_YMM13}, {"ymm14", X86_REG_YMM14}, {"ymm15", X86_REG_YMM15},
		// ZMM registers
		{"zmm0", X86_REG_ZMM0}, {"zmm1", X86_REG_ZMM1}, {"zmm2", X86_REG_ZMM2}, {"zmm3", X86_REG_ZMM3},
		{"zmm4", X86_REG_ZMM4}, {"zmm5", X86_REG_ZMM5}, {"zmm6", X86_REG_ZMM6}, {"zmm7", X86_REG_ZMM7},
		{"zmm8", X86_REG_ZMM8}, {"zmm9", X86_REG_ZMM9}, {"zmm10", X86_REG_ZMM10}, {"zmm11", X86_REG_ZMM11},
		{"zmm12", X86_REG_ZMM12}, {"zmm13", X86_REG_ZMM13}, {"zmm14", X86_REG_ZMM14}, {"zmm15", X86_REG_ZMM15}
	};

	if ( reg_name.empty ( ) ) {
		std::print ( "Empty register name\n" );
		return X86_REG_INVALID;
	}

	if ( reg_name == "flags" ) {
		return X86_REG_INVALID;
	}

	auto it = reg_map.find ( reg_name );
	if ( it != reg_map.end ( ) ) {
		return it->second;
	}

	std::print ( "Unrecognized register: {}\n", reg_name );
	return X86_REG_INVALID;
}

uint64_t parse_register_value ( const std::string& value_str ) {
	if ( value_str.empty ( ) || value_str [ 0 ] != '#' ) {
		std::print ( "Invalid register value format: {}\n", value_str.empty ( ) ? "<empty>" : value_str );
		return 0;
	}

	// Remove trailing comma if present
	std::string clean_str = value_str;
	if ( !clean_str.empty ( ) && clean_str.back ( ) == ',' ) {
		clean_str.pop_back ( );
	}

	std::string hex_str = clean_str.substr ( 1 );
	if ( hex_str.length ( ) % 2 != 0 ) {
		//std::print ( "Padding odd-length register value: {} with 0 at front\n", hex_str );
		hex_str = "0" + hex_str;
	}

	std::vector<uint8_t> bytes;
	for ( size_t i = 0; i < hex_str.length ( ); i += 2 ) {
		try {
			std::string byte_str = hex_str.substr ( i, 2 );
			bytes.push_back ( static_cast< uint8_t > ( std::stoul ( byte_str, nullptr, 16 ) ) );
		}
		catch ( const std::exception& e ) {
			( e );
			std::print ( "Error parsing register value byte: {}\n", hex_str.substr ( i, 2 ) );
			return 0;
		}
	}


	uint64_t result = 0;
	for ( size_t i = 0; i < bytes.size ( ) && i < 8; ++i ) { // Limit to 8 bytes for uint64_t
		result |= static_cast< uint64_t > ( bytes [ i ] ) << ( i * 8 );
	}

	return result;
}

// Helper function to parse hex opcode into bytes
std::vector<uint8_t> parse_opcode ( const std::string& opcode_str ) {
	std::vector<uint8_t> opcode;
	if ( opcode_str.empty ( ) || opcode_str [ 0 ] != '#' ) {
		std::print ( "Invalid opcode format: {}\n", opcode_str );
		return opcode;
	}

	std::string hex_str = opcode_str.substr ( 1 ); // Skip '#'
	if ( hex_str.length ( ) % 2 != 0 ) {
		std::print ( "Invalid opcode length: {}\n", hex_str );
		return opcode;
	}

	for ( size_t i = 0; i < hex_str.length ( ); i += 2 ) {
		try {
			std::string byte_str = hex_str.substr ( i, 2 );
			uint8_t byte = static_cast< uint8_t > ( std::stoul ( byte_str, nullptr, 16 ) );
			opcode.push_back ( byte );
		}
		catch ( const std::exception& e ) {
			( e );
			std::print ( "Error parsing opcode byte: {}\n", hex_str.substr ( i, 2 ) );
			return {};
		}
	}
	return opcode;
}

struct DeserializedTestCase {
	uint64_t instr_id;
	std::vector<uint8_t> opcode;
	std::string mnemonic;
	std::vector<std::pair<x86_reg, uint64_t>> inputs; 
	std::vector<std::pair<x86_reg, uint64_t>> outputs;
	uint32_t flags_in;  
	uint32_t flags_out; 
};

struct TestCase {
	struct Register {
		std::string name;
		uint64_t value;
	};
	std::vector<Register> inputs;
	Register output;		
	uint32_t flags_in;  
	uint32_t flags_out; 
};

struct Instruction {
	uint64_t id;
	std::vector<uint8_t> opcode;
	std::string mnemonic;
	uint32_t case_count;
	std::vector<TestCase> cases;
};

std::vector<Instruction> parse_input ( const std::string& input ) {
	std::vector<Instruction> instructions;
	std::istringstream stream ( input );
	std::string line;

	while ( std::getline ( stream, line ) ) {
		if ( line.empty ( ) ) continue;

		// Parse instruction line
		if ( line.starts_with ( "instr:" ) ) {
			Instruction instr;
			std::string id_str, opcode_str, mnemonic, case_count_str;

			// Split instruction line
			size_t pos = line.find ( ':' );
			size_t semicolon1 = line.find ( ';', pos );
			size_t semicolon2 = line.find ( ';', semicolon1 + 1 );
			size_t semicolon3 = line.find ( ';', semicolon2 + 1 );

			id_str = line.substr ( pos + 1, semicolon1 - pos - 1 );
			opcode_str = line.substr ( semicolon1 + 1, semicolon2 - semicolon1 - 1 );
			mnemonic = line.substr ( semicolon2 + 1, semicolon3 - semicolon2 - 1 );
			case_count_str = line.substr ( semicolon3 + 1 );

			// Convert fields
			try {
				instr.id = std::stoull ( id_str, nullptr, 16 );
				instr.opcode = parse_opcode ( opcode_str );
				if ( instr.opcode.empty ( ) ) {
					std::print ( "Skipping instruction due to invalid opcode: {}\n", line );
					continue;
				}
				instr.mnemonic = mnemonic;
				instr.case_count = std::stoul ( case_count_str );
			}
			catch ( const std::exception& e ) {
				( e );
				std::print ( "Error parsing instruction: {}\n", line );
				continue;
			}

			// Parse test cases
			for ( uint32_t i = 0; i < instr.case_count; ++i ) {
				if ( !std::getline ( stream, line ) || line.empty ( ) ) {
					std::print ( "Missing test case for instruction ID {:#x}\n", instr.id );
					break;
				}

				if ( !line.starts_with ( " in:" ) ) {
					std::print ( "Invalid test case format: {}\n", line );
					continue;
				}

				TestCase test_case {};
				size_t pipe_pos = line.find ( '|' );
				if ( pipe_pos == std::string::npos ) {
					std::print ( "Invalid test case, missing '|': {}\n", line );
					continue;
				}

				// Parse inputs
				std::string inputs_str = line.substr ( 4, pipe_pos - 4 );
				std::string outputs_str = line.substr ( pipe_pos + 1 );

				// Parse input registers and flags
				size_t input_pos = 0;
				while ( input_pos < inputs_str.size ( ) ) {
					size_t colon = inputs_str.find ( ':', input_pos );
					size_t comma = inputs_str.find ( ',', colon );
					if ( colon == std::string::npos ) break; // No more inputs
					// Handle case where it's the last input, so no trailing comma
					if ( comma == std::string::npos || comma < colon ) comma = inputs_str.size ( );


					std::string reg_name_str = inputs_str.substr ( input_pos, colon - input_pos );
					std::string reg_value_str = inputs_str.substr ( colon + 1, comma - ( colon + 1 ) );


					try {
						if ( reg_name_str == "flags" ) {
							test_case.flags_in = static_cast< uint32_t > ( parse_register_value ( reg_value_str ) );
						}
						else {
							uint64_t value = parse_register_value ( reg_value_str );
							test_case.inputs.push_back ( { reg_name_str, value } );
						}
					}
					catch ( const std::exception& e ) {
						( e );
						std::print ( "Error parsing input register value: {} for reg {}\n", reg_value_str, reg_name_str );
					}
					if ( comma == inputs_str.size ( ) ) break;
					input_pos = comma + 1;
				}

				// Parse output and flags
				size_t out_prefix_pos = outputs_str.find ( "out:" );
				if ( out_prefix_pos == std::string::npos ) {
					std::print ( "Missing 'out:' in output: {}\n", outputs_str );
					continue;
				}

				std::string out_content_str = outputs_str.substr ( out_prefix_pos + 4 );
				try {
					if ( out_content_str.empty ( ) ) {
						std::print ( "Empty output string after 'out:'\n" );
						continue;
					}
					if ( out_content_str.starts_with ( "flags:" ) ) {
						std::string flags_value_str = out_content_str.substr ( 6 );
						if ( flags_value_str.empty ( ) ) {
							std::print ( "Empty flags value in output\n" );
							continue;
						}
						test_case.output = { "", 0 };
						test_case.flags_out = static_cast< uint32_t >( parse_register_value ( flags_value_str ) );
					}
					else {
						size_t comma_pos = out_content_str.find ( ',' );
						std::string reg_part_str = out_content_str;
						std::string flags_part_str = "";

						if ( comma_pos != std::string::npos ) {
							reg_part_str = out_content_str.substr ( 0, comma_pos );
							flags_part_str = out_content_str.substr ( comma_pos + 1 );
							if ( flags_part_str.starts_with ( "flags:" ) ) {
								flags_part_str = flags_part_str.substr ( 6 );
							}
							else {
								if ( !flags_part_str.empty ( ) ) {
									std::print ( "Warning: Unexpected content after comma in output: {}\n", flags_part_str );
									flags_part_str = "";
								}
							}
						}

						size_t out_colon = reg_part_str.find ( ':' );
						if ( out_colon == std::string::npos || out_colon == 0 || out_colon >= reg_part_str.size ( ) - 1 ) {
							std::print ( "Invalid output register format: {}\n", reg_part_str.empty ( ) ? "<empty>" : reg_part_str );
							continue;
						}

						std::string out_reg_name_str = reg_part_str.substr ( 0, out_colon );
						std::string out_reg_value_str = reg_part_str.substr ( out_colon + 1 );

						if ( out_reg_name_str.empty ( ) ) {
							std::print ( "Empty output register name\n" );
							continue;
						}
						if ( out_reg_value_str.empty ( ) ) {
							std::print ( "Empty output register value\n" );
							continue;
						}
						test_case.output = { out_reg_name_str, parse_register_value ( out_reg_value_str ) };
						test_case.flags_out = flags_part_str.empty ( ) ? 0 : static_cast< uint32_t >( parse_register_value ( flags_part_str ) );
					}
				}
				catch ( const std::exception& e ) {
					( e );
					std::print ( "Error parsing output/flags: {}\n", out_content_str );
					continue;
				}

				instr.cases.push_back ( test_case );
			}

			instructions.push_back ( instr );
		}
	}

	return instructions;
}

// Convert parsed instructions to deserialized test cases
std::vector<DeserializedTestCase> deserialize_test_cases ( const std::vector<Instruction>& instructions ) {
	std::vector<DeserializedTestCase> deserialized;
	deserialized.reserve ( instructions.size ( ) * 26 ); // Rough estimate for capacity

	for ( const auto& instr : instructions ) {
		for ( const auto& tc : instr.cases ) {
			DeserializedTestCase dtc;
			dtc.instr_id = instr.id;
			dtc.opcode = instr.opcode;
			dtc.mnemonic = instr.mnemonic;

			for ( const auto& input : tc.inputs ) {
				x86_reg reg_id = resolve_register ( input.name );
				if ( reg_id != X86_REG_INVALID ) {
					dtc.inputs.emplace_back ( reg_id, input.value );
				}
			}

			if ( !tc.output.name.empty ( ) ) {
				x86_reg out_reg_id = resolve_register ( tc.output.name );
				if ( out_reg_id != X86_REG_INVALID ) {
					dtc.outputs.emplace_back ( out_reg_id, tc.output.value );
				}
			}


			dtc.flags_in = tc.flags_in;
			dtc.flags_out = tc.flags_out;

			deserialized.push_back ( dtc );
		}
	}

	return deserialized;
}
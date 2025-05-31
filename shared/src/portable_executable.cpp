#include <shared/portable_executable.hpp>
#include <fstream>
#include <algorithm>
#include <ranges>
#include <format>
#include <functional>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace PE
{
	auto is_rva_in_section ( uint32_t rva, const SectionHeader& section ) -> bool {
		return rva >= section.virtual_address &&
			rva <= section.virtual_address + section.virtual_size;
	}

	auto mapped_rva_in_section ( uint32_t rva, const SectionHeader& section ) -> bool {
		return rva >= section.pointer_to_raw_data &&
			rva <= section.pointer_to_raw_data + section.size_of_raw_data;
	}

	auto Parser::is_executable_address ( uint64_t va ) const noexcept -> bool {
		static auto executable_sections = this->get_executable_sections_data ( );
		//auto rva = va - mapped_address;
		for ( const auto& [_, data, virt, ___] : executable_sections ) {
			if ( va >= virt && va <= virt + data.size ( ) ) {
				return true;
			}
		}
		return false;
	}

	auto Parser::rva_to_offset ( uint32_t rva ) const -> size_t {
		if ( mapped_image ) {
			return rva;
		}
		auto pred = std::bind ( is_rva_in_section, rva, std::placeholders::_1 );
		auto it = std::ranges::find_if ( pe_info_.section_headers, pred );

		if ( it == pe_info_.section_headers.end ( ) ) {
			return 0;
			throw std::runtime_error ( "RVA not found in any section" );
		}

		return rva - it->virtual_address + it->pointer_to_raw_data;
	}

	template<typename T>
	auto Parser::read_struct ( std::span<const uint8_t> data, size_t offset ) -> T {
		if ( offset + sizeof ( T ) > data.size ( ) ) {
			throw std::runtime_error ( "Buffer overflow reading structure" );
		}
		T result;
		std::memcpy ( &result, data.data ( ) + offset, sizeof ( T ) );
		return result;
	}

	auto Parser::parse ( std::span<const uint8_t> buffer ) -> PEInfoAligned {
		auto dos_header = read_struct<DosHeader> ( buffer, 0 );
		if ( dos_header.e_magic != 0x5A4D ) {
			return {};
			throw std::runtime_error ( "Not a valid PE file" );
		}

		size_t pe_offset = dos_header.e_lfanew;
		if ( uint32_t signature = read_struct<uint32_t> ( buffer, pe_offset );
				 signature != 0x00004550 ) {
			throw std::runtime_error ( "Invalid PE signature" );
		}

		auto file_header = read_struct<FileHeader> ( buffer, pe_offset + 4 );
		if ( file_header.machine != 0x8664 ) {
			throw std::runtime_error ( "Not an x64 binary" );
		}

		auto optional_header = read_struct<OptionalHeader> (
			buffer, pe_offset + 4 + sizeof ( FileHeader ) );
		if ( optional_header.magic != 0x20b ) {
			throw std::runtime_error ( "Not a PE32+ binary" );
		}

		std::vector<DataDirectory> data_dirs { optional_header.data_directories.begin ( ),
			optional_header.data_directories.end ( ) };

		size_t section_offset = pe_offset + 4 + sizeof ( FileHeader ) +
			file_header.size_of_optional_header;
		std::vector<SectionHeader> sections;
		sections.reserve ( file_header.number_of_sections );

		for ( uint16_t i : std::views::iota ( 0u, file_header.number_of_sections ) ) {
			sections.push_back ( read_struct<SectionHeader> (
				buffer, section_offset + i * sizeof ( SectionHeader ) ) );
		}

		return { dos_header,file_header,optional_header,std::move ( sections ),std::move ( data_dirs ) };
	}

	Parser::Parser ( std::string_view file_path ) {
		std::ifstream file { file_path.data ( ),std::ios::binary };
		if ( !file ) {
			throw std::runtime_error ( std::string ( "Failed to open file: " ) + file_path.data ( ) );
		}

		file.seekg ( 0, std::ios::end );
		buffer_.resize ( file.tellg ( ) );
		file.seekg ( 0, std::ios::beg );
		file.read ( reinterpret_cast< char* >( buffer_.data ( ) ), buffer_.size ( ) );
		pe_info_ = parse ( buffer_ );
	}

	Parser::Parser ( uint64_t address ) {
		buffer_.resize ( 0x1000 );
		std::memcpy ( buffer_.data ( ), ( void* ) address, 0x1000 );
		pe_info_ = parse ( buffer_ );
		buffer_.resize ( pe_info_.optional_header.size_of_image );
		std::memcpy ( buffer_.data ( ), ( void* ) address, buffer_.size ( ) );
		mapped_image = true;
		mapped_address = address;
	}

	auto Parser::get_section_data ( std::string_view section_name ) const -> std::vector<uint8_t> {
		auto section = std::ranges::find_if ( pe_info_.section_headers,
																					[ section_name ] ( const auto& s )
		{
			std::string name { reinterpret_cast< const char* >( s.name.data ( ) ),8 };
			return name.starts_with ( section_name );
		} );

		if ( section == pe_info_.section_headers.end ( ) ) {
			throw std::runtime_error ( "Section " + std::string ( section_name ) + " not found" );
		}

		return std::vector<uint8_t> (
			buffer_.begin ( ) + section->pointer_to_raw_data,
			buffer_.begin ( ) + section->pointer_to_raw_data + section->size_of_raw_data );
	}

	auto Parser::get_entry_point ( ) const noexcept -> uint64_t {
		if ( override_entry_point_ ) {
			return get_image_base ( ) + override_entry_point_;
		}

		return pe_info_.optional_header.image_base +
			pe_info_.optional_header.address_of_entry_point;
	}

	auto Parser::get_text_section_data ( ) const -> std::vector<uint8_t> {
		return get_section_data ( ".text" );
	}

	auto Parser::get_image_base ( ) const noexcept -> uint64_t {
		if ( override_base_address_ ) {
			return override_base_address_;
		}

		return pe_info_.optional_header.image_base;
	}

	auto Parser::get_executable_sections_data ( ) const -> ExecutableSectionData {
		ExecutableSectionData result;

		for ( const auto& section : pe_info_.section_headers |
					std::views::filter ( [ ] ( const auto& s )
		{
			return s.characteristics & scn_mem_execute;
		} ) ) {
			std::string name { reinterpret_cast< const char* >( section.name.data ( ) ),8 };
			name = name.substr ( 0, name.find ( '\0' ) );
			size_t start = section.pointer_to_raw_data;
			result.emplace_back (
				name,
				std::vector<uint8_t> ( buffer_.begin ( ) + start,
				buffer_.begin ( ) + start + section.size_of_raw_data ),
				get_image_base ( ) + section.virtual_address,
				true
			);
		}

		if ( result.empty ( ) ) {
			return {};
		}
		return result;
	}

	auto Parser::get_all_sections_data ( ) const -> ExecutableSectionData {
		ExecutableSectionData result;

		for ( const auto& section : pe_info_.section_headers ) {
			std::string name { reinterpret_cast< const char* >( section.name.data ( ) ),8 };
			name = name.substr ( 0, name.find ( '\0' ) );
			size_t start = section.pointer_to_raw_data;
			result.emplace_back (
				name,
				std::vector<uint8_t> ( buffer_.begin ( ) + start,
				buffer_.begin ( ) + start + section.size_of_raw_data ),
				get_image_base ( ) + section.virtual_address,
				static_cast< bool >( section.characteristics & scn_mem_execute )
			);
		}

		if ( result.empty ( ) ) {
			return {};
		}
		return result;
	}

	auto Parser::get_import_directory ( ) const -> ImportDirectoryData {
		const auto& import_dir = pe_info_.data_directories [ 1 ];
		if ( import_dir.virtual_address == 0 ) {
			return {};
		}

		ImportDirectoryData result;
		size_t offset = rva_to_offset ( import_dir.virtual_address );
		if ( !offset ) {
			return {};
		}

		for ( size_t current_offset = offset; current_offset + sizeof ( ImportDirectory ) <= buffer_.size ( ); current_offset += sizeof ( ImportDirectory ) ) {
			auto import = read_struct<ImportDirectory> ( buffer_, current_offset );
			if ( import.import_lookup_table_rva == 0 ) break;

			auto name_offset = rva_to_offset ( import.name_rva );
			if ( !offset ) {
				break;
			}

			auto name_start = buffer_.begin ( ) + name_offset;
			auto name_end = std::find ( name_start, buffer_.end ( ), 0 );
			std::string dll_name { name_start,name_end };

			std::vector<ImportEntry> entries;
			size_t lookup_offset = rva_to_offset ( import.import_lookup_table_rva );
			uint32_t iat_base_rva = import.import_address_table_rva;
			size_t index = 0;

			while ( true ) {
				auto entry = read_struct<ImportLookupEntry64> ( buffer_, lookup_offset );
				if ( entry.data == 0 ) break;

				// Calculate the thunk RVA as the IAT entry's address
				uint64_t thunk_rva = iat_base_rva + index * sizeof ( uint64_t );

				if ( entry.data & ( 1ULL << 63 ) ) {
					// Ordinal import
					entries.emplace_back ( static_cast< uint16_t >( entry.data & 0xFFFF ), std::nullopt, thunk_rva );
				}
				else {
					// Name import
					size_t name_offset = rva_to_offset ( entry.data & 0x7FFFFFFF ) + 2;
					auto _name_start = buffer_.begin ( ) + name_offset;
					auto _name_end = std::find ( _name_start, buffer_.end ( ), 0 );
					std::string name { _name_start,_name_end };
					entries.emplace_back ( static_cast< uint16_t >( 0 ), std::move ( name ), thunk_rva );
				}
				lookup_offset += sizeof ( ImportLookupEntry64 );
				index++;
			}
			result.emplace_back ( std::move ( dll_name ), std::move ( entries ) );
		}
		return result;
	}

	auto Parser::get_relocation_directory ( ) const -> RelocationDirectoryData {
		const auto& reloc_dir = pe_info_.data_directories [ 5 ];
		if ( reloc_dir.virtual_address == 0 ) {
			return {};
		}

		RelocationDirectoryData result;
		size_t offset = rva_to_offset ( reloc_dir.virtual_address );
		size_t current_offset = offset;

		while ( current_offset < offset + reloc_dir.size ) {
			auto block = read_struct<BaseRelocationBlock> ( buffer_, current_offset );
			uint32_t entry_count = ( block.size_of_block - 8 ) / 2;
			std::vector<RelocationEntry> entries;
			entries.reserve ( entry_count );

			for ( uint32_t i : std::views::iota ( 0u, entry_count ) ) {
				auto entry = read_struct<BaseRelocationEntry> (
					buffer_, current_offset + 8 + i * sizeof ( BaseRelocationEntry ) );
				entries.emplace_back ( static_cast< uint16_t > ( ( entry.offset >> 12 ) & 0xF ), static_cast< uint16_t > ( entry.offset & 0xFFF ) );
			}
			result.emplace_back ( block.virtual_address, std::move ( entries ) );
			current_offset += block.size_of_block;
		}
		return result;
	}

	auto Parser::resolve_chained_function ( uint64_t base_offset, RuntimeFunction func ) const -> RuntimeFunction {
		if ( !func.unwind_info_address ) {
			return func;
		}

		try {
			auto unwind_info = read_struct<UnwindInfo> (
					buffer_, rva_to_offset ( func.unwind_info_address ) );

			if ( ( unwind_info.flags & 0x4 ) != 0 ) { // UNW_FLAG_CHAININFO
				uint32_t index = unwind_info.count_of_codes;
				if ( ( index & 1 ) != 0 ) {
					index += 1;
				}

				uint64_t chain_offset = rva_to_offset ( func.unwind_info_address ) +
					offsetof ( UnwindInfo, unwind_code ) +
					( index * sizeof ( UnwindCode ) );

				auto chain_func = read_struct<RuntimeFunction> ( buffer_, chain_offset );
				return resolve_chained_function ( base_offset, chain_func );
			}
		}
		catch ( ... ) {
			return func;
		}

		return func;
	}

	auto Parser::get_exception_directory ( ) const -> ExceptionDirectoryData {
		const auto& exception_dir = pe_info_.data_directories [ 3 ];
		if ( exception_dir.virtual_address == 0 ) {
			return {};
		}

		ExceptionDirectoryData result;
		size_t offset = rva_to_offset ( exception_dir.virtual_address );
		if ( !offset ) {
			return {};
		}
		uint32_t entry_count = exception_dir.size / sizeof ( RuntimeFunction );
		result.reserve ( entry_count );

		for ( uint32_t i : std::views::iota ( 0u, entry_count ) ) {
			auto func = read_struct<RuntimeFunction> (
					buffer_, offset + i * sizeof ( RuntimeFunction ) );

			auto resolved_func = resolve_chained_function ( offset, func );
			std::optional<UnwindInfo> unwind_info;
			if ( resolved_func.unwind_info_address ) {
				try {
					unwind_info = read_struct<UnwindInfo> (
							buffer_, rva_to_offset ( resolved_func.unwind_info_address ) );
				}
				catch ( ... ) {
					unwind_info = std::nullopt;
				}
			}

			result.emplace_back ( resolved_func, unwind_info );
		}
		return result;
	}

	auto Parser::get_tls_directory ( ) const -> TlsDirectoryData {
		const auto& tls_dir = pe_info_.data_directories [ 9 ];
		if ( tls_dir.virtual_address == 0 ) {
			return {};
		}

		size_t offset = rva_to_offset ( tls_dir.virtual_address );
		auto tls = read_struct<TlsDirectory64> ( buffer_, offset );
		std::vector<uint64_t> callbacks;

		if ( tls.address_of_callbacks ) {
			size_t callback_offset = rva_to_offset (
				static_cast< uint32_t >( tls.address_of_callbacks ) );

			for ( size_t current_offset = callback_offset; ;
						current_offset += sizeof ( uint64_t ) ) {
				uint64_t callback = read_struct<uint64_t> ( buffer_, current_offset );
				if ( callback == 0 ) break;
				callbacks.push_back ( callback );
			}
		}
		return { tls,std::move ( callbacks ) };
	}

	auto Parser::get_debug_directory ( ) const -> DebugDirectoryData {
		const auto& debug_dir = pe_info_.data_directories [ 6 ];
		if ( debug_dir.virtual_address == 0 ) {
			return {};
		}

		DebugDirectoryData result;
		size_t offset = rva_to_offset ( debug_dir.virtual_address );
		uint32_t entry_count = debug_dir.size / sizeof ( DebugDirectory );
		result.reserve ( entry_count );

		for ( uint32_t i : std::views::iota ( 0u, entry_count ) ) {
			auto entry = read_struct<DebugDirectory> (
				buffer_, offset + i * sizeof ( DebugDirectory ) );
			std::optional<std::vector<uint8_t>> debug_data;

			if ( entry.pointer_to_raw_data && entry.size_of_data ) {
				size_t start = entry.pointer_to_raw_data;
				debug_data = std::vector<uint8_t> (
					buffer_.begin ( ) + start,
					buffer_.begin ( ) + start + entry.size_of_data );
			}
			result.emplace_back ( entry, std::move ( debug_data ) );
		}
		return result;
	}

	auto Parser::get_export_directory ( ) const -> ExportDirectoryData {
		const auto& export_dir = pe_info_.data_directories [ 0 ];
		if ( export_dir.virtual_address == 0 ) {
			return {};
		}

		size_t offset = rva_to_offset ( export_dir.virtual_address );
		auto export_table = read_struct<ExportDirectory> ( buffer_, offset );

		std::string dll_name;
		if ( export_table.name_rva ) {
			auto name_start = buffer_.begin ( ) + rva_to_offset ( export_table.name_rva );
			auto name_end = std::find ( name_start, buffer_.end ( ), 0 );
			dll_name = std::string ( name_start, name_end );
		}

		std::vector<ExportEntry> entries;
		entries.reserve ( export_table.number_of_names );

		auto functions_offset = rva_to_offset ( export_table.address_of_functions );
		auto names_offset = rva_to_offset ( export_table.address_of_names );
		auto ordinals_offset = rva_to_offset ( export_table.address_of_name_ordinals );

		for ( uint32_t i = 0; i < export_table.number_of_names; ++i ) {
			uint32_t name_rva = read_struct<uint32_t> ( buffer_, names_offset + i * sizeof ( uint32_t ) );
			uint16_t ordinal = read_struct<uint16_t> ( buffer_, ordinals_offset + i * sizeof ( uint16_t ) );
			uint32_t function_rva = read_struct<uint32_t> ( buffer_, functions_offset + ordinal * sizeof ( uint32_t ) );

			std::string name;
			if ( name_rva ) {
				auto name_start = buffer_.begin ( ) + rva_to_offset ( name_rva );
				auto name_end = std::find ( name_start, buffer_.end ( ), 0 );
				name = std::string ( name_start, name_end );
			}

			std::optional<uint16_t> forwarder_ordinal;
			if ( function_rva >= export_dir.virtual_address &&
					function_rva < export_dir.virtual_address + export_dir.size ) {
				forwarder_ordinal = ordinal;
			}

			entries.emplace_back (
					std::move ( name ),
					ordinal + export_table.base,
					forwarder_ordinal,
					function_rva ? get_image_base ( ) + function_rva : 0
			);
		}

		return { export_table,std::move ( entries ) };
	}

	auto Parser::chase_entry_point ( const std::vector<uint8_t>& text, uint64_t image_base, size_t initial_offset ) const->std::vector<capstone::Instruction> {
		size_t offset = initial_offset;
		capstone::Decoder decoder { text.data ( ) + offset,text.size ( ) - offset,image_base + offset };
		std::vector<capstone::Instruction> instrs;

		for ( int i = 0; i < 5 && decoder.can_decode ( ); ++i ) {
			auto instr = decoder.decode ( );
			if ( !instr.is_valid ( ) ) break;
			auto should_stop = instr.is_call ( ) || instr.is_return ( );
			instrs.push_back ( std::move ( instr ) );
			if ( should_stop ) break;
		}

		return instrs;
	}

	auto Parser::try_detect_compiler ( ) const->std::string {
		auto text = get_text_section_data ( );
		size_t ep_offset = rva_to_offset ( pe_info_.optional_header.address_of_entry_point );
		if ( ep_offset + 32 > text.size ( ) ) {
			return "Unknown"; // Too short
		}

		uint64_t image_base = get_image_base ( );
		auto instrs = chase_entry_point ( text, image_base, ep_offset );
		if ( instrs.empty ( ) ) return "Unknown";

		auto sections = get_all_sections_data ( );
		bool has_pdata = std::ranges::any_of ( sections, [ ] ( const auto& s )
		{
			return std::get<0> ( s ) == ".pdata";
		} );
		bool has_rodata = std::ranges::any_of ( sections, [ ] ( const auto& s )
		{
			return std::get<0> ( s ) == ".rodata";
		} );

		// MSVC: push rbp; mov rbp, rsp + call (likely __security_init_cookie)
		if ( instrs.size ( ) >= 3 &&
				instrs [ 0 ].mnemonic ( ) == X86_INS_PUSH &&
				instrs [ 0 ].operands ( ) [ 0 ].reg == X86_REG_RBP &&
				instrs [ 1 ].mnemonic ( ) == X86_INS_MOV &&
				instrs [ 1 ].operands ( ) [ 0 ].reg == X86_REG_RBP &&
				instrs [ 1 ].operands ( ) [ 1 ].reg == X86_REG_RSP &&
				instrs [ 2 ].is_call ( ) ) {
			if ( has_pdata ) return "MSVC";
			if ( !has_rodata ) return "MSVC";
		}

		// GCC: push rbp; mov rbp, rsp + call (likely _pei386_runtime_relocator)
		if ( instrs.size ( ) >= 3 &&
				instrs [ 0 ].mnemonic ( ) == X86_INS_PUSH &&
				instrs [ 0 ].operands ( ) [ 0 ].reg == X86_REG_RBP &&
				instrs [ 1 ].mnemonic ( ) == X86_INS_MOV &&
				instrs [ 1 ].operands ( ) [ 0 ].reg == X86_REG_RBP &&
				instrs [ 1 ].operands ( ) [ 1 ].reg == X86_REG_RSP &&
				instrs [ 2 ].is_call ( ) ) {
			if ( has_rodata ) return "GCC";
			if ( !has_pdata ) return "GCC";
		}

		// Clang: sub rsp, xx + call (likely __main)
		if ( instrs.size ( ) >= 2 &&
				instrs [ 0 ].mnemonic ( ) == X86_INS_SUB &&
				instrs [ 0 ].operands ( ) [ 0 ].reg == X86_REG_RSP &&
				instrs [ 1 ].is_call ( ) ) {
			if ( !has_pdata ) return "Clang";
			if ( has_rodata ) return "Clang";
		}

		// Fallback: Prologue only
		if ( instrs [ 0 ].mnemonic ( ) == X86_INS_PUSH &&
				instrs [ 0 ].operands ( ) [ 0 ].reg == X86_REG_RBP &&
				instrs.size ( ) > 1 &&
				instrs [ 1 ].mnemonic ( ) == X86_INS_MOV &&
				instrs [ 1 ].operands ( ) [ 0 ].reg == X86_REG_RBP &&
				instrs [ 1 ].operands ( ) [ 1 ].reg == X86_REG_RSP ) {
			if ( has_pdata ) return "MSVC";
			if ( has_rodata ) return "GCC";
			return "GCC"; // Default to GCC
		}
		if ( instrs [ 0 ].mnemonic ( ) == X86_INS_SUB &&
				instrs [ 0 ].operands ( ) [ 0 ].reg == X86_REG_RSP ) {
			return "Clang";
		}

		if ( instrs [ 0 ].mnemonic ( ) == X86_INS_SUB ) {
			if ( instrs.size ( ) >= 4 ) {
				if ( instrs [ 1 ].mnemonic ( ) == X86_INS_CALL && instrs [ 2 ].mnemonic ( ) == X86_INS_ADD && instrs [ 3 ].mnemonic ( ) == X86_INS_JMP ) {
					return "MSVC";
				}
			}
		}

		return "Unknown";
	}
	auto Parser::section_name_for_address ( uint64_t address ) const -> std::string {
		for ( const auto& section : pe_info_.section_headers ) {
			std::string name { reinterpret_cast< const char* >( section.name.data ( ) ),8 };
			name = name.substr ( 0, name.find ( '\0' ) );
			size_t start = get_image_base ( ) + section.virtual_address;
			size_t end = section.size_of_raw_data + start;
			if ( address >= start && address <= end ) {
				return name;
			}
		}
		return std::string ( );
	}
	auto Parser::override_base_address ( uint64_t address ) -> void {
		override_base_address_ = address;
	}
	auto Parser::override_entry_point ( uint64_t address ) -> void {
		override_entry_point_ = address;
	}

	auto Parser::get_pdb_path ( ) const -> std::optional<std::string> {
		auto debug_data = get_debug_directory ( );
		for ( const auto& [entry, data] : debug_data ) {
			if ( entry.type_ == 2 ) { // IMAGE_DEBUG_TYPE_CODEVIEW
				if ( !data.has_value ( ) || data->size ( ) < 4 ) {
					continue;
				}

				// Check for CV signature (RSDS or NB10)
				const uint8_t* raw_data = data->data ( );
				if ( std::memcmp ( raw_data, "RSDS", 4 ) == 0 ) {
					// RSDS format (newer PDB 7.0)
					if ( data->size ( ) < 24 ) { // Signature (4) + GUID (16) + Age (4)
						continue;
					}
					// Path starts after signature (4), GUID (16), and age (4)
					size_t path_offset = 24;
					auto path_start = raw_data + path_offset;
					auto path_end = std::find ( path_start, raw_data + data->size ( ), 0 );
					if ( path_end != raw_data + data->size ( ) ) {
						return std::string ( path_start, path_end );
					}
				}
				else if ( std::memcmp ( raw_data, "NB10", 4 ) == 0 ) {
					// NB10 format (older PDB 2.0)
					if ( data->size ( ) < 16 ) { // Signature (4) + Offset (4) + Sig (4) + Age (4)
						continue;
					}
					size_t path_offset = 16;
					auto path_start = raw_data + path_offset;
					auto path_end = std::find ( path_start, raw_data + data->size ( ), 0 );
					if ( path_end != raw_data + data->size ( ) ) {
						return std::string ( path_start, path_end );
					}
				}
			}
		}
		return std::nullopt;
	}

	auto Parser::get_pdb_url ( ) const -> std::optional<std::string> {
		auto debug_data = get_debug_directory ( );
		for ( const auto& [entry, data_opt] : debug_data ) {
			if ( entry.type_ != 2 || !data_opt.has_value ( ) ) { // IMAGE_DEBUG_TYPE_CODEVIEW
				continue;
			}

			const auto& data = *data_opt;
			if ( data.size ( ) < 4 ) {
				continue;
			}

			uint32_t signature = read_struct<uint32_t> ( data, 0 );
			if ( signature == 0x53445352 ) { // 'RSDS'
				if ( data.size ( ) < sizeof ( CV_INFO_PDB70 ) ) {
					continue;
				}

				auto cv_info = read_struct<CV_INFO_PDB70> ( data, 0 );
				size_t name_offset = sizeof ( CV_INFO_PDB70 ) - 1;
				auto name_end = std::find ( data.begin ( ) + name_offset, data.end ( ), 0 );
				if ( name_end == data.end ( ) ) {
					continue;
				}

				std::string pdb_name ( data.begin ( ) + name_offset, name_end );
				std::string pdb_filename = pdb_name.substr ( pdb_name.find_last_of ( "\\/" ) + 1 );

				char guid_str [ 33 ];
				snprintf ( guid_str, sizeof ( guid_str ), "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
								 cv_info.guid_data1, cv_info.guid_data2, cv_info.guid_data3,
								 cv_info.guid_data4 [ 0 ], cv_info.guid_data4 [ 1 ], cv_info.guid_data4 [ 2 ],
								 cv_info.guid_data4 [ 3 ], cv_info.guid_data4 [ 4 ], cv_info.guid_data4 [ 5 ],
								 cv_info.guid_data4 [ 6 ], cv_info.guid_data4 [ 7 ] );
				std::string guid_upper = guid_str;

				return std::format (
					"https://msdl.microsoft.com/download/symbols/{}/{}{}/{}",
					pdb_filename,
					guid_upper,
					cv_info.age,
					pdb_filename
				);
			}
			else if ( signature == 0x3031424E ) { // 'NB10'
				if ( data.size ( ) < sizeof ( CV_INFO_PDB20 ) ) {
					continue;
				}

				auto cv_info = read_struct<CV_INFO_PDB20> ( data, 0 );
				size_t name_offset = sizeof ( CV_INFO_PDB20 ) - 1; // -1 for pdb_name[1]
				auto name_end = std::find ( data.begin ( ) + name_offset, data.end ( ), 0 );
				if ( name_end == data.end ( ) ) {
					continue;
				}

				std::string pdb_name ( data.begin ( ) + name_offset, name_end );
				std::string pdb_filename = pdb_name.substr ( pdb_name.find_last_of ( "\\/" ) + 1 );

				char guid_str [ 9 ];
				snprintf ( guid_str, sizeof ( guid_str ), "%08X", cv_info.signature );
				std::string guid_upper = guid_str;

				return std::format (
					"https://msdl.microsoft.com/download/symbols/{}/{}{}/{}",
					pdb_filename,
					guid_upper,
					cv_info.age,
					pdb_filename
				);
			}
		}
		return std::nullopt;
	}

	auto Parser::get_imports ( ) const -> std::map<std::string, std::map<std::string, uint64_t>> {
		std::map<std::string, std::map<std::string, uint64_t>> result;
		auto import_dir = get_import_directory ( );

		for ( const auto& [dll_name, entries] : import_dir ) {
			std::map<std::string, uint64_t> func_map;
			for ( const auto& [ordinal, opt_name, thunk_rva] : entries ) {
				std::string func_name;
				if ( opt_name.has_value ( ) ) {
					func_name = opt_name.value ( );
				}
				else {
					func_name = std::format ( "Ordinal_{}", ordinal ); // Fallback for ordinal-only imports
				}
				uint64_t iat_addr = get_image_base ( ) + thunk_rva;
				func_map [ func_name ] = iat_addr;

				std::print ( "Mapping {}!{} to {:016x}h\n", dll_name, func_name, iat_addr );
			}
			result [ dll_name ] = std::move ( func_map );
		}

		return result;
	}

	auto Parser::fix_security_cookie ( ) -> void {
		__debugbreak ( );
	}

	bool Parser::is_address_in_iat ( uint64_t va ) const {
		uint64_t image_base = get_image_base ( );
		uint64_t rva = va - image_base;

		// Get Import Directory Table info
		IMAGE_DATA_DIRECTORY* import_dir = ( IMAGE_DATA_DIRECTORY* ) &pe_info_.optional_header.data_directories [ IMAGE_DIRECTORY_ENTRY_IMPORT ];
		if ( import_dir->VirtualAddress == 0 || import_dir->Size == 0 ) {
			return false;
		}

		size_t import_desc_offset = rva_to_offset ( import_dir->VirtualAddress );
		auto import_descriptor = reinterpret_cast< const IMAGE_IMPORT_DESCRIPTOR* >( buffer_.data ( ) + import_desc_offset );

		// Iterate through import descriptors
		while ( import_descriptor->Characteristics != 0 ) {
			uint32_t iat_rva = import_descriptor->FirstThunk; // OriginalFirstThunk for INT
			if ( iat_rva == 0 ) continue; // Skip if no IAT

			// We need the *size* of the IAT for this descriptor.
			// This is tricky, as the size isn't directly in the descriptor.
			// We infer it by finding the end marker (null QWORD).
			size_t iat_offset = rva_to_offset ( iat_rva );
			uint64_t current_iat_entry_rva = iat_rva;
			size_t current_iat_offset = iat_offset;

			while ( true ) {
				// Boundary check for reading QWORD
				if ( current_iat_offset + sizeof ( uint64_t ) > buffer_.size ( ) ) {
					// Or throw an exception / log error
					break;
				}
				uint64_t entry_value = *reinterpret_cast< const uint64_t* >( buffer_.data ( ) + current_iat_offset );
				if ( entry_value == 0 ) {
					break; // End of this IAT
				}

				// Check if the target RVA falls within this specific entry's address
				if ( rva == current_iat_entry_rva ) {
					return true;
				}

				current_iat_entry_rva += sizeof ( uint64_t );
				current_iat_offset += sizeof ( uint64_t );
			}
			// If we reach here, 'rva' wasn't found in this specific IAT.
			// Move to the next import descriptor.
			import_descriptor++;
		}

		return false; // Not found in any IAT
	}

	uint64_t Parser::read_qword_at_rva ( uint64_t rva ) const {
		size_t offset = rva_to_offset ( static_cast< uint32_t >( rva ) ); // This throws if RVA is invalid or out of section bounds
		if ( offset + sizeof ( uint64_t ) > buffer_.size ( ) ) {
			throw std::out_of_range ( std::format ( "RVA 0x{:x} read (offset 0x{:x}) exceeds PE buffer bounds (size 0x{:x})", rva, offset, buffer_.size ( ) ) );
		}
		return *reinterpret_cast< const uint64_t* >( buffer_.data ( ) + offset );
	}
}
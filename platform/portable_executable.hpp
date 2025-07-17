#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <fstream>
#include <stdexcept>
#include <optional>
#include <tuple>
#include <ranges>
#include <span>

// Packed structures using #pragma pack
#pragma pack(push, 1)

struct DosHeader {
	uint16_t e_magic;       // Magic number "MZ" (0x5A4D)
	uint16_t e_cblp;        // Bytes on last page of file
	uint16_t e_cp;          // Pages in file
	uint16_t e_crlc;        // Relocations
	uint16_t e_cparhdr;     // Size of header in paragraphs
	uint16_t e_minalloc;    // Minimum extra paragraphs needed
	uint16_t e_maxalloc;    // Maximum extra paragraphs needed
	uint16_t e_ss;          // Initial (relative) SS value
	uint16_t e_sp;          // Initial SP value
	uint16_t e_csum;        // Checksum
	uint16_t e_ip;          // Initial IP value
	uint16_t e_cs;          // Initial (relative) CS value
	uint16_t e_lfarlc;      // File address of relocation table
	uint16_t e_ovno;        // Overlay number
	std::array<uint16_t, 4> e_res;    // Reserved words
	uint16_t e_oemid;       // OEM identifier
	uint16_t e_oeminfo;     // OEM information
	std::array<uint16_t, 10> e_res2;  // Reserved words
	uint32_t e_lfanew;      // File address of new exe header (PE header)
};

struct FileHeader {
	uint16_t machine;              // Target machine (0x8664 for x64)
	uint16_t number_of_sections;   // Number of sections
	uint32_t time_date_stamp;      // Timestamp
	uint32_t pointer_to_symbol_table; // File offset of symbol table (or 0)
	uint32_t number_of_symbols;    // Number of symbols
	uint16_t size_of_optional_header; // Size of optional header
	uint16_t characteristics;      // Flags (executable, DLL, etc.)
};

struct DataDirectory {
	uint32_t virtual_address;
	uint32_t size;
};

struct OptionalHeader {
	uint16_t magic;                // 0x20b for PE32+ (64-bit)
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t address_of_entry_point;
	uint32_t base_of_code;
	uint64_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_os_version;
	uint16_t minor_os_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t checksum;
	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint64_t size_of_stack_reserve;
	uint64_t size_of_stack_commit;
	uint64_t size_of_heap_reserve;
	uint64_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	std::array<DataDirectory, 16> data_directories;
};

struct SectionHeader {
	std::array<uint8_t, 8> name;
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t size_of_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_to_relocations;
	uint32_t pointer_to_line_numbers;
	uint16_t number_of_relocations;
	uint16_t number_of_line_numbers;
	uint32_t characteristics;
};

struct ImportDirectory {
	uint32_t import_lookup_table_rva;
	uint32_t time_date_stamp;
	uint32_t forwarder_chain;
	uint32_t name_rva;
	uint32_t import_address_table_rva;
};

struct ImportLookupEntry64 {
	uint64_t data;
};

struct BaseRelocationBlock {
	uint32_t virtual_address;
	uint32_t size_of_block;
};

struct BaseRelocationEntry {
	uint16_t offset;
};

struct RuntimeFunction {
	uint32_t begin_address;
	uint32_t end_address;
	uint32_t unwind_info_address;
};

struct UnwindCode {
	union {
		struct {
			uint8_t code_offset;
			uint8_t unwind_opcode : 4;
			uint8_t opcode_info : 4;

		} s;

		uint16_t FrameOffset;
		uint16_t Value;
	} u;
};

struct UnwindInfo {
	uint8_t version : 3;
	uint8_t flags : 5;
	uint8_t size_of_prolog;
	uint8_t count_of_codes;
	uint8_t frame_register : 4;
	uint8_t frame_offset : 4;
	UnwindCode unwind_code [ 1 ];
};

struct TlsDirectory64 {
	uint64_t start_address_of_raw_data;
	uint64_t end_address_of_raw_data;
	uint64_t address_of_index;
	uint64_t address_of_callbacks;
	uint32_t size_of_zero_fill;
	uint32_t characteristics;
};

struct DebugDirectory {
	uint32_t characteristics;
	uint32_t time_date_stamp;
	uint16_t major_version;
	uint16_t minor_version;
	uint32_t type_;
	uint32_t size_of_data;
	uint32_t address_of_raw_data;
	uint32_t pointer_to_raw_data;
};

struct CV_INFO_PDB70 { // RSDS format (PDB 7.0)
	uint32_t cv_signature; // 'RSDS' (0x53445352)
	uint32_t guid_data1;   // First part of GUID
	uint16_t guid_data2;   // Second part of GUID
	uint16_t guid_data3;   // Third part of GUID
	uint8_t  guid_data4 [ 8 ]; // Fourth part of GUID (8 bytes)
	uint32_t age;          // Age of the PDB
	char     pdb_name [ 1 ];  // Null-terminated PDB filename (variable length)
};

struct CV_INFO_PDB20 { // NB10 format (PDB 2.0)
	uint32_t cv_signature; // 'NB10' (0x3031424E)
	uint32_t offset;       // Offset (usually 0)
	uint32_t signature;    // Timestamp/Signature
	uint32_t age;          // Age of the PDB
	char     pdb_name [ 1 ];  // Null-terminated PDB filename (variable length)
};

struct ExportDirectory {
	uint32_t characteristics;
	uint32_t time_date_stamp;
	uint16_t major_version;
	uint16_t minor_version;
	uint32_t name_rva;
	uint32_t base;
	uint32_t number_of_functions;
	uint32_t number_of_names;
	uint32_t address_of_functions;
	uint32_t address_of_names;
	uint32_t address_of_name_ordinals;
};

struct TypeDescriptor {
	uint64_t pVFTable;          // Pointer to vtable (usually points to type_info's vtable)
	uint64_t spare;            // Unused (padding or reserved)
	char name [ 1 ];              // Null-terminated type name (variable length)
};

struct BaseClassDescriptor {
	uint32_t type_descriptor_rva; // RVA to TypeDescriptor
	uint32_t num_contained_bases; // Number of bases in the hierarchy
	uint32_t mdisp;              // Member displacement
	uint32_t pdisp;              // VBase displacement
	uint32_t vdisp;              // Displacement inside vbase
	uint32_t attributes;         // Flags (e.g., virtual inheritance)
};

struct ClassHierarchyDescriptor {
	uint32_t signature;          // Always 1 for MSVC RTTI
	uint32_t attributes;         // Flags (e.g., multiple inheritance)
	uint32_t num_base_classes;   // Number of base classes
	uint32_t base_class_array_rva; // RVA to array of BaseClassDescriptor RVAs
};

#pragma pack(pop)

// Aligned versions
struct DosHeaderAligned {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint32_t e_lfanew;
};

struct FileHeaderAligned {
	uint16_t machine;
	uint16_t number_of_sections;
	uint32_t time_date_stamp;
	uint32_t pointer_to_symbol_table;
	uint32_t number_of_symbols;
	uint16_t size_of_optional_header;
	uint16_t characteristics;
};

struct DataDirectoryAligned {
	uint32_t virtual_address;
	uint32_t size;
};

struct OptionalHeaderAligned {
	uint16_t magic;
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t address_of_entry_point;
	uint32_t base_of_code;
	uint64_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_os_version;
	uint16_t minor_os_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t checksum;
	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint64_t size_of_stack_reserve;
	uint64_t size_of_stack_commit;
	uint64_t size_of_heap_reserve;
	uint64_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	std::vector<DataDirectoryAligned> data_directories;
};

struct SectionHeaderAligned {
	std::array<uint8_t, 8> name;
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t size_of_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_to_relocations;
	uint32_t pointer_to_line_numbers;
	uint16_t number_of_relocations;
	uint16_t number_of_line_numbers;
	uint32_t characteristics;
};

struct PEInfoAligned {
	DosHeader dos_header;
	FileHeader file_header;
	OptionalHeader optional_header;
	std::vector<SectionHeader> section_headers;
	std::vector<DataDirectory> data_directories;
};

namespace PE
{
	constexpr uint32_t scn_mem_execute = 0x20000000;

	using ExecutableSectionData = std::vector<std::tuple<std::string, std::vector<uint8_t>, uint64_t, bool>>;
	using ImportEntry = std::tuple<uint32_t, std::optional<std::string>, uint64_t>;
	using ImportDirectoryData = std::vector<std::pair<std::string, std::vector<ImportEntry>>>;
	using RelocationEntry = std::pair<uint16_t, uint16_t>;
	using RelocationDirectoryData = std::vector<std::pair<uint32_t, std::vector<RelocationEntry>>>;
	using ExceptionEntry = std::pair<RuntimeFunction, std::optional<UnwindInfo>>;
	using ExceptionDirectoryData = std::vector<ExceptionEntry>;
	using TlsDirectoryData = std::pair<TlsDirectory64, std::vector<uint64_t>>;
	using DebugEntry = std::pair<DebugDirectory, std::optional<std::vector<uint8_t>>>;
	using DebugDirectoryData = std::vector<DebugEntry>;
	using ExportEntry = std::tuple<std::string, uint32_t, std::optional<uint16_t>, uint64_t>; // name, ordinal, hint, rva
	using ExportDirectoryData = std::pair<ExportDirectory, std::vector<ExportEntry>>;

	class Parser {
	public:
		std::vector<uint8_t> buffer_;
		uint64_t override_base_address_ = 0;
		uint64_t override_entry_point_ = 0;

		auto rva_to_offset ( uint32_t rva ) const->size_t;

		template<typename T>
		static auto read_struct ( std::span<const uint8_t> data, size_t offset ) -> T;

		static auto parse ( std::span<const uint8_t> buffer ) -> PEInfoAligned;

		auto resolve_chained_function ( uint64_t base_offset, RuntimeFunction func ) const->RuntimeFunction;
		explicit Parser ( std::string_view file_path );
		explicit Parser ( std::string_view file_path, bool dummy_no_parser );
		explicit Parser ( const std::vector<uint8_t>& file_path );

		[[nodiscard]] auto get_section_data ( std::string_view section_name ) const->std::vector<uint8_t>;
		[[nodiscard]] auto get_entry_point ( ) const noexcept -> uint64_t;
		[[nodiscard]] auto get_text_section_data ( ) const->std::vector<uint8_t>;
		[[nodiscard]] auto get_image_base ( ) const noexcept -> uint64_t;
		[[nodiscard]] auto get_executable_sections_data ( ) const->ExecutableSectionData;
		[[nodiscard]] auto get_all_sections_data ( ) const->ExecutableSectionData;
		[[nodiscard]] auto get_import_directory ( ) const->ImportDirectoryData;
		[[nodiscard]] auto get_relocation_directory ( ) const->RelocationDirectoryData;
		[[nodiscard]] auto get_exception_directory ( ) const->ExceptionDirectoryData;
		[[nodiscard]] auto get_tls_directory ( ) const->TlsDirectoryData;
		[[nodiscard]] auto get_debug_directory ( ) const->DebugDirectoryData;
		[[nodiscard]] auto get_export_directory ( ) const->ExportDirectoryData;
		[[nodiscard]] auto section_name_for_address ( uint64_t address ) const->std::string;
		[[nodiscard]] auto get_pdb_path ( ) const->std::optional<std::string>;
		[[nodiscard]] auto get_pdb_url ( ) const->std::optional<std::string>;
		auto override_base_address ( uint64_t address ) -> void;
		auto override_entry_point ( uint64_t address ) -> void;

		PEInfoAligned pe_info_;
	};
}
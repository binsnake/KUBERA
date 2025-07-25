#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>
#include <print>

#include <linuxpe/includes/linuxpe>
#include <context/memory.hpp>

class ModuleManager {
	struct Module {
		std::string name;
		uint64_t base;
		std::size_t size;
		std::unordered_map<std::string, uint64_t> exports;
		std::unordered_map<uint16_t, uint64_t> exports_by_ordinal;
	};

	kubera::VirtualMemory* vm;
	std::vector<Module> modules;
	std::vector<std::string> search_paths { "","C:\\Windows\\System32\\" };

	uint64_t get_module_base ( const std::string& mod ) {
		std::string lower = mod;
		std::transform ( lower.begin ( ), lower.end ( ), lower.begin ( ), ::tolower );
		for ( const auto& m : modules ) {
			std::string n = m.name;
			std::transform ( n.begin ( ), n.end ( ), n.begin ( ), ::tolower );
			if ( n == lower ) return m.base;
		}
		return 0;
	}

	uint64_t get_export_address ( const std::string& mod, const std::string& func,
															uint16_t ord = 0, bool by_ord = false ) {
		uint64_t base = get_module_base ( mod );
		if ( !base ) {
			return 0;
		}
		for ( const auto& m : modules ) {
			if ( m.base != base ) continue;
			if ( by_ord ) {
				auto it = m.exports_by_ordinal.find ( ord );
				if ( it != m.exports_by_ordinal.end ( ) ) return it->second;
			}
			else {
				auto it = m.exports.find ( func );
				if ( it != m.exports.end ( ) ) return it->second;
			}
			break;
		}
		return 0;
	}

	void resolve_relocations ( win::image_x64_t* img, win::nt_headers_x64_t* nt,
													 int64_t delta ) {
		std::println ( "Resolving relocations..." );
		auto* dir = img->get_directory ( win::directory_entry_basereloc );
		if ( !dir->present ( ) ) {
			std::println ( "\tImage has no relocations!" );
			return;
		}
		auto* rel = &img->rva_to_ptr<win::reloc_directory_t> ( dir->rva )->first_block;
		std::size_t processed = 0u;
		while ( processed < dir->size ) {
			auto num = rel->num_entries ( );
			auto entry = rel->begin ( );
			for ( std::size_t i = 0; i < num; ++i, ++entry ) {
				auto type = entry->type;
				auto shift = entry->offset % 0xFFF;
				if ( type == 0 ) continue;
				if ( type == 3 || type == 10 ) {
					auto fix = img->rva_to_ptr<std::uint8_t> ( rel->base_rva );
					if ( !fix ) fix = reinterpret_cast< std::uint8_t* > ( img );
					*reinterpret_cast< uint64_t* > ( fix + shift ) += delta;
				}
			}
			processed += rel->size_block;
			rel = rel->next ( );
		}
		std::println ( "\tResolved {} relocations!", processed / sizeof ( win::reloc_entry_t ) );
	}

public:
	explicit ModuleManager ( kubera::VirtualMemory* mem ) : vm ( mem ) { }

	Module get_module_by_address ( uint64_t address ) const {
		for ( const auto& mod : modules ) {
			if ( address >= mod.base && address < ( mod.base + mod.size ) ) {
				return mod;
			}
		}
		return {};
	}	
	
	std::string get_module_name_by_address ( uint64_t address ) const {
		for ( const auto& mod : modules ) {
			if ( address >= mod.base && address < ( mod.base + mod.size ) ) {
				return mod.name;
			}
		}
		return "";
	}

	uint64_t get_module_base_public ( const std::string& mod ) {
		return get_module_base ( mod );
	}

	uint64_t get_export_address_public ( const std::string& mod, const std::string& func, uint16_t ord = 0, bool by_ord = false ) {
		return get_export_address ( mod, func, ord, by_ord );
	}

	uint64_t get_entry_point ( const std::string& mod ) {
		auto vm_base = get_module_base ( mod );
		auto mod_base = reinterpret_cast< win::image_x64_t* >( vm->translate ( vm_base, kubera::PageProtection::READ ) );
		return vm_base + mod_base->get_nt_headers ( )->optional_header.entry_point;
	}

	const std::unordered_map<std::string, uint64_t>* get_exports_public ( const std::string& mod ) const {
		std::string lower = mod;
		std::transform ( lower.begin ( ), lower.end ( ), lower.begin ( ), ::tolower );
		for ( const auto& m : modules ) {
			std::string n = m.name;
			std::transform ( n.begin ( ), n.end ( ), n.begin ( ), ::tolower );
			if ( n == lower ) return &m.exports;
		}
		return nullptr;
	}

	uint64_t load_module ( const std::string& path, uint64_t preferred_base = 0 ) {
		std::println ( "[mm] Mapping {}", path );
		using namespace kubera;
		uint64_t existing = get_module_base ( path );
		if ( existing ) {
			return existing;
		}

		std::ifstream file ( path, std::ios::binary | std::ios::ate );
		if ( !file ) {
			return 0;
		}
		std::size_t file_size = static_cast< std::size_t >( file.tellg ( ) );
		file.seekg ( 0 );
		std::vector<uint8_t> buf ( file_size );
		file.read ( reinterpret_cast< char* >( buf.data ( ) ), file_size );

		auto* image = reinterpret_cast< win::image_x64_t* >( buf.data ( ) );
		if ( image->dos_header.e_magic != 'ZM' ) {
			return 0;
		}
		auto* nt = image->get_nt_headers ( );

		if ( nt->file_header.machine != win::machine_id::amd64 ) {
			return 0;
		}
		std::size_t image_size = nt->optional_header.size_image;
		uint64_t base = 0;
		if ( preferred_base ) {
			base = vm->alloc_at ( preferred_base, image_size, PageProtection::READ | PageProtection::WRITE, 0x1000, true );
		}
		else {
			base = vm->alloc ( image_size, PageProtection::READ | PageProtection::WRITE, 0x1000, true );
		}
		int64_t delta = static_cast< int64_t >( base - nt->optional_header.image_base );

		resolve_relocations(image, nt, delta);

		vm->write_bytes(base, buf.data(), nt->optional_header.size_headers);
		vm->protect(base, nt->optional_header.size_headers, PageProtection::READ);

		for (const auto& sec : nt->sections()) {
			uint64_t sec_va = base + sec.virtual_address;
			std::size_t sec_virtual_size = sec.virtual_size ? sec.virtual_size : sec.size_raw_data;
			std::size_t sec_raw_size = sec.size_raw_data;

			if (sec_raw_size > 0) {
				vm->write_bytes (sec_va, buf.data() + sec.ptr_raw_data, sec_raw_size);
			}

			uint8_t prot;
			if (sec.characteristics.mem_execute) {
				prot = sec.characteristics.mem_write ? ( PageProtection::READ | PageProtection::WRITE | PageProtection::EXEC) : ( PageProtection::READ | PageProtection::EXEC);
			}
			else if (sec.characteristics.mem_write) {
				prot = PageProtection::READ | PageProtection::WRITE;
			}
			else {
				prot = PageProtection::READ;
			}
			vm->protect(sec_va, sec_virtual_size, prot);
		}

		Module mod { path, base, image_size };
		auto* exp_dir = image->get_directory ( win::directory_entry_export );
		if ( exp_dir && exp_dir->present ( ) ) {
			auto* exp = image->rva_to_ptr<win::export_directory_t> ( exp_dir->rva );
			auto* funcs = image->rva_to_ptr<uint32_t> ( exp->rva_functions );
			auto* names = image->rva_to_ptr<uint32_t> ( exp->rva_names );
			auto* ords = image->rva_to_ptr<uint16_t> ( exp->rva_name_ordinals );
			for ( uint32_t i = 0; i < exp->num_functions; i++ ) {
				uint32_t rva = funcs [ i ];
				if ( !rva ) continue;
				mod.exports_by_ordinal [ exp->base + i ] = base + rva;
			}
			for ( uint32_t i = 0; i < exp->num_names; i++ ) {
				auto* name_ptr = image->rva_to_ptr<char> ( names [ i ] );
				std::string name ( name_ptr );
				uint16_t ord = ords [ i ];
				mod.exports [ name ] = base + funcs [ ord ];
			}
		}
		modules.push_back ( std::move ( mod ) );
		return base;
	}
};
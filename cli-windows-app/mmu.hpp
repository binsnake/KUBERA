#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include <print>
#include <filesystem>

#include <linuxpe/includes/linuxpe>

namespace mmu
{
	constexpr size_t PAGE_SIZE = 4096;

	enum PageState {
		MEM_FREE = 0,
		MEM_RESERVE = 1,
		MEM_COMMIT = 2
	};

	enum class Protection : uint32_t {
		NOACCESS = 0x00,
		READONLY = 0x01,
		READWRITE = 0x02,
		EXECUTE = 0x04,
		EXECUTE_READ = 0x05,
		EXECUTE_READWRITE = 0x06
	};

	struct Region {
		uint64_t base;
		size_t size;
		PageState state;
		Protection protect;

		bool operator<( const Region& other ) const {
			return base < other.base;
		}
	};

	class MemoryManager {
	private:
		struct PageInfo {
			bool present = false;
			Protection protect = Protection::NOACCESS;
			char* host_ptr = nullptr;
		};

		std::unordered_map<uint64_t, PageInfo> pages;  // Key: (va >> 12)
		std::vector<Region> regions;                   // Sorted by base

		void sort_regions ( ) {
			std::sort ( regions.begin ( ), regions.end ( ) );
		}

		Region* find_region ( uint64_t va ) {
			Region temp { va, 0, MEM_FREE, Protection::NOACCESS };
			auto it = std::lower_bound ( regions.begin ( ), regions.end ( ), temp );
			if ( it != regions.begin ( ) ) {
				--it;
				if ( it->base <= va && it->base + it->size > va ) {
					return &( *it );
				}
			}
			return nullptr;
		}

		uint64_t find_free_base ( uint64_t preferred, size_t size ) {
			if ( preferred == 0 ) preferred = 0x10000000ULL;  // Arbitrary starting point for user-mode.
			uint64_t current = preferred & ~( PAGE_SIZE - 1 );
			bool found = false;
			while ( !found ) {
				found = true;
				for ( const auto& r : regions ) {
					if ( ( current < r.base + r.size ) && ( current + size > r.base ) ) {
						current = ( r.base + r.size + PAGE_SIZE - 1 ) & ~( PAGE_SIZE - 1 );
						found = false;
						break;
					}
				}
			}
			return current;
		}

	public:
		MemoryManager ( ) = default;

		~MemoryManager ( ) {
			for ( auto& p : pages ) {
				if ( p.second.host_ptr ) {
					delete [ ] p.second.host_ptr;
				}
			}
		}

		uint64_t reserve ( uint64_t addr, size_t size, Protection prot ) {
			size = ( ( size + PAGE_SIZE - 1 ) / PAGE_SIZE ) * PAGE_SIZE;
			if ( addr == 0 ) {
				addr = find_free_base ( 0, size );
			}
			else {
				addr &= ~( PAGE_SIZE - 1 );
			}

			for ( uint64_t check = addr; check < addr + size; check += PAGE_SIZE ) {
				if ( find_region ( check ) ) {
					return 0;
				}
			}

			regions.push_back ( { addr, size, MEM_RESERVE, prot } );
			sort_regions ( );
			return addr;
		}

		bool commit ( uint64_t addr, size_t size, Protection prot ) {
			addr &= ~( PAGE_SIZE - 1 );
			size = ( ( size + PAGE_SIZE - 1 ) / PAGE_SIZE ) * PAGE_SIZE;
			Region* r = find_region ( addr );
			if ( !r || r->state != MEM_RESERVE || r->base > addr || r->base + r->size < addr + size ) {
				return false;
			}
			// Set pages as committed but not present (for on-demand paging simulation).
			for ( uint64_t p = addr; p < addr + size; p += PAGE_SIZE ) {
				uint64_t key = p >> 12;
				pages [ key ].present = false;
				pages [ key ].protect = prot;
				pages [ key ].host_ptr = nullptr;
			}
			r->state = MEM_COMMIT;
			r->protect = prot;
			return true;
		}

		char* translate ( uint64_t va, uint32_t access ) {  // Access: 1=read, 2=write, 4=execute
			uint64_t key = va >> 12;
			auto it = pages.find ( key );
			if ( it == pages.end ( ) ) {
				return nullptr;  // Page fault: not committed.
			}
			PageInfo& pi = it->second;
			bool can_read = ( static_cast< uint32_t >( pi.protect ) & 0x01 ) != 0;
			bool can_write = ( static_cast< uint32_t >( pi.protect ) & 0x02 ) != 0;
			bool can_execute = ( static_cast< uint32_t >( pi.protect ) & 0x04 ) != 0;
			if ( ( access & 1 ) && !can_read ) {
				return nullptr;
			}

			if ( ( access & 2 ) && !can_write ) {
				return nullptr;
			}

			if ( ( access & 4 ) && !can_execute ) {
				return nullptr;
			}

			if ( !pi.present ) {
				pi.host_ptr = new char [ PAGE_SIZE ] ( );
				pi.present = true;
			}
			return pi.host_ptr + ( va & ( PAGE_SIZE - 1 ) );
		}
	};

	class ModuleManager {
	private:
		MemoryManager* vm;
		struct Module {
			std::string name;
			uint64_t base;
			size_t size;
			std::unordered_map<std::string, uint64_t> exports;
			std::unordered_map<uint16_t, uint64_t> exports_by_ordinal;
		};
		std::vector<Module> modules;
		std::vector<std::string> search_paths = { "", "C:\\Windows\\System32\\" };

		uint64_t get_module_base ( const std::string& mod_name ) {
			std::string lower_name = mod_name;
			std::transform ( lower_name.begin ( ), lower_name.end ( ), lower_name.begin ( ), ::tolower );
			for ( const auto& m : modules ) {
				std::string m_lower = m.name;
				std::transform ( m_lower.begin ( ), m_lower.end ( ), m_lower.begin ( ), ::tolower );
				if ( m_lower == lower_name ) {
					return m.base;
				}
			}
			return 0;
		}

		uint64_t get_export_address ( const std::string& mod_name, const std::string& func_name, uint16_t ordinal = 0, bool by_ordinal = false ) {
			uint64_t mod_base = get_module_base ( mod_name );
			if ( mod_base == 0 ) return 0;
			for ( const auto& m : modules ) {
				if ( m.base == mod_base ) {
					if ( by_ordinal ) {
						auto it = m.exports_by_ordinal.find ( ordinal );
						if ( it != m.exports_by_ordinal.end ( ) ) return it->second;
					}
					else {
						auto it = m.exports.find ( func_name );
						if ( it != m.exports.end ( ) ) return it->second;
					}
					break;
				}
			}
			return 0;
		}

		void resolve_relocations ( win::image_x64_t* image, win::nt_headers_x64_t* nt, int64_t delta ) {
			std::println ( "Resolving relocations..." );

			auto* reloc_dir = image->get_directory ( win::directory_entry_basereloc );
			if ( !reloc_dir->present ( ) ) {
				std::println ( "\tImage has no relocations!" );
				return;
			}

			auto* relocs = &image->rva_to_ptr<win::reloc_directory_t> ( reloc_dir->rva )->first_block;
			size_t processed_bytes = 0u;
			while ( processed_bytes < reloc_dir->size ) {
				auto num_entries = relocs->num_entries ( );
				auto reloc_entry = relocs->begin ( );
				for ( auto i = 0u; i < num_entries; ++i, ++reloc_entry ) {
					auto type = reloc_entry->type;
					auto shift_delta = reloc_entry->offset % 0xFFF;
					if ( type == 0 ) {
						continue;
					}

					if ( type == 3 || type == 10 ) {
						auto fix_va = image->rva_to_ptr<std::uint8_t> ( relocs->base_rva );
						if ( !fix_va )
							fix_va = reinterpret_cast< std::uint8_t* > ( image );

						*reinterpret_cast< uint64_t* >( fix_va + shift_delta ) += delta;
					}
				}

				processed_bytes += relocs->size_block;
				relocs = relocs->next ( );
			}

			std::println ( "\tResolved {} relocations!", processed_bytes / sizeof ( win::reloc_entry_t ) );
		}

		bool resolve_imports ( win::image_x64_t* image, win::nt_headers_x64_t* nt ) {
			std::size_t imports_resolved = 0u;
			std::println ( "Resolving imports..." );

			auto* import_dir = image->get_directory ( win::directory_entry_import );
			if ( !import_dir->present ( ) ) {
				std::println ( "\tImage has no imports!" );
				return true;
			}

			auto* iat = image->rva_to_ptr<win::import_directory_t> ( import_dir->rva );
			for ( ; iat->rva_first_thunk; ++iat ) {
				auto* name = image->rva_to_ptr<char> ( iat->rva_name );
				if ( !name ) {
					continue;
				}

				std::string dll_name ( name );
				uint64_t module_base = get_module_base ( dll_name );
				if ( !module_base ) {
					std::string full_path;
					for ( const auto& dir : search_paths ) {
						std::filesystem::path p = dir + dll_name;
						if ( std::filesystem::exists ( p ) ) {
							full_path = p.string ( );
							break;
						}
					}
					if ( full_path.empty ( ) ) {
						std::println ( "\tFailed to find path for {}", dll_name );
						return false;
					}
					module_base = load_module ( full_path );
					if ( !module_base ) {
						std::println ( "\tFailed to load dependency {}", dll_name );
						return false;
					}
				}
				std::println ( "\t{} - {:#x}", dll_name, module_base );

				auto* first_thunk = image->rva_to_ptr<win::image_thunk_data_t<>> ( iat->rva_first_thunk );
				auto* thunk = image->rva_to_ptr<win::image_thunk_data_t<>> ( iat->rva_original_first_thunk ? iat->rva_original_first_thunk : iat->rva_first_thunk );
				for ( ; thunk->address; ++thunk, ++first_thunk ) {
					if ( thunk->is_ordinal ) {
						std::uint16_t ordinal = thunk->ordinal;
						auto resolved = get_export_address ( dll_name, "", ordinal, true );
						first_thunk->function = resolved;
						std::println ( "\t\t{:#x} -> {:#x}", ordinal, resolved );
						++imports_resolved;
						continue;
					}

					auto* named_import = image->rva_to_ptr<win::image_named_import_t> ( thunk->address );
					if ( !named_import ) {
						continue;
					}

					std::string func_name ( named_import->name );
					auto resolved = get_export_address ( dll_name, func_name );
					first_thunk->function = resolved;
					std::println ( "\t\t{} -> {:#x}", func_name, resolved );
					++imports_resolved;
				}
			}

			std::println ( "\tResolved {} imports!", imports_resolved );
			return true;
		}

	public:
		ModuleManager ( MemoryManager* v ) : vm ( v ) { }

		uint64_t load_module ( const std::string& path ) {
			uint64_t existing_base = get_module_base ( path );
			if ( existing_base != 0 ) {
				return existing_base;
			}

			std::ifstream file ( path, std::ios::binary | std::ios::ate );
			if ( !file ) {
				return 0;
			}
			size_t file_size = static_cast< size_t >( file.tellg ( ) );
			file.seekg ( 0 );
			std::vector<uint8_t> buffer ( file_size );
			file.read ( reinterpret_cast< char* >( buffer.data ( ) ), file_size );

			auto* image = reinterpret_cast< win::image_x64_t* >( buffer.data ( ) );
			if ( image->dos_header.e_magic != 'ZM' ) {
				return 0;
			}
			auto* nt = image->get_nt_headers ( );
			if ( nt->signature != 0x50450000 ) {
				return 0;
			}

			if ( nt->file_header.machine != win::machine_id::amd64 ) {
				return 0;
			}
			uint64_t preferred_base = nt->optional_header.image_base;
			size_t image_size = nt->optional_header.size_image;
			uint64_t base = vm->reserve ( preferred_base, image_size, Protection::READWRITE );
			if ( base == 0 ) {
				base = vm->reserve ( 0, image_size, Protection::READWRITE );
			}
			if ( base == 0 ) {
				return 0;
			}
			int64_t delta = static_cast< int64_t >( base - nt->optional_header.image_base );

			if ( !resolve_imports ( image, nt ) ) {
				return 0;
			}
			resolve_relocations ( image, nt, delta );

			for ( const auto& section : nt->sections ( ) ) {
				uint64_t section_va = base + section.virtual_address;
				size_t section_size = section.virtual_size;
				Protection prot;
				if ( section.characteristics.mem_execute ) {
					prot = ( section.characteristics.mem_write ) ? Protection::EXECUTE_READWRITE : Protection::EXECUTE_READ;
				}
				else if ( section.characteristics.mem_write ) {
					prot = Protection::READWRITE;
				}
				else {
					prot = Protection::READONLY;
				}
				if ( !vm->commit ( section_va, section_size, prot ) ) {
					return 0;
				}

				const uint8_t* src = buffer.data ( ) + section.ptr_raw_data;
				size_t raw_size = section.size_raw_data;
				for ( size_t off = 0; off < section_size; off += PAGE_SIZE ) {
					char* dest = vm->translate ( section_va + off, 2 );
					if ( !dest ) {
						return 0;
					}
					size_t copy_size = std::min ( PAGE_SIZE, raw_size > off ? raw_size - off : 0 );
					if ( copy_size > 0 ) {
						std::memcpy ( dest, src + off, copy_size );
					}
					if ( copy_size < PAGE_SIZE ) {
						std::memset ( dest + copy_size, 0, PAGE_SIZE - copy_size );
					}
				}
			}

			Module new_mod { path, base, image_size };
			auto* export_dir = image->get_directory ( win::directory_entry_export );
			if ( export_dir->present ( ) ) {
				auto* exp = image->rva_to_ptr<win::export_directory_t> ( export_dir->rva );
				auto* functions = image->rva_to_ptr<uint32_t> ( exp->rva_functions );
				auto* names = image->rva_to_ptr<uint32_t> ( exp->rva_names );
				auto* ordinals = image->rva_to_ptr<uint16_t> ( exp->rva_name_ordinals );

				for ( uint32_t i = 0; i < exp->num_functions; ++i ) {
					uint32_t func_rva = functions [ i ];
					if ( func_rva == 0 ) continue;
					new_mod.exports_by_ordinal [ exp->base + i ] = base + func_rva;
				}

				for ( uint32_t i = 0; i < exp->num_names; ++i ) {
					auto* name_ptr = image->rva_to_ptr<char> ( names [ i ] );
					std::string name ( name_ptr );
					uint16_t ord = ordinals [ i ];
					new_mod.exports [ name ] = base + functions [ ord ];
				}
			}

			modules.push_back ( std::move ( new_mod ) );
			return base;
		}
	};
};
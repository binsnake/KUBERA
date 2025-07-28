#include "../memory.hpp"

namespace kubera
{
	VirtualMemory::VirtualMemory ( std::size_t ps ) : page_size ( ps ) {
		for ( auto& c : cache ) {
			c.virt = UINT64_MAX;
		}
	}

	VirtualMemory::~VirtualMemory ( ) {
		for ( auto& [v, p] : pages ) {
			if ( p->data ) {
				_aligned_free ( p->data );
			}
		}
	}

	void VirtualMemory::set_read_hook ( uint64_t addr, std::function<void ( VirtualMemory* vm, uint64_t addr, std::size_t size )> hook ) {
		auto* region = const_cast< Region* >( find_region ( addr ) );
		if ( region ) {
			region->read_hook = std::move ( hook );
		}
	}

	uint8_t* VirtualMemory::commit ( std::size_t size ) {
		return reinterpret_cast< uint8_t* >( _aligned_malloc ( size, PAGE_ALIGN ) );
	}

	void VirtualMemory::uncommit ( uint8_t* data ) {
		if ( data ) {
			_aligned_free ( data );
		}
	}

	uint64_t VirtualMemory::alloc ( std::size_t size, uint8_t prot, std::size_t alignment, bool commit_immediately ) {
		uint64_t base = ( next_alloc + alignment - 1 ) & ~( alignment - 1 );
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		Region region { base, pages_needed * page_size, prot, prot };
		regions [ base ] = region;
		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = base + i * page_size;
			pages [ virt ] = std::make_unique<Page> ( );
			pages [ virt ]->prot = prot;
			pages [ virt ]->region_base = base;
			if ( commit_immediately ) {
				pages [ virt ]->data = commit ( page_size );
				if ( !pages [ virt ]->data ) {
					if constexpr ( verbose_memory ) {
						std::println ( "Failed to commit memory for page at address {:#x}", virt );
					}

					for ( std::size_t j = 0; j <= i; j++ ) {
						pages.erase ( base + j * page_size );
					}
					regions.erase ( base );
					return 0;
				}
				std::memset ( pages [ virt ]->data, 0, page_size );
				pages [ virt ]->present = true;
			}
		}
		next_alloc = base + pages_needed * page_size;
		return base;
	}

	uint64_t VirtualMemory::alloc_at ( uint64_t base_addr, std::size_t size, uint8_t prot, std::size_t alignment, bool commit_immediately ) {
		uint64_t base = ( base_addr + alignment - 1 ) & ~( alignment - 1 );
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		uint64_t region_end = base + pages_needed * page_size;

		while ( true ) {
			auto it = regions.lower_bound ( base );
			if ( it != regions.begin ( ) ) --it;
			bool overlap = false;
			while ( it != regions.end ( ) && it->first < region_end ) {
				if ( it->first + it->second.size > base ) {
					if constexpr ( verbose_memory ) {
						std::println ( "Warning: Requested region at {:#x} overlaps with existing region at {:#x} (size {:#x}). Trying next available address.",
												 base, it->first, it->second.size );
					}
					overlap = true;
					base = ( it->first + it->second.size + alignment - 1 ) & ~( alignment - 1 );
					region_end = base + pages_needed * page_size;
					it = regions.lower_bound ( base );
					if ( it != regions.begin ( ) ) --it;
					continue;
				}
				++it;
			}

			if ( !overlap ) {
				break;
			}
		}

		Region region { base, pages_needed * page_size, prot, prot };
		regions [ base ] = region;

		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = base + i * page_size;
			if ( pages.find ( virt ) != pages.end ( ) ) {
				if constexpr ( verbose_memory ) {
					std::println ( "Warning: Page at address {:#x} already exists. Allocation failed.", virt );
				}
				regions.erase ( base );
				for ( std::size_t j = 0; j < i; j++ ) {
					pages.erase ( base + j * page_size );
				}
				return 0;
			}
			pages [ virt ] = std::make_unique<Page> ( );
			pages [ virt ]->prot = prot;
			pages [ virt ]->region_base = base;
			if ( commit_immediately ) {
				pages [ virt ]->data = commit ( page_size );
				if ( !pages [ virt ]->data ) {
					if constexpr ( verbose_memory ) {
						std::println ( "Failed to commit memory for page at address {:#x}", virt );
					}
					for ( std::size_t j = 0; j <= i; j++ ) {
						pages.erase ( base + j * page_size );
					}
					regions.erase ( base );
					return 0;
				}
				std::memset ( pages [ virt ]->data, 0, page_size );
				pages [ virt ]->present = true;
			}
		}

		return base;
	}

	uint64_t VirtualMemory::load ( const void* data, std::size_t size, uint8_t prot, std::size_t alignment ) {
		uint64_t addr = alloc ( size, prot, alignment );
		write_bytes ( addr, data, size, PageProtection::WRITE );
		return addr;
	}

	void VirtualMemory::free ( uint64_t addr, std::size_t size ) {
		uint64_t base = addr & ~( page_size - 1 );
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		uint64_t region_end = base + pages_needed * page_size;

		auto it = regions.lower_bound ( base );
		if ( it != regions.begin ( ) ) --it;
		while ( it != regions.end ( ) && it->first < region_end ) {
			if ( it->first + it->second.size > base ) {
				auto next = std::next ( it );
				regions.erase ( it );
				it = next;
			}
			else {
				++it;
			}
		}

		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = base + i * page_size;
			auto page_it = pages.find ( virt );
			if ( page_it != pages.end ( ) ) {
				uncommit ( page_it->second->data );
				pages.erase ( page_it );
			}
		}
	}

	bool VirtualMemory::protect ( uint64_t addr, std::size_t size, uint8_t prot ) {
		uint64_t start = addr & ~( page_size - 1 );
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		uint64_t end = start + pages_needed * page_size;

		auto* region = find_region ( addr );
		if ( !region ) {
			return false;
		}

		split_region ( region->base_address, start, end, prot );
		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = start + i * page_size;
			auto it = pages.find ( virt );
			if ( it == pages.end ( ) ) return false;
			it->second->prot = prot;
		}
		return true;
	}

	const Region* VirtualMemory::find_region ( uint64_t addr ) const {
		auto it = regions.upper_bound ( addr );
		if ( it == regions.begin ( ) ) {
			return nullptr;
		}
		--it;
		if ( it->first <= addr && addr < it->first + it->second.size ) {
			return &it->second;
		}
		return nullptr;
	}

	void VirtualMemory::split_region ( uint64_t base, uint64_t split_start, uint64_t split_end, uint8_t new_protect ) {
		auto it = regions.find ( base );
		if ( it == regions.end ( ) ) return;

		Region old_region = it->second;
		regions.erase ( it );

		if ( split_start > base ) {
			Region before { base, static_cast< std::size_t >( split_start - base ), old_region.allocation_protect, old_region.current_protect };
			regions [ base ] = before;
		}

		Region modified { split_start, static_cast< std::size_t >( split_end - split_start ), old_region.allocation_protect, new_protect };
		regions [ split_start ] = modified;

		if ( split_end < base + old_region.size ) {
			Region after { split_end, static_cast< std::size_t > ( base + old_region.size - split_end ), old_region.allocation_protect, old_region.current_protect };
			regions [ split_end ] = after;
		}

		for ( auto& [virt, page] : pages ) {
			if ( virt >= base && virt < base + old_region.size ) {
				auto* new_region = find_region ( virt );
				if ( new_region ) {
					page->region_base = new_region->base_address;
				}
			}
		}
	}

	void* VirtualMemory::translate ( uint64_t addr, uint8_t access, bool silent ) {
		uint64_t virt_page = addr & ~( page_size - 1 );
		for ( auto& e : cache ) {
			if ( e.virt == virt_page ) {
				if ( ( e.page->prot & access ) != access ) {
					if constexpr ( verbose_memory ) {
						if ( !silent )
							std::println ( "Access violation at address {:#x} with access {:#x} (protection)", addr, access );
					}
					return nullptr;
				}
				if ( !e.page->present ) {
					e.page->data = commit ( page_size );
					if ( !e.page->data ) {
						if constexpr ( verbose_memory ) {
							if ( !silent )
								std::println ( "Access violation at address {:#x} with access {:#x} (memory not committed)", addr, access );
						}
						return nullptr;
					}
					std::memset ( e.page->data, 0, page_size );
					e.page->present = true;
				}
				if ( ( access & PageProtection::READ ) != 0 ) {
					auto* region = find_region ( addr );
					if ( region && region->read_hook ) {
						( *region->read_hook )( this, addr, page_size - ( addr - virt_page ) );
					}
				}
				return e.page->data + ( addr - virt_page );
			}
		}
		auto it = pages.find ( virt_page );
		if ( it == pages.end ( ) ) {
			if constexpr ( verbose_memory ) {
				if ( !silent )
					std::println ( "Access violation at address {:#x} with access {:#x} (invalid address)", addr, access );
			}
			return nullptr;
		}
		Page* pg = it->second.get ( );
		cache [ cache_pos ] = { virt_page, pg };
		cache_pos = ( cache_pos + 1 ) % cache.size ( );
		if ( ( pg->prot & access ) != access ) {
			if constexpr ( verbose_memory ) {
				if ( !silent )
					std::println ( "Access violation at address {:#x} with access {:#x}", addr, access );
			}
			return nullptr;
		}
		if ( !pg->present ) {
			pg->data = commit ( page_size );
			if ( !pg->data ) {
				if constexpr ( verbose_memory ) {
					if ( !silent )
						std::println ( "Access violation at address {:#x} with access %u (insufficient memory)", addr, access );
				}
				return nullptr;
			}
			std::memset ( pg->data, 0, page_size );
			pg->present = true;
		}

		auto* region = find_region ( addr );
		if ( region && region->read_hook ) {
			( *region->read_hook )( this, addr, page_size - ( addr - virt_page ) );
		}

		return pg->data + ( addr - virt_page );
	}

	void* VirtualMemory::translate_bypass ( uint64_t addr, bool silent ) {
		uint64_t virt_page = addr & ~( page_size - 1 );
		for ( auto& e : cache ) {
			if ( e.virt == virt_page ) {
				if ( !e.page->present ) {
					e.page->data = commit ( page_size );
					if ( !e.page->data ) {
						if constexpr ( verbose_memory ) {
							if ( !silent )
								std::println ( "Access violation at address {:#x} (insufficient memory)", addr );
						}
						return nullptr;
					}
					std::memset ( e.page->data, 0, page_size );
					e.page->present = true;
				}
				return e.page->data + ( addr - virt_page );
			}
		}

		auto it = pages.find ( virt_page );
		if ( it == pages.end ( ) ) {
			if constexpr ( verbose_memory ) {
				if ( !silent )
					std::println ( "Access violation at address {:#x} (invalid address)", addr );
			}
			return nullptr;
		}
		Page* pg = it->second.get ( );
		cache [ cache_pos ] = { virt_page, pg };
		cache_pos = ( cache_pos + 1 ) % cache.size ( );

		if ( !pg->present ) {
			pg->data = commit ( page_size );
			if ( !pg->data ) {
				if constexpr ( verbose_memory ) {
					if ( !silent )
						std::println ( "Access violation at address {:#x} (insufficient memory)", addr );
				}
				return nullptr;
			}
			std::memset ( pg->data, 0, page_size );
			pg->present = true;
		}

		return pg->data + ( addr - virt_page );
	}

	bool VirtualMemory::check ( uint64_t addr, std::size_t size, uint8_t access ) {
		for ( std::size_t offset = 0; offset < size; offset += page_size ) {
			void* p = translate ( addr + offset, access );
			if ( !p ) return false;
		}
		return true;
	}

	WinMemoryBasicInformation VirtualMemory::get_memory_basic_information ( uint64_t addr ) {
		WinMemoryBasicInformation mbi { 0 };
		auto* region = find_region ( addr );
		if ( region ) {
			mbi.base_address = region->base_address;
			mbi.allocation_base = region->base_address;
			mbi.allocation_protect = map_to_win_protect ( region->base_address );
			mbi.region_size = region->size;
			mbi.protect = map_to_win_protect ( addr );
			mbi.state = 0x1000;
			mbi.type = 0x20000;
		}
		return mbi;
	}

	Page* VirtualMemory::get_page ( uint64_t addr ) {
		auto it = pages.find ( addr & ~( page_size - 1 ) );
		if ( it == pages.end ( ) ) return nullptr;
		return it->second.get ( );
	}

	uint32_t VirtualMemory::map_to_win_protect ( uint64_t addr ) {
		auto* region = find_region ( addr );
		if ( !region ) {
			return 0x01; // PAGE_NOACCESS
		}
		const auto protection = region->current_protect;
		const auto executable = ( protection & PageProtection::EXEC ) != PageProtection::NONE;
		const auto readable = ( protection & PageProtection::READ ) != PageProtection::NONE;
		const auto writable = ( protection & PageProtection::WRITE ) != PageProtection::NONE;

		if ( !readable ) {
			return 0x01; // PAGE_NOACCESS
		}

		if ( executable && writable ) {
			return 0x40; // PAGE_EXECUTE_READWRITE
		}

		if ( writable ) {
			return 0x04; // PAGE_READWRITE
		}

		if ( executable ) {
			return 0x20; // PAGE_EXECUTE_READ
		}

		return 0x02; // PAGE_READONLY
	}
}

#ifndef KUBERA_MEMORY_HPP
#define KUBERA_MEMORY_HPP

#include <cstdint>
#include <unordered_map>
#include <array>
#include <cstring>
#include <memory>
#include "types.hpp"

namespace kubera
{

	class VirtualMemory {
	public:
		enum Protection : uint8_t {
			NONE = 0,
			READ = 1 << 0,
			WRITE = 1 << 1,
			EXEC = 1 << 2
		};

		explicit VirtualMemory ( std::size_t page_sz = 0x1000 );
		~VirtualMemory ( );

		uint64_t alloc ( std::size_t size, uint8_t prot, std::size_t alignment = 0x1000 );
		uint64_t load ( const void* data, std::size_t size, uint8_t prot, std::size_t alignment = 0x1000 );
		void free ( uint64_t addr, std::size_t size );
		bool protect ( uint64_t addr, std::size_t size, uint8_t prot );

		template<typename T> T read ( uint64_t addr );
		template<typename T> void write ( uint64_t addr, T val );
		void* translate ( uint64_t addr, uint8_t access );
		bool check ( uint64_t addr, std::size_t size, uint8_t access );

		std::size_t page_size;
	private:
		struct Page {
			uint8_t* data { nullptr };
			uint8_t prot { Protection::NONE };
			bool present { false };
		};

		std::unordered_map<uint64_t, Page> pages;
		uint64_t next_alloc { 0x100000000ULL };

		struct CacheEntry { uint64_t virt; Page* page; };
		std::array<CacheEntry, 16> cache;
		std::size_t cache_pos { 0 };
	};

	inline VirtualMemory::VirtualMemory ( std::size_t ps ) : page_size ( ps ) {
		for ( auto& c : cache ) c.virt = UINT64_MAX;
	}

	inline VirtualMemory::~VirtualMemory ( ) {
		for ( auto& [v, p] : pages ) {
			if ( p.data ) std::free ( p.data );
		}
	}

	inline uint64_t VirtualMemory::alloc ( std::size_t size, uint8_t prot, std::size_t alignment ) {
		uint64_t base = ( next_alloc + alignment - 1 ) & ~( alignment - 1 );
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = base + i * page_size;
			pages [ virt ] = Page { nullptr, prot, false };
		}
		next_alloc = base + pages_needed * page_size;
		return base;
	}

	inline uint64_t VirtualMemory::load ( const void* data, std::size_t size, uint8_t prot, std::size_t alignment ) {
		uint64_t addr = alloc ( size, prot, alignment );
		std::memcpy ( translate ( addr, Protection::WRITE | Protection::READ ), data, size );
		return addr;
	}

	inline void VirtualMemory::free ( uint64_t addr, std::size_t size ) {
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = ( addr & ~( page_size - 1 ) ) + i * page_size;
			auto it = pages.find ( virt );
			if ( it != pages.end ( ) ) {
				if ( it->second.data ) std::free ( it->second.data );
				pages.erase ( it );
			}
		}
	}

	inline bool VirtualMemory::protect ( uint64_t addr, std::size_t size, uint8_t prot ) {
		std::size_t pages_needed = ( size + page_size - 1 ) / page_size;
		for ( std::size_t i = 0; i < pages_needed; i++ ) {
			uint64_t virt = ( addr & ~( page_size - 1 ) ) + i * page_size;
			auto it = pages.find ( virt );
			if ( it == pages.end ( ) ) return false;
			it->second.prot = prot;
		}
		return true;
	}

	inline void* VirtualMemory::translate ( uint64_t addr, uint8_t access ) {
		uint64_t virt_page = addr & ~( page_size - 1 );
		for ( auto& e : cache ) {
			if ( e.virt == virt_page ) {
				if ( !( e.page->prot & access ) ) return nullptr;
				if ( !e.page->present ) {
					e.page->data = static_cast< uint8_t* >( _aligned_malloc ( page_size, page_size ) ); __assume( e.page->data != nullptr );
					std::memset ( e.page->data, 0, page_size );
					e.page->present = true;
				}
				return e.page->data + ( addr - virt_page );
			}
		}
		auto it = pages.find ( virt_page );
		if ( it == pages.end ( ) ) return nullptr;
		Page* pg = &it->second;
		cache [ cache_pos ] = { virt_page, pg };
		cache_pos = ( cache_pos + 1 ) % cache.size ( );
		if ( !( pg->prot & access ) ) return nullptr;
		if ( !pg->present ) {
			pg->data = static_cast< uint8_t* >( _aligned_malloc ( page_size, page_size ) ); __assume( pg->data != nullptr );
			std::memset ( pg->data, 0, page_size );
			pg->present = true;
		}
		return pg->data + ( addr - virt_page );
	}

	inline bool VirtualMemory::check ( uint64_t addr, std::size_t size, uint8_t access ) {
		for ( std::size_t offset = 0; offset < size; offset += page_size ) {
			void* p = translate ( addr + offset, access );
			if ( !p ) return false;
		}
		return true;
	}

	template<typename T>
	inline T VirtualMemory::read ( uint64_t addr ) {
		void* p = translate ( addr, Protection::READ );
		if ( !p ) return T {};
		T val;
		std::memcpy ( &val, p, sizeof ( T ) );
		return val;
	}

	template<>
	inline uint128_t VirtualMemory::read ( uint64_t addr ) {
		uint64_t low = read<uint64_t> ( addr );
		uint64_t high = read<uint64_t> ( addr + 8 );
		uint128_t result = uint128_t ( high );
		result <<= 64;
		result |= low;
		return result;
	}

	template<>
	inline uint256_t VirtualMemory::read ( uint64_t addr ) {
		uint256_t result = 0;
		for ( int i = 0; i < 4; i++ ) {
			uint64_t part = read<uint64_t> ( addr + i * 8 );
			result |= uint256_t ( part ) << ( i * 64 );
		}
		return result;
	}

	template<>
	inline uint512_t VirtualMemory::read ( uint64_t addr ) {
		uint512_t result = 0;
		for ( int i = 0; i < 8; i++ ) {
			uint64_t part = read<uint64_t> ( addr + i * 8 );
			result |= uint512_t ( part ) << ( i * 64 );
		}
		return result;
	}

	template<typename T>
	inline void VirtualMemory::write ( uint64_t addr, T val ) {
		void* p = translate ( addr, Protection::WRITE );
		if ( !p ) return;
		std::memcpy ( p, &val, sizeof ( T ) );
	}

	template<>
	inline void VirtualMemory::write ( uint64_t addr, uint128_t val ) {
		uint64_t low = static_cast< uint64_t >( val & uint128_t ( 0xFFFFFFFFFFFFFFFFULL ) );
		uint64_t high = static_cast< uint64_t >( val >> 64 );
		write<uint64_t> ( addr, low );
		write<uint64_t> ( addr + 8, high );
	}

	template<>
	inline void VirtualMemory::write ( uint64_t addr, uint256_t val ) {
		for ( int i = 0; i < 4; i++ ) {
			uint64_t part = static_cast< uint64_t > ( ( val >> ( i * 64 ) ) & uint256_t ( 0xFFFFFFFFFFFFFFFFULL ) );
			write<uint64_t> ( addr + i * 8, part );
		}
	}

	template<>
	inline void VirtualMemory::write ( uint64_t addr, uint512_t val ) {
		for ( int i = 0; i < 8; i++ ) {
			uint64_t part = static_cast< uint64_t > ( ( val >> ( i * 64 ) ) & uint512_t ( 0xFFFFFFFFFFFFFFFFULL ) );
			write<uint64_t> ( addr + i * 8, part );
		}
	}

} // namespace kubera

#endif

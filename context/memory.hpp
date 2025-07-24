#ifndef KUBERA_MEMORY_HPP
#define KUBERA_MEMORY_HPP

#include <cstdint>
#include <unordered_map>
#include <map>
#include <array>
#include <cstring>
#include <memory>
#include <print>
#include "types.hpp"

namespace kubera
{
	constexpr auto verbose_memory = true;
	class VirtualMemory {
	public:
		explicit VirtualMemory ( std::size_t page_sz = 0x1000 );
		~VirtualMemory ( );

		[[nodiscard]] uint64_t alloc ( std::size_t size, uint8_t prot, std::size_t alignment = 0x1000 );
		[[nodiscard]] uint64_t alloc_at ( uint64_t base_addr, std::size_t size, uint8_t prot );
		[[nodiscard]] uint8_t* commit ( std::size_t size );
		void uncommit ( uint8_t* data );
		[[nodiscard]] uint64_t load ( const void* data, std::size_t size, uint8_t prot, std::size_t alignment = 0x1000 );
		void free ( uint64_t addr, std::size_t size );
		bool protect ( uint64_t addr, std::size_t size, uint8_t prot );
		[[nodiscard]] uint32_t map_to_win_protect ( uint64_t addr );
		[[nodiscard]] WinMemoryBasicInformation get_memory_basic_information ( uint64_t addr );
		[[nodiscard]] Page* get_page ( uint64_t addr );
		void set_read_hook ( uint64_t addr, std::function<void ( VirtualMemory*, uint64_t addr, std::size_t size )> hook );

		template<typename T> [[nodiscard]] T read ( uint64_t addr );
		template<typename T> void write ( uint64_t addr, T val );
		void read_bytes ( uint64_t addr, void* dest, std::size_t size, uint8_t access = PageProtection::READ );
		void write_bytes ( uint64_t addr, const void* src, std::size_t size, uint8_t access = PageProtection::WRITE );
		[[nodiscard]] void* translate ( uint64_t addr, uint8_t access );
		[[nodiscard]] void* translate_bypass ( uint64_t addr );
		[[nodiscard]] bool check ( uint64_t addr, std::size_t size, uint8_t access );

		std::size_t page_size;

	private:
		std::unordered_map<uint64_t, std::unique_ptr<Page>> pages;
		std::map<uint64_t, Region> regions;
		uint64_t next_alloc { 0x100000000ULL };

		struct CacheEntry { uint64_t virt; Page* page; };
		std::array<CacheEntry, 16> cache;
		std::size_t cache_pos { 0 };

		const Region* find_region ( uint64_t addr ) const;
		void split_region ( uint64_t base, uint64_t split_start, uint64_t split_end, uint8_t new_protect );
	};

	constexpr auto PAGE_ALIGN = 4096;

	template<typename T>
	inline T VirtualMemory::read ( uint64_t addr ) {
		T val {0};
		uint8_t* dest = reinterpret_cast< uint8_t* >( &val );
		std::size_t remaining = sizeof ( T );
		uint64_t current = addr;
		while ( remaining > 0 ) {
			void* src = translate ( current, PageProtection::READ );
			if ( !src ) return T {};
			std::size_t offset = current % page_size;
			std::size_t to_copy = std::min ( remaining, page_size - offset );
			std::memcpy ( dest, src, to_copy );
			dest += to_copy;
			current += to_copy;
			remaining -= to_copy;
		}
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
		const uint8_t* src = reinterpret_cast< const uint8_t* > ( &val );
		std::size_t remaining = sizeof ( T );
		uint64_t current = addr;
		while ( remaining > 0 ) {
			void* dest = translate ( current, PageProtection::WRITE );
			if ( !dest ) return;
			std::size_t offset = current % page_size;
			std::size_t to_copy = std::min ( remaining, page_size - offset );
			std::memcpy ( dest, src, to_copy );
			src += to_copy;
			current += to_copy;
			remaining -= to_copy;
		}
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

	inline void VirtualMemory::read_bytes ( uint64_t addr, void* dest, std::size_t size, uint8_t access ) {
		uint8_t* d = static_cast< uint8_t* > ( dest );
		std::size_t remaining = size;
		uint64_t current = addr;
		while ( remaining > 0 ) {
			void* src = translate ( current, access );
			if ( !src ) {
				std::memset ( d, 0, remaining );
				return;
			}
			std::size_t offset = current % page_size;
			std::size_t to_copy = std::min ( remaining, page_size - offset );
			std::memcpy ( d, src, to_copy );
			d += to_copy;
			current += to_copy;
			remaining -= to_copy;
		}
	}

	inline void VirtualMemory::write_bytes ( uint64_t addr, const void* src, std::size_t size, uint8_t access ) {
		const uint8_t* s = static_cast< const uint8_t* >( src );
		std::size_t remaining = size;
		uint64_t current = addr;
		while ( remaining > 0 ) {
			void* dest = translate ( current, access );
			if ( !dest ) return;
			std::size_t offset = current % page_size;
			std::size_t to_copy = std::min ( remaining, page_size - offset );
			std::memcpy ( dest, s, to_copy );
			s += to_copy;
			current += to_copy;
			remaining -= to_copy;
		}
	}
} // namespace kubera

#endif
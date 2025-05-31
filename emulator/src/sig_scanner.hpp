#pragma once 
#include <algorithm>
#include <type_traits>
#include <array>
#include <cstdint>
#include <utility>
#include <immintrin.h>
#if defined(__clang__)
#define CLANG 1
#else
#define CLANG 0
#endif
#if defined(__GNUC__)&&!defined(__clang__)
#define GCC 1
#else
#define GCC 0
#endif
#if defined(_MSC_VER)&&!defined(__clang__)
#define MSVC 1
#else
#define MSVC 0
#endif
#if defined(_MSC_VER)&&defined(__clang__)
#define CLANG_CL 1
#else
#define CLANG_CL 0
#endif
static_assert( CLANG + GCC + MSVC == 1 );
#if MSVC || CLANG_CL
#if _WIN32 || _WIN64
#if _WIN64
#define BITNESS 64
#else
#define BITNESS 32
#endif
#endif
#else
#if __x86_64__ || __ppc64__
#define BITNESS 64
#else
#define BITNESS 32
#endif
#endif
static_assert( sizeof ( void* ) * 8 == BITNESS );
#if CLANG || GCC
#define UNREACHABLE __builtin_unreachable()
#define Inline __attribute__((always_inline)) inline
#define LambdaInline __attribute__((always_inline))
#else
#define UNREACHABLE __assume(false)
#define Inline __forceinline
#define LambdaInline [[msvc::forceinline]]
#endif
#define FWD(...) static_cast<decltype(__VA_ARGS__)&&>(__VA_ARGS__)
#define MOV(...) static_cast<typename std::remove_reference<decltype(__VA_ARGS__)>::type &&>(__VA_ARGS__)
#if CLANG || GCC
template<class T, class T0>concept $Same = __is_same ( T, T0 );
template<class T, class...Ts>constexpr bool all_same { ( __is_same ( T, Ts )&&... ) };
#else
template<class T, class T0>concept $Same = std::is_same_v<T, T0>;
template<class T, class...Ts>constexpr bool all_same { ( std::is_same_v<T, Ts>&&... ) };
#endif
namespace Algorithm
{
	template<class Arg0, class...Args>
		requires( all_same<Arg0, Args...>&& std::is_trivially_copyable_v<Arg0> && sizeof ( Arg0 ) <= 2 * sizeof ( void* ) )
	Inline constexpr Arg0 max ( Arg0 arg0, const Args...args )noexcept {
		( ( arg0 = ( args > arg0 ) ? args : arg0 ), ... );
		return arg0;
	}
}
namespace details
{
	template<std::uint64_t MaxValue>struct compact_impl;
	template<std::uint64_t MaxValue>requires( ( MaxValue >= 0 ) && MaxValue <= std::uint8_t ( -1 ) ) struct compact_impl<MaxValue> { using type = std::uint8_t; };
	template<std::uint64_t MaxValue>requires( ( MaxValue > std::uint8_t ( -1 ) ) && MaxValue <= std::uint16_t ( -1 ) )	struct compact_impl<MaxValue> { using type = std::uint16_t; };
	template<std::uint64_t MaxValue>requires( ( MaxValue > std::uint16_t ( -1 ) ) && MaxValue <= std::uint32_t ( -1 ) )	struct compact_impl<MaxValue> { using type = std::uint32_t; };
	template<std::uint64_t MaxValue>requires( ( MaxValue > std::uint32_t ( -1 ) ) && MaxValue <= std::uint64_t ( -1 ) )	struct compact_impl<MaxValue> { using type = std::uint64_t; };
}
template<std::uint64_t...MaxValue>using Compact = typename details::compact_impl<Algorithm::max ( MaxValue... )>::type;
template<std::uint64_t Value>static constexpr Compact<Value> compact { static_cast< Compact<Value> >( Value ) };
template<class...>struct LikeImpl;
template<class From, class To>struct LikeImpl<From&, To> { using type = To&; };
template<class From, class To>struct LikeImpl<const From&, To> { using type = const To&; };
template<class From, class To>struct LikeImpl<volatile From&, To> { using type = volatile To&; };
template<class From, class To>struct LikeImpl<const volatile From&, To> { using type = const volatile To&; };
template<class From, class To>struct LikeImpl<From&&, To> { using type = To&&; };
template<class From, class To>struct LikeImpl<const From&&, To> { using type = const To&&; };
template<class From, class To>struct LikeImpl<volatile From&&, To> { using type = volatile To&&; };
template<class From, class To>struct LikeImpl<const volatile From&&, To> { using type = const volatile To&&; };
template<class From, class To>struct LikeImpl<From, To> { using type = To&&; };
template<class From, class To>struct LikeImpl<const From, To> { using type = const To&&; };
template<class From, class To>struct LikeImpl<volatile From, To> { using type = volatile To&&; };
template<class From, class To>struct LikeImpl<const volatile From, To> { using type = const volatile To&&; };
template<class From, class To>using Like = typename LikeImpl<From, std::remove_cvref_t<To>>::type;
template<class From, class To>using LikePtr = std::remove_reference_t<Like<From, To>>*;
template<class, std::size_t>struct ConstVector;
template<class T, std::size_t N>
	requires( N > 0 )
struct ConstVector<T, N> {
	using index_t = Compact<N>;
	T m_data [ N ];
	index_t m_size;
	constexpr ConstVector ( auto&& ...args )noexcept requires( sizeof...( args ) <= N ) : m_data { FWD ( args )... }, m_size { sizeof...( args ) } { }
	constexpr index_t size ( )const noexcept { return m_size; }
	static constexpr index_t capacity ( ) noexcept { return N; }
	template<class Self>constexpr Like<Self, T> front ( this Self&& self ) noexcept { return FWD ( self ).m_data [ 0 ]; }
	template<class Self>constexpr Like<Self, T> back ( this Self&& self ) noexcept { return FWD ( self ).m_data [ self.m_size - 1 ]; }
	template<class Self>constexpr Like<Self, T> operator[]( this Self&& self, index_t index ) noexcept { return static_cast< Like<Self, T> >( FWD ( self ).m_data [ index ] ); }//msvc bug
	template<class Self>constexpr LikePtr<Self, T> data ( this Self&& self ) noexcept { return self.m_data; }
	template<class Self>constexpr LikePtr<Self, T> begin ( this Self&& self ) noexcept { return self.m_data; }
	template<class Self>constexpr LikePtr<Self, T> end ( this Self&& self ) noexcept { return self.begin ( ) + self.m_size; }
	constexpr void clear ( )noexcept { m_size = {}; }
	constexpr void push_back ( T entry )noexcept { m_data [ m_size++ ] = entry; }
};
template<class T>
struct ConstVector<T, 0> {
	constexpr ConstVector ( )noexcept { }
	static constexpr std::uint8_t size ( ) noexcept { return 0; }
	static constexpr std::uint8_t capacity ( ) noexcept { return 0; }
	constexpr const T* data ( )const noexcept { return nullptr; }
	constexpr const T* begin ( )const noexcept { return nullptr; }
	constexpr const T* end ( )const noexcept { return nullptr; }
};
template<class, class Sig>struct CallableImpl;
template<class T, class Ret, class...Args>struct CallableImpl<T, Ret ( Args... )> { static constexpr bool value { requires( T f, Args...args ) { { FWD ( f )( FWD ( args )... ) }->$Same<Ret>; } }; };
template<class T, class Sig>concept Callable = CallableImpl<T, Sig>::value;
template<class T, std::size_t N>
struct FixedString {
private:
	template<std::size_t...I>
	Inline constexpr FixedString ( const T ( &str ) [ N + 1 ], std::index_sequence<I...> )noexcept :m_data { str [ I ]... } { }
public:
	Inline constexpr FixedString ( const T ( &str ) [ N + 1 ] )noexcept : FixedString { str, std::make_index_sequence<N>{} } { }
	Inline constexpr FixedString ( auto...chars )noexcept : m_data { chars... } { }
	Inline static constexpr Compact<N> size ( )noexcept { return N; }
	template<class Self>Inline constexpr Like<Self, T> operator[]( this Self&& self, std::size_t index ) noexcept { return static_cast< Like<Self, T> >( FWD ( self ).m_data [ index ] ); }//msvc bug
	Inline constexpr const T* begin ( )const noexcept { return m_data; }
	Inline constexpr const T* end ( )const noexcept { return m_data + size ( ); }
	Inline constexpr const T* data ( )const noexcept { return begin ( ); }
	Inline constexpr bool operator==( const FixedString<T, N>& )const noexcept = default;
	Inline constexpr bool operator!=( const FixedString<T, N>& )const noexcept = default;
	using char_type = T;
	T m_data [ N ];
};
template<class T>
struct FixedString<T, 0> {
	Inline constexpr FixedString ( const T ( & ) [ 1 ] )noexcept { }
	Inline constexpr FixedString ( )noexcept { }
	Inline static constexpr std::uint8_t size ( )noexcept { return 0; }
	template<class Self>Inline constexpr Like<Self, T> operator[]( this Self&&, std::size_t ) noexcept;
	Inline constexpr const T* begin ( )const noexcept { return nullptr; }
	Inline constexpr const T* end ( )const noexcept { return nullptr; }
	Inline constexpr const T* data ( )const noexcept { return nullptr; }
	Inline constexpr bool operator==( const FixedString<T, 0>& )const noexcept { return true; }
	Inline constexpr bool operator!=( const FixedString<T, 0>& )const noexcept { return false; }
	using char_type = T;
};
template<class Char, std::size_t N>FixedString ( const Char ( & ) [ N ] ) -> FixedString<Char, N - 1>;
template<class Char, $Same<Char>...Chars>FixedString ( Char, Chars... ) -> FixedString<Char, sizeof...( Chars ) + 1>;
template<class T, std::size_t Size>
concept $Size = sizeof ( T ) == Size;
template<class T>concept $HasBeginEnd = requires( const T container ) { container.begin ( ) != container.end ( ); };
template<class T>concept $HasDataSize = requires( const T container ) { container.data ( ) + container.size ( ); };
template<class T>concept $CArray = std::is_array<typename std::remove_cvref<T>::type>::value;
namespace details
{
	template<class Container>struct ElementOfImpl { using type = std::remove_cvref_t<decltype( *std::declval<const std::remove_cvref_t<Container>> ( ).data ( ) )>; };
	template<$CArray Container>struct ElementOfImpl<Container> { using type = std::remove_cvref_t<decltype( *std::declval<Container> ( ) )>; };
}
template<class Container>using ElementOf = typename details::ElementOfImpl<Container>::type;
namespace Algorithm
{
	template<$HasDataSize Container>
	Inline constexpr void bubble_sort ( Container&& container, Callable<bool ( const ElementOf<Container>, const ElementOf<Container> )> auto&& compare )noexcept {
		using Index = std::remove_cvref_t<decltype( container.size ( ) )>;
		const Index n { container.size ( ) };
		if ( n )
			for ( Index i {}; i != n - 1; ++i )
				for ( Index j {}; j < n - i - 1; ++j )
					if ( !FWD ( compare )( container [ j ], container [ j + 1 ] ) )
						std::swap ( container [ j ], container [ j + 1 ] );
	}
	template<$HasBeginEnd Container>
	Inline constexpr void stable_sort ( Container&& container, Callable<bool ( const ElementOf<Container>, const ElementOf<Container> )> auto&& compare )noexcept {
		if ( std::is_constant_evaluated ( ) )
			bubble_sort ( FWD ( container ), FWD ( compare ) );
		else
			std::stable_sort ( container.begin ( ), container.end ( ), FWD ( compare ) );
	}
}
template<auto Value>constexpr auto constant { Value };
template<std::uint8_t Bits>struct UnsignedBitsImpl { };
template<std::uint8_t Bits> using UnsignedBits = typename UnsignedBitsImpl<Bits>::type;
template<> struct UnsignedBitsImpl<8> { using type = std::uint8_t; };
template<> struct UnsignedBitsImpl<16> { using type = std::uint16_t; };
template<> struct UnsignedBitsImpl<32> { using type = std::uint32_t; };
template<> struct UnsignedBitsImpl<64> { using type = std::uint64_t; };
template<class T>concept $Dtor = !std::is_trivially_destructible_v<T>;
template<class T>concept $NotCvref = $Same<T, std::remove_cvref_t<T>>;
template<$NotCvref T>
struct Opt {
#if GCC//gcc bug
	T m_value {};
#else
	union { T m_value; };
#endif
	bool m_hasValue;
	Inline constexpr Opt ( )noexcept :m_hasValue {} { }
	Inline constexpr Opt ( auto&&...args )noexcept requires( requires{T { FWD ( args )... }; } ) : m_value { FWD ( args )... }, m_hasValue { true } { }
	Inline constexpr Opt& operator=( const Opt& rhs )noexcept {
		( *this ).~Opt ( );
		std::construct_at ( this, rhs );
		return *this;
	}
	Inline constexpr Opt& operator=( Opt&& rhs )noexcept {
		( *this ).~Opt ( );
		std::construct_at ( this, MOV ( rhs ) );
		return *this;
	}
	Inline constexpr Opt& operator=( auto&& args )noexcept
		requires( requires{T { FWD ( args ) }; } ) {
		( *this ).~Opt ( );
		std::construct_at ( this, FWD ( args ) );
		return *this;
	}
	Inline constexpr void emplace ( auto&&...args )noexcept
		requires( requires{T { FWD ( args )... }; } ) {
		std::construct_at ( this, FWD ( args )... );
		m_hasValue = true;
	}
	Inline constexpr void reset ( )noexcept {
		if ( m_hasValue ) {
			if constexpr ( $Dtor<T> )
				m_value.~T ( );
			m_hasValue = false;
		}
	}
	Inline constexpr ~Opt ( )noexcept {
		if constexpr ( $Dtor<T> )
			if ( m_hasValue )
				m_value.~T ( );
	}
	Inline constexpr Opt ( const Opt& rhs )noexcept :m_hasValue { rhs.m_hasValue } {
		if ( m_hasValue )
			std::construct_at ( __builtin_addressof( m_value ), rhs.m_value );
	}
	Inline constexpr Opt ( Opt&& rhs )noexcept :m_hasValue { rhs.m_hasValue } {
		if ( m_hasValue ) {
			std::construct_at ( __builtin_addressof( m_value ), MOV ( rhs.m_value ) );
			rhs.m_hasValue = false;
		}
	}
	Inline constexpr explicit operator bool ( )const noexcept { return m_hasValue; }
	Inline constexpr bool has_value ( )const noexcept { return m_hasValue; }
	template<class Self>Inline constexpr Like<Self, T> value ( this Self&& self ) noexcept { return FWD ( self ).m_value; }
	template<class Self>Inline constexpr Like<Self, T> operator*( this Self&& self ) noexcept { return FWD ( self ).m_value; }
	template<class Self>Inline constexpr LikePtr<Self, T> operator->( this Self&& self ) noexcept { return __builtin_addressof( self.m_value ); }
};
template<class T>Inline constexpr bool operator==( const Opt<T>& l, const Opt<T>& r )noexcept {
	if ( l.has_value ( ) )
		return r.has_value ( ) && *l == *r;
	else
		return !r.has_value ( );
}
template<class T>Inline constexpr bool operator!=( const Opt<T>& l, const Opt<T>& r )noexcept { return !( l == r ); }
template<class T>Inline constexpr bool operator==( const Opt<T>& l, const T& r )noexcept { return l && ( *l == r ); }
template<class T>Inline constexpr bool operator==( const T& l, const Opt<T>& r )noexcept { return r && ( l == *r ); }
template<class T>Inline constexpr bool operator!=( const Opt<T>& l, const T& r )noexcept { return !l || ( *l != r ); }
template<class T>Inline constexpr bool operator!=( const T& l, const Opt<T>& r )noexcept { return !r || ( l != *r ); }
#if CLANG || GCC
template<class T, class...Ts>concept $AnyOf = ( __is_same ( T, Ts ) || ... );
#else
template<class T, class...Ts>concept $AnyOf = ( std::is_same_v<T, Ts> || ... );
#endif
template<class T, class U>concept $Assignable = requires( U & u, const T x ) { u = x; };
namespace Bytes
{
	template<$Same<std::uint16_t> T>Inline constexpr T concat ( std::uint8_t v0, std::uint8_t v1 ) noexcept { return v0 | ( v1 << 8 ); }
	template<$Same<std::uint32_t> T>Inline constexpr T concat ( std::uint8_t v0, std::uint8_t v1, std::uint8_t v2, std::uint8_t v3 ) noexcept { return v0 | ( v1 << 8 ) | ( v2 << 16 ) | ( v3 << 24 ); }
	template<$Same<std::uint64_t> T>Inline constexpr T concat ( std::uint8_t v0, std::uint8_t v1, std::uint8_t v2, std::uint8_t v3, std::uint8_t v4, std::uint8_t v5, std::uint8_t v6, std::uint8_t v7 ) noexcept { return std::uint64_t ( v0 ) | ( std::uint64_t ( v1 ) << 8 ) | ( ( std::uint64_t ) ( v2 ) << 16 ) | ( std::uint64_t ( v3 ) << 24 ) | ( std::uint64_t ( v4 ) << 32 ) | ( std::uint64_t ( v5 ) << 40 ) | ( std::uint64_t ( v6 ) << 48 ) | ( std::uint64_t ( v7 ) << 56 ); }
}
namespace BytePattern
{
	struct Nibbles {
		std::uint8_t low : 4;
		std::uint8_t high : 4;
	};
	struct ComparisonEntryNibble {
		std::size_t offset;
		Opt<std::uint8_t> low;
		Opt<std::uint8_t> high;
	};
	struct ComparisonEntryBytes {
		std::size_t offset {};
		std::uint8_t size {};
	};
	struct Element {
		Opt<std::uint8_t> low, high, byte;
		constexpr Element ( Opt<std::uint8_t> low, Opt<std::uint8_t> high )noexcept :low { low }, high { high }, byte { ( low && high ) ? static_cast< std::uint8_t >( *low | ( *high << 4 ) ) : Opt<std::uint8_t>{} } { }
		constexpr Element ( std::uint8_t byte )noexcept :low { static_cast< std::uint8_t >( byte & 0x0f ) }, high { static_cast< std::uint8_t >( static_cast< std::uint8_t >( byte & 0xf0 ) >> 4 ) }, byte { ( low && high ) ? static_cast< std::uint8_t >( *low | ( *high << 4 ) ) : Opt<std::uint8_t>{} } { }
		constexpr Element ( )noexcept { }
		constexpr bool operator==( const Element& r )noexcept { return low == r.low && high == r.high; }
	};

	namespace details
	{
		template<auto OriginalElements, std::size_t... IndexesToClear>
		consteval auto create_modified_array_for_sequence ( ) noexcept {
			auto new_array = OriginalElements; // OriginalElements is std::array<BytePattern::Element, N>
			// Element is BytePattern::Element, visible due to nested namespace.
			( ( std::get<IndexesToClear> ( new_array ) = Element {} ), ... );
			return new_array;
		}
	}

	template<auto Elements>
	struct Sequence {
		static constexpr std::size_t numElements { Elements.size ( ) };
		static constexpr std::array<Element, numElements> elements { Elements };
		static constexpr ConstVector<ComparisonEntryBytes, numElements> bytesEntries { [ ]
		{
			ConstVector<ComparisonEntryBytes, numElements> result;
			std::size_t start{};
			for ( ;;) {
				while ( start < numElements && !elements [ start ].byte )++start;//skip wildcards/nibbles
				if ( start >= numElements )break;
				std::size_t iNextNonByte{ start + 1 };
				while ( iNextNonByte < numElements&& elements [ iNextNonByte ].byte )++iNextNonByte;
				const std::size_t dist{ iNextNonByte - start };
				const std::uint8_t compareLength{ ( dist >= 8 && sizeof ( void* ) >= 8 ) ? std::uint8_t ( 8 ) : ( dist >= 4 ? std::uint8_t ( 4 ) : ( dist >= 2 ? std::uint8_t ( 2 ) : std::uint8_t ( 1 ) ) )};
				result.push_back ( { start, compareLength } );
				start += compareLength;
			}
			Algorithm::stable_sort ( result,[ ] ( const ComparisonEntryBytes& l, const ComparisonEntryBytes& r ) { return l.size > r.size; } );
			return result;
		}( ) };
		static constexpr ConstVector<ComparisonEntryNibble, numElements> nibbleEntries { [ ]
		{
			ConstVector<ComparisonEntryNibble, numElements> result;
			std::size_t offset{};
			for ( Element e : elements ) {
				if ( e.low.has_value ( ) ^ e.high.has_value ( ) )
					result.push_back ( { offset, e.low, e.high } );
				++offset;
			}
			return result;
		}( ) };
		template<auto I, $Size<1> Uint8>
		Inline static constexpr bool cmpBytesEntries ( Uint8* ptr )noexcept {
			static constexpr ComparisonEntryBytes entry { bytesEntries [ I ] };
			static constexpr std::size_t offset { entry.offset };
			static constexpr std::uint8_t size { entry.size };
			static constexpr auto bytes { [ ] ( )->UnsignedBits<size * 8>
			{
				/* */if constexpr ( size == 1 )return *elements [ offset ].byte;
				else if constexpr ( size == 2 )return Bytes::concat<std::uint16_t> ( *elements [ offset ].byte, *elements [ offset + 1 ].byte );
				else if constexpr ( size == 4 )return Bytes::concat<std::uint32_t> ( *elements [ offset ].byte, *elements [ offset + 1 ].byte, *elements [ offset + 2 ].byte, *elements [ offset + 3 ].byte );
				else if constexpr ( size == 8 )return Bytes::concat<std::uint64_t> ( *elements [ offset ].byte, *elements [ offset + 1 ].byte, *elements [ offset + 2 ].byte, *elements [ offset + 3 ].byte, *elements [ offset + 4 ].byte, *elements [ offset + 5 ].byte, *elements [ offset + 6 ].byte, *elements [ offset + 7 ].byte );
			}( ) };
			return *reinterpret_cast< const decltype( bytes )* >( ptr + offset ) == bytes;
		}
		template<auto I, $Size<1> Uint8>
		Inline static constexpr bool cmpNibbleEntry ( Uint8* ptr )noexcept {
			static constexpr ComparisonEntryNibble entry { nibbleEntries [ I ] };
			static constexpr std::size_t offset { entry.offset };
			static constexpr Opt<std::uint8_t> low { entry.low };
			static constexpr Opt<std::uint8_t> high { entry.high };
			if constexpr ( low )
				return reinterpret_cast< const Nibbles* >( ptr + offset )->low == constant<*low>;
			else if constexpr ( high )
				return reinterpret_cast< const Nibbles* >( ptr + offset )->high == constant<*high>;
		}
		template<$Size<1> Uint8, auto...I, auto...J>
		Inline static constexpr bool isMatchImpl ( Uint8* ptr, std::index_sequence<I...>, std::index_sequence<J...> )noexcept {
			return ( cmpBytesEntries<I> ( ptr )&&... ) && ( cmpNibbleEntry<J> ( ptr )&&... );
		}
		template<$Size<1> Uint8>
		Inline static constexpr bool isMatch ( Uint8* ptr )noexcept {
			return isMatchImpl ( ptr, std::make_index_sequence<bytesEntries.size ( )>{}, std::make_index_sequence<nibbleEntries.size ( )>{} );
		}
		template<std::size_t...Indexes>
		static consteval auto deleteElement ( )noexcept {
			return Sequence<details::create_modified_array_for_sequence<Elements, Indexes...> ( )>{};
		}
	};
	template<FixedString str>
	constexpr ConstVector<Element, str.size ( )> parsePatternString ( )noexcept {
		constexpr auto isHexDigit { [ ] ( char c ) { return ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' ) || ( c >= 'A' && c <= 'F' ); } };
		constexpr auto char2hexDigit { [ ] ( char c )-> std::uint8_t
		{
			if ( c >= '0' && c <= '9' ) return c - '0';
			if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
			if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
			UNREACHABLE;
		} };
		constexpr std::size_t size { str.size ( ) };
		const char* pBegin { str.data ( ) };
		const char* pEnd { pBegin + size };
		ConstVector<Element, size> result;
		if constexpr ( size ) {
			bool expectSpace {};
			for ( const char* pChar { pBegin }; pChar != pEnd;) {
				const char c { *pChar };
				if ( c == ' ' ) {
					if ( !expectSpace )
						UNREACHABLE;
					++pChar;
					expectSpace = false;
				}
				else {
					if ( expectSpace )UNREACHABLE;
					if ( c == '?' ) {
						if ( pChar + 1 == pEnd ) {
							pChar += 1;
							result.push_back ( {} );
						}
						else {
							const char c1 { pChar [ 1 ] };
							if ( c1 == ' ' ) {
								pChar += 1;
								result.push_back ( {} );
							}
							else if ( c1 == '?' ) {
								pChar += 2;
								result.push_back ( {} );
							}
							else if ( isHexDigit ( c1 ) ) {
								result.push_back ( Element { char2hexDigit ( c1 ), {} } );
								pChar += 2;
							}
							else
								UNREACHABLE;
						}
					}
					else {
						if ( !isHexDigit ( c ) )UNREACHABLE;
						if ( pChar + 1 == pEnd ) {
							result.push_back ( char2hexDigit ( c ) );
							pChar += 1;
						}
						else {
							const char c1 { pChar [ 1 ] };
							if ( c1 == ' ' ) {
								result.push_back ( char2hexDigit ( c ) );
								pChar += 1;
							}
							else if ( c1 == '?' ) {
								result.push_back ( Element { {}, char2hexDigit ( c ) } );
								pChar += 2;
							}
							else if ( isHexDigit ( c1 ) ) {
								result.push_back ( static_cast< std::uint8_t >( char2hexDigit ( c ) * 0x10 + char2hexDigit ( c1 ) ) );
								pChar += 2;
							}
							else
								UNREACHABLE;
						}
					}
					expectSpace = true;
				}
			}
		}
		return result;
	}
	template<FixedString str>
	constexpr auto makeBytePattern ( )noexcept {
		constexpr ConstVector<Element, str.size ( )> arr { parsePatternString<str> ( ) };
		return [ = ]<auto...I>( std::index_sequence<I...> ) {
			return Sequence < std::array<Element, arr.size ( )>{arr [ I ]...} > {};
		}( std::make_index_sequence<arr.size ( )>{} );
	}
}
template<class Container, class T>concept LinearContainerOf = requires{ *( std::declval<Container> ( ).data ( ) + std::declval<Container> ( ).size ( ) ); }&& $Same<std::remove_cvref_t<decltype( *( std::declval<Container> ( ).data ( ) + std::declval<Container> ( ).size ( ) ) )>, std::remove_cvref_t<T>>;
template<class Container, class...Ts>concept LinearContainerAnyOf = ( LinearContainerOf<Container, Ts> || ... );
template<class T>concept $UInt = std::is_integral_v<std::remove_cvref_t<T>> && std::is_unsigned_v<std::remove_cvref_t<T>>;
namespace Bits
{
	template <$UInt T>Inline constexpr T clearLowestBit ( T value ) noexcept { return value & ( value - 1 ); }
	//Returns the number of trailing 0-bits in x, starting at the least significant bit position. If x is 0, the result is undefined
	Inline constexpr std::uint32_t trailingZeroCount ( std::uint32_t x )noexcept {
	#if MSVC
		if ( std::is_constant_evaluated ( ) ) {
			if ( x == 0 ) return 32; // Defined behavior for 0 for ctz in C++20 is width.
			std::uint32_t count { 0 };
			while ( ( x & 1 ) == 0 && count < 32 ) {
				x >>= 1;
				++count;
			}
			return count;
		}
		else {
			unsigned long result;
			if ( _BitScanForward ( &result, x ) ) // _BitScanForward returns non-zero on success
				return static_cast< std::uint32_t > ( result );
			return 32; // If x is 0, result is undefined, _BitScanForward returns 0. Match C++20 __builtin_ctz.
		}
	#else
		return static_cast< std::uint32_t >( __builtin_ctz ( x ) );
	#endif
	}
}
#if MSVC
#define DEFINE_AVX_BYTES(name,x) static constexpr __m256i name{ .m256i_u8{x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x} }
#else
#define DEFINE_AVX_BYTES(name,x) static constexpr __m256i name{ __builtin_bit_cast(__m256i,std::array<std::uint8_t,32>{x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x}) }
#endif
namespace BytePattern
{
	template<auto pattern, std::intptr_t Offset>
	struct Scanner {
		using Pattern = decltype( pattern );
		static constexpr std::intptr_t offset { Offset };
		static constexpr std::size_t numElements { Pattern::numElements };
		static constexpr Opt<std::size_t> iFirstByte { [ ] ( )->Opt<std::size_t>
		{
			for ( std::size_t i{}; i < Pattern::elements.size ( ); ++i )
				if ( Pattern::elements [ i ].byte )
					return i;
			return {};
		}( ) };
		static constexpr Opt<std::size_t> iLastByte { [ ] ( )->Opt<std::size_t>
		{
			std::size_t result{Pattern::elements.size ( )};
			for ( std::size_t i{}; i < Pattern::elements.size ( ); ++i )
				if ( Pattern::elements [ i ].byte )
					result = i;
			if ( result == Pattern::elements.size ( ) )return {};
			else return result;
		}( ) };
		//bytes == 0, nibbles >= 1
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>
			requires( !iFirstByte.has_value ( ) )
		Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search_unbounded ( Uint8* pBegin, Action&&...action )noexcept//todo:optimize
		{
			for ( ;;) {
				if ( Pattern::isMatch ( pBegin ) ) [[unlikely]]
				{
					( action ( pBegin + offset ), ... );
					if constexpr ( sizeof...( action ) == 0 )
						return pBegin + offset;
				}
				++pBegin;
			}
		}
		//bytes == 1, nibbles >= 0
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>
			requires( iFirstByte.has_value ( ) && iLastByte.has_value ( ) && *iFirstByte == *iLastByte )
		Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search_unbounded ( Uint8* pBegin, Action&&...action )noexcept {
			static constexpr auto iFirst { compact<*iFirstByte> };
			DEFINE_AVX_BYTES ( first, *Pattern::elements [ iFirst ].byte );
			for ( ;; pBegin += sizeof ( __m256i ) ) {
				const __m256i block { _mm256_loadu_si256 ( reinterpret_cast< const __m256i* >( pBegin + iFirst ) ) };
				const __m256i eq { _mm256_cmpeq_epi8 ( first, block ) };
				for ( std::uint32_t mask { static_cast< std::uint32_t >( _mm256_movemask_epi8 ( eq ) ) }; mask; mask = Bits::clearLowestBit ( mask ) ) [[unlikely]]
				{
					const auto bitPos { Bits::trailingZeroCount ( mask ) };
					if ( decltype( Pattern::template deleteElement<iFirst> ( ) )::isMatch ( pBegin + bitPos ) ) [[unlikely]]
					{
						( action ( pBegin + bitPos + offset ), ... );
						if constexpr ( sizeof...( action ) == 0 )
							return pBegin + bitPos + offset;
					}
				}
			}
		}
		//bytes >= 2, nibbles >= 0
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>
			requires( iFirstByte.has_value ( ) && iLastByte.has_value ( ) && *iFirstByte != *iLastByte )
		Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search_unbounded ( Uint8* pBegin, Action&&...action )noexcept {
			static constexpr auto iFirst { compact<*iFirstByte> };
			static constexpr auto iLast { compact<*iLastByte> };
			DEFINE_AVX_BYTES ( first, *Pattern::elements [ iFirst ].byte );
			DEFINE_AVX_BYTES ( last, *Pattern::elements [ iLast ].byte );
			for ( ;; pBegin += sizeof ( __m256i ) ) {
				const __m256i block_first { _mm256_loadu_si256 ( reinterpret_cast< const __m256i* >( pBegin + iFirst ) ) };
				const __m256i block_last { _mm256_loadu_si256 ( reinterpret_cast< const __m256i* >( pBegin + iLast ) ) };
				const __m256i eq_first { _mm256_cmpeq_epi8 ( first, block_first ) };
				const __m256i eq_last { _mm256_cmpeq_epi8 ( last, block_last ) };
				for ( std::uint32_t mask { static_cast< std::uint32_t >( _mm256_movemask_epi8 ( _mm256_and_si256 ( eq_first, eq_last ) ) ) }; mask != 0; mask = Bits::clearLowestBit ( mask ) ) [[unlikely]]
				{
					const auto bitPos { Bits::trailingZeroCount ( mask ) };
					if ( decltype( Pattern::template deleteElement<iFirst, iLast> ( ) )::isMatch ( pBegin + bitPos ) ) [[unlikely]]
					{
						( action ( pBegin + bitPos + offset ), ... );
						if constexpr ( sizeof...( action ) == 0 )
							return pBegin + bitPos + offset;
					}
				}
			}
		}
		//bytes == 0, nibbles >= 1
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>
			requires( !iFirstByte.has_value ( ) )
		Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search ( Uint8* pBegin, std::size_t size, Action&&...action )noexcept//todo:optimize
		{
			if ( size >= numElements ) [[likely]]//prevent pEnd underflow
			{
				Uint8* const pEnd { pBegin + size - numElements };
				while ( pBegin <= pEnd ) [[likely]]
				{
					if ( Pattern::isMatch ( pBegin ) ) [[unlikely]]
					{
						( action ( pBegin + offset ), ... );
						if constexpr ( sizeof...( action ) == 0 )
							return pBegin + offset;
					}
					++pBegin;
				}
			}
			if constexpr ( sizeof...( action ) == 0 )
				return nullptr;
		}
		//bytes == 1, nibbles >= 0
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>
			requires( iFirstByte.has_value ( ) && iLastByte.has_value ( ) && *iFirstByte == *iLastByte )
		Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search ( Uint8* pBegin, std::size_t size, Action&&...action )noexcept {
			static constexpr auto iFirst { compact<*iFirstByte> };
			DEFINE_AVX_BYTES ( first, *Pattern::elements [ iFirst ].byte );
			if ( size >= numElements ) [[likely]]//prevent pEnd underflow
			{
				Uint8* const pEnd { pBegin + size - numElements };
				if ( numElements > 0 && size >= numElements + sizeof ( __m256i ) - 1 ) // Ensure pBegin + iFirst + (sizeof(__m256i) -1) is valid. More general: size >= iFirst + sizeof(__m256i) && size >= numElements
					// Simpler check: size >= iFirst + sizeof(__m256i)
					// Corrected check for loop: (pBegin + iFirst) should be readable up to (pBegin + iFirst + sizeof(__m256i) -1)
					// The loop runs as long as (pBegin + iFirst + sizeof(__m256i) -1) < (pBegin_orig + size).
					// And also pBegin <= pEnd.
					// A common way to write this is: pEndSimd = pBegin_orig + size - (iFirst + sizeof(__m256i)). Loop while pBegin <= pEndSimd.
					// But pBegin is also used for Pattern::isMatch, which reads up to pBegin + numElements -1.
					// So, pBegin + numElements -1 < pBegin_orig + size.
					// Let's use a conservative bound that satisfies both SIMD reads and scalar pattern matching.
					// For SIMD: pBegin + iFirst + sizeof(__m256i) <= pBegin_orig + size
					// For scalar: pBegin + numElements <= pBegin_orig + size
					// So pBegin must be <= pBegin_orig + size - max(iFirst + sizeof(__m256i), numElements)
					// The original condition was: size >= numElements + sizeof(__m256i). This implies pBegin <= pEndSimd where pEndSimd = pBegin_orig + size - numElements - sizeof(__m256i)
					// This is safe for pBegin in Pattern::isMatch. But is it safe for _mm256_loadu_si256(ptr + iFirst)?
					// pBegin + iFirst for _mm256_loadu_si256 should be fine if pBegin increments by sizeof(__m256i) and max pBegin in loop is pEndSimd.
					// Max address read by SIMD: pEndSimd + iFirst + sizeof(__m256i) - 1
					// = pBegin_orig + size - numElements - sizeof(__m256i) + iFirst + sizeof(__m256i) - 1
					// = pBegin_orig + size - numElements + iFirst - 1
					// This must be < pBegin_orig + size. So, size - numElements + iFirst - 1 < size --> iFirst < numElements + 1. (This is true if iFirst is a valid index)
					// The original condition `size >= numElements + sizeof(__m256i)` seems fine and conservative.
				{
					Uint8* const pEndSimd { pBegin + size - ( numElements > 0 ? numElements - 1 : 0 ) - sizeof ( __m256i ) }; // ensure pBegin + (numElements-1) is valid and pBegin + iFirst + sizeof(__m256i) -1 is valid
					for ( ; pBegin <= pEndSimd; pBegin += sizeof ( __m256i ) ) { // Check if pBegin + iFirst is safe for load
						const __m256i block { _mm256_loadu_si256 ( reinterpret_cast< const __m256i* >( pBegin + iFirst ) ) };
						const __m256i eq { _mm256_cmpeq_epi8 ( first, block ) };
						for ( std::uint32_t mask { static_cast< std::uint32_t >( _mm256_movemask_epi8 ( eq ) ) }; mask; mask = Bits::clearLowestBit ( mask ) ) [[unlikely]]
						{
							const auto bitPos { Bits::trailingZeroCount ( mask ) };
							if ( pBegin + bitPos <= pEnd ) { // Check candidate is not past pEnd
								if ( decltype( Pattern::template deleteElement<iFirst> ( ) )::isMatch ( pBegin + bitPos ) ) [[unlikely]]
								{
									( action ( pBegin + bitPos + offset ), ... );
									if constexpr ( sizeof...( action ) == 0 )
										return pBegin + bitPos + offset;
								}
							}
							else { // if bitPos would go past pEnd, subsequent bits also will.
								break;
							}
						}
					}
				}
				[[unlikely]]; // Fallthrough for remaining part or small sizes
				for ( ; pBegin <= pEnd; ++pBegin )
					if ( Pattern::isMatch ( pBegin ) ) [[unlikely]]
					{
						( action ( pBegin + offset ), ... );
						if constexpr ( sizeof...( action ) == 0 )
							return pBegin + offset;
					}
			}
			if constexpr ( sizeof...( action ) == 0 )
				return nullptr;
		}
		//bytes >= 2, nibbles >= 0
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>
			requires( iFirstByte.has_value ( ) && iLastByte.has_value ( ) && *iFirstByte != *iLastByte )
		Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search ( Uint8* pBegin, std::size_t size, Action&&...action )noexcept {
			static constexpr auto iFirst { compact<*iFirstByte> };
			static constexpr auto iLast { compact<*iLastByte> };
			DEFINE_AVX_BYTES ( first, *Pattern::elements [ iFirst ].byte );
			DEFINE_AVX_BYTES ( last, *Pattern::elements [ iLast ].byte );
			if ( size >= numElements ) [[likely]]//prevent pEnd underflow
			{
				Uint8* const pEnd { pBegin + size - numElements };
				// Ensure reads for block_first and block_last are valid.
				// Max index read is iLast. So, pBegin + iLast + sizeof(__m256i) -1 must be < pBegin_orig + size
				// pBegin loop max: pBegin_orig + size - (iLast + sizeof(__m256i))
				// The loop needs pBegin <= pEndSimd.
				// pEndSimd should be pBegin_orig + size - std::max(numElements, iLast + (std::uint8_t)sizeof(__m256i)); (rough idea)
				// The original condition: size >= sizeof ( __m256i ) + iLast
				// This means pBegin_orig + size >= pBegin_orig + sizeof(__m256i) + iLast
				// So pEndSimd = pBegin_orig + size - (sizeof(__m256i) + iLast) is well-defined.
				// Max address read for block_last: (pEndSimd) + iLast + sizeof(__m256i) -1
				// = pBegin_orig + size - sizeof(__m256i) - iLast + iLast + sizeof(__m256i) -1 = pBegin_orig + size -1. This is safe.
				// Also need to ensure pBegin + bitPos <= pEnd for the scalar check.
				if ( size >= ( iLast + sizeof ( __m256i ) ) && size >= numElements ) [[likely]]
				{
					// Ensure pBegin for Pattern::isMatch never exceeds pEnd.
					// pBegin for SIMD can go up to a point where pBegin + iLast + sizeof(__m256i) -1 is the last byte of the buffer.
					// Max offset for SIMD read is iLast.
					Uint8* const pEndSimd { pBegin + size - ( iLast + sizeof ( __m256i ) ) };
					for ( ; pBegin <= pEndSimd; pBegin += sizeof ( __m256i ) ) [[likely]]
					{
						const __m256i block_first { _mm256_loadu_si256 ( reinterpret_cast< const __m256i* >( pBegin + iFirst ) ) };
						const __m256i block_last { _mm256_loadu_si256 ( reinterpret_cast< const __m256i* >( pBegin + iLast ) ) };
						const __m256i eq_first { _mm256_cmpeq_epi8 ( first, block_first ) };
						const __m256i eq_last { _mm256_cmpeq_epi8 ( last, block_last ) };
						for ( std::uint32_t mask { static_cast< std::uint32_t >( _mm256_movemask_epi8 ( _mm256_and_si256 ( eq_first, eq_last ) ) ) }; mask != 0; mask = Bits::clearLowestBit ( mask ) ) [[unlikely]]
						{
							const auto bitPos { Bits::trailingZeroCount ( mask ) };
							if ( pBegin + bitPos <= pEnd ) { // Check candidate is not past pEnd
								if ( decltype( Pattern::template deleteElement<iFirst, iLast> ( ) )::isMatch ( pBegin + bitPos ) ) [[unlikely]]
								{
									( action ( pBegin + bitPos + offset ), ... );
									if constexpr ( sizeof...( action ) == 0 )
										return pBegin + bitPos + offset;
								}
							}
							else { // if bitPos would go past pEnd
								break;
							}
						}
					}
				}
				[[unlikely]]; // Fallthrough for remaining part or small sizes
				for ( ; pBegin <= pEnd; ++pBegin )
					if ( Pattern::isMatch ( pBegin ) ) [[unlikely]]
					{
						( action ( pBegin + offset ), ... );
						if constexpr ( sizeof...( action ) == 0 )
							return pBegin + offset;
					}
			}
			if constexpr ( sizeof...( action ) == 0 )
				return nullptr;
		}
		template<$Size<1> Uint8, Callable<void ( Uint8* const )>...Action>Inline static std::conditional_t<sizeof...( Action ) == 0, Uint8*, void> search ( Uint8* pBegin, Uint8* pEnd, Action&&...action )noexcept { return search ( pBegin, static_cast< std::size_t >( pEnd - pBegin ), FWD ( action )... ); } // Added FWD
		template<LinearContainerAnyOf<char, std::uint8_t> Container, Callable<void ( ElementOf<Container>* )>...Action>Inline static auto search ( Container&& bytes, Action&&...action )noexcept { return search ( bytes.data ( ), bytes.size ( ), FWD ( action )... ); } // Added FWD
	};
}
template<FixedString str, std::intptr_t offset = 0>constexpr BytePattern::Scanner<BytePattern::makeBytePattern<str> ( ), offset> byte_scanner {};
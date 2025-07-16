#pragma once

#include <type_traits>
#include <cstdint>
#include "types.hpp"

template <typename T>
struct BitWidth {
  static constexpr size_t value = 0;
};

template <> struct BitWidth<uint64_t> { static constexpr size_t value = 64; };
template <> struct BitWidth<uint128_t> { static constexpr size_t value = 128; };
template <> struct BitWidth<uint256_t> { static constexpr size_t value = 256; };
template <> struct BitWidth<uint512_t> { static constexpr size_t value = 512; };

template <typename T>
struct SignedType {
  using type = void;
};

template <> struct SignedType<uint64_t> { using type = int64_t; };
template <> struct SignedType<uint128_t> { using type = int128_t; };
template <> struct SignedType<uint256_t> { using type = int256_t; };
template <> struct SignedType<uint512_t> { using type = int512_t; };

template <typename T>
inline typename SignedType<T>::type sign_extend ( T value, size_t op_size ) {
  if ( op_size == 0 || op_size > BitWidth<T>::value / 8 ) {
    throw std::runtime_error ( "Invalid operand size for sign extension" );
  }
  using SignedT = typename SignedType<T>::type;
  constexpr size_t bit_width = BitWidth<T>::value;
  return static_cast< SignedT >( value << ( bit_width - op_size * 8 ) ) >> ( bit_width - op_size * 8 );
}

#define SIGN_EXTEND(value, op_size) sign_extend(value, op_size)
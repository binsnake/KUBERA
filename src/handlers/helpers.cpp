#include "helpers.hpp"

bool helpers::divide_unsigned_boost ( uint128_t dividend, uint64_t divisor, size_t op_size, uint64_t& quotient, uint64_t& remainder ) {
	if ( divisor == 0 ) {
		return true;
	}

	uint128_t q = dividend / divisor;
	uint128_t r = dividend % divisor;

	uint128_t max_quotient_val = GET_OPERAND_MASK ( op_size );

	if ( q > max_quotient_val ) {
		return true;
	}

	quotient = static_cast< uint64_t >( q );
	remainder = static_cast< uint64_t >( r );
	return false;
}

bool helpers::divide_signed_boost ( int128_t dividend, int64_t divisor, size_t op_size, int64_t& quotient, int64_t& remainder ) {
	int bits = static_cast<int>(op_size * 8);

	if ( divisor == 0 ) {
		return true;
	}

	int bits_dividend = bits * 2;
	if ( bits_dividend > 128 ) bits_dividend = 128;

	int128_t min_dividend = -( int128_t ( 1 ) << ( bits_dividend - 1 ) );
	if ( dividend == min_dividend && divisor == -1 ) {
		return true;
	}

	int128_t q = dividend / divisor;
	int128_t r = dividend % divisor;

	int128_t min_quotient = -( int128_t ( 1 ) << ( bits - 1 ) );
	int128_t max_quotient = ( int128_t ( 1 ) << ( bits - 1 ) ) - 1;
	if ( q < min_quotient || q > max_quotient ) {
		return true;
	}

	quotient = static_cast< int64_t >( q );
	remainder = static_cast< int64_t >( r );
	return false;
}

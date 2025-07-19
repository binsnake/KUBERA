#pragma once

#include <cstdint>
#include <utility>
#include <context/KUBERA.hpp>

#define STK(x) *(uint64_t*)(x)
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

extern "C" void _syscall_host ( );

template< typename ReturnType = void, typename... Args,
	typename T1 = void*, typename T2 = void*, typename T3 = void*, typename T4 = void* >
inline ReturnType syscall ( const uint64_t Index, T1 A1 = { }, T2 A2 = { }, T3 A3 = { }, T4 A4 = { }, Args... Arguments ) {
	static_assert( sizeof ( void* ) == 8, "Only x64 is supported." );

	return reinterpret_cast< ReturnType ( * )( T1, T2, T3, T4, uint64_t, uint64_t, Args... ) >( _syscall_host )(
		A1, A2, A3, A4, Index, 0, Arguments...
		);
}

template<size_t... indeces>
auto generate_stk_arguments_helper ( kubera::KUBERA& ctx, std::index_sequence<indeces...> ) {
	return std::make_tuple ( STK (
		(uint64_t)ctx.get_virtual_memory ( )->translate ( 
			ctx.get_reg ( Register::RSP, 8 ), kubera::VirtualMemory::READ | kubera::VirtualMemory::WRITE )
		+ 0x28 + sizeof ( uint64_t ) * indeces )... );
}

template<size_t count>
auto generate_stk_arguments ( kubera::KUBERA& ctx ) {
	return generate_stk_arguments_helper ( ctx, std::make_index_sequence<count> ( ) );
}

template <uint32_t arg_count>
struct ArgumentTupleBuilder {
	static auto get_tuple ( kubera::KUBERA& a2 ) {
		if constexpr ( arg_count >= 4 )
			return std::make_tuple (
				a2.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( ),
				a2.get_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( ),
				a2.get_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t> ( ),
				a2.get_reg_internal<kubera::KubRegister::R9, Register::R9, uint64_t> ( )
			);
		else if constexpr ( arg_count == 3 )
			return std::make_tuple (
				a2.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( ),
				a2.get_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( ),
				a2.get_reg_internal<kubera::KubRegister::R8, Register::R8, uint64_t> ( )
			);
		else if constexpr ( arg_count == 2 )
			return std::make_tuple (
				a2.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( ),
				a2.get_reg_internal<kubera::KubRegister::RDX, Register::RDX, uint64_t> ( )
			);
		else if constexpr ( arg_count == 1 )
			return std::make_tuple (
				a2.get_reg_internal<kubera::KubRegister::R10, Register::R10, uint64_t> ( )
				);
	}
};

template<uint32_t arg_count>
constexpr auto generate_argument_list ( kubera::KUBERA& a2 ) {
	auto arg_tuple = ArgumentTupleBuilder<arg_count>::get_tuple ( a2 );
	if constexpr ( arg_count > 4 ) {
		constexpr uint32_t stk_argument_count = arg_count - 4;
		return std::tuple_cat ( std::move ( arg_tuple ), generate_stk_arguments<stk_argument_count> ( a2 ) );
	}
	else
		return arg_tuple;
}

template<uint32_t arg_count>
void dispatch_syscall ( const uint32_t syscall_number, kubera::KUBERA& a2 ) {
	auto arg_list = generate_argument_list<arg_count> ( a2 );
	std::apply ( [ & ] ( auto... fixed_args )
	{
		a2.set_reg_internal<kubera::KubRegister::RAX, Register::RAX, uint64_t> ( syscall<unsigned long> ( syscall_number, fixed_args... ) );
	}, arg_list );
}
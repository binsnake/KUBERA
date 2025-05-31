#include "pch.hpp"

template const uint8_t& EmulationContext::get_reg<uint8_t> ( x86_reg ) const;
template const uint16_t& EmulationContext::get_reg<uint16_t> ( x86_reg ) const;
template const uint32_t& EmulationContext::get_reg<uint32_t> ( x86_reg ) const;
template const uint64_t& EmulationContext::get_reg<uint64_t> ( x86_reg ) const;
template uint8_t& EmulationContext::get_reg_mut<uint8_t> ( x86_reg );
template uint16_t& EmulationContext::get_reg_mut<uint16_t> ( x86_reg );
template uint32_t& EmulationContext::get_reg_mut<uint32_t> ( x86_reg );
template uint64_t& EmulationContext::get_reg_mut<uint64_t> ( x86_reg );
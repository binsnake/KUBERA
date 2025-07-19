#pragma once

#include <context/KUBERA.hpp>
#include <map>
#include <string>
#include "module_manager.hpp"

namespace syscall_handlers
{
	inline std::map <uint32_t, void ( * )( uint32_t, kubera::KUBERA& ctx )> handler_map;
	inline std::map <uint32_t, std::string> handler_name_map;
	inline std::map<std::string, uint32_t> syscall_map;
	void dispatcher ( const iced::Instruction& instr, kubera::KUBERA& ctx );
	void dispatcher_verbose ( const iced::Instruction& instr, kubera::KUBERA& ctx );

	void build_syscall_map ( kubera::KUBERA& ctx, ModuleManager& mm );

	template <bool verbose>
	void init ( );
};
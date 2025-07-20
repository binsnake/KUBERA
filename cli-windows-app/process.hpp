#pragma once

#include <context/KUBERA.hpp>
#include <unordered_map>
#include "module_manager.hpp"

namespace process
{
	inline kubera::KUBERA ctx { };
	inline ModuleManager mm { ctx.get_virtual_memory ( ) };
};
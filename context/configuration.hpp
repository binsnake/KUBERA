#pragma once

#include <cstdint>

namespace kubera
{
	enum VendorType : uint8_t {
		INTEL = 0,
		AMD
	};
	struct ArchOptions {
		uint8_t x64 : 1;
		uint8_t verbose : 1;
		uint8_t exit_on_infinite_loop : 1;
		VendorType vendor : 1;
		uint8_t reserved : 4;
	};
};
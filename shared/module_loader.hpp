#pragma once

#include <shared/portable_executable.hpp>

#include <string>
#include <filesystem>
#include <memory>

class KModule {
private:
	PE::Parser parser;
	std::unique_ptr<uint8_t [ ]> mapping;
public:
	KModule ( ) = delete;
	KModule ( std::filesystem::path dll_path );
};
#pragma once
#include <filesystem>
#include <vector>
#include <string>
#include "analyzer.hpp"

class Scanner {
public:
    std::vector<std::filesystem::path> collect_files(const std::filesystem::path& root) const;

private:
    bool is_supported_extension(const std::filesystem::path& p) const;
};
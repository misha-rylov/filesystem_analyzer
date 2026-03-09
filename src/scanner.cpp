#include "scanner.hpp"
#include <unordered_set>
#include <algorithm>

bool Scanner::is_supported_extension(const std::filesystem::path& p) const {
    static const std::unordered_set<std::string> exts = {
        ".sys", ".bat", ".cmd", ".ps1",
        ".js", ".vbs", ".jar", ".apk", ".pdf", ".doc",
        ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z", ".so", ".bin"
    };

    auto ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return exts.count(ext) > 0;
}

std::vector<std::filesystem::path> Scanner::collect_files(const std::filesystem::path& root) const {
    std::vector<std::filesystem::path> files;
    if (!std::filesystem::exists(root)) return files;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             root, std::filesystem::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        const auto& p = entry.path();
        if (is_supported_extension(p)) files.push_back(p);
    }

    return files;
}
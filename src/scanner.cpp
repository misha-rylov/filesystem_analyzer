#include "scanner.hpp"
#include <unordered_set>
#include <algorithm>

bool Scanner::is_supported_extension(const std::filesystem::path& p) const {
    static const std::unordered_set<std::string> exts = {
        // Documents
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        // Archives
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        // Executables / Libraries
        ".sys", ".so", ".bin", ".dylib", ".dll",
        // Scripts
        ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".apk",
        // Video
        ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg", ".3gp", ".ogv",
        // Audio
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a", ".mid", ".amr"
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
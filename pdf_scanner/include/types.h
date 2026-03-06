#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>

namespace pdfscanner {

enum class Severity {
    Clean,
    Low,
    Medium,
    High,
    Critical
};

struct StringMatch {
    std::string identifier;
    size_t offset;
    std::string data;
};

struct RuleMatch {
    std::string rule_name;
    std::string namespace_;
    std::vector<StringMatch> strings;
    std::map<std::string, std::string> metadata;
    Severity severity;
};

struct ScanResult {
    std::string file_path;
    std::string file_name;
    size_t file_size;
    std::string md5;
    std::string sha1;
    std::string sha256;
    std::chrono::system_clock::time_point scan_time;
    std::vector<RuleMatch> matches;
    size_t threats_detected;
    Severity overall_severity;
    std::optional<std::string> error;
    
    ScanResult() : file_size(0), threats_detected(0), overall_severity(Severity::Clean) {}
};

struct ScanSummary {
    size_t total_files;
    size_t infected_files;
    size_t clean_files;
    std::chrono::system_clock::time_point scan_date;
};

} // namespace pdfscanner

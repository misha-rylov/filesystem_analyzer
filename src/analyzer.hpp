#pragma once
#include <string>
#include <vector>
#include <filesystem>

enum class ThreatLevel { Safe, Suspicious, Dangerous, Critical };

struct Finding {
    std::string source;
    std::string id;
    std::string description;
    ThreatLevel level;
};

struct AnalysisResult {
    std::filesystem::path file;
    std::string detected_type;
    ThreatLevel overall = ThreatLevel::Safe;
    std::vector<Finding> findings;
};

class Analyzer {
public:
    AnalysisResult analyzeFile(const std::filesystem::path& file) const;
    std::vector<AnalysisResult> analyzeDirectory(const std::filesystem::path& dir) const;

private:
    std::string detectTypeByMagic(const std::filesystem::path& file) const;
    void runStaticChecks(const std::filesystem::path& file, const std::string& type, AnalysisResult& out) const;
    void runYara(const std::filesystem::path& file, AnalysisResult& out) const;
    void runClamAV(const std::filesystem::path& file, AnalysisResult& out) const;
};
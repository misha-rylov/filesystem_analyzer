#include "analyzer.hpp"
#include "scanner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <chrono>

#ifdef HAVE_JSON
#include <nlohmann/json.hpp>
#endif

static const char* lvl(ThreatLevel l) {
    switch (l) {
        case ThreatLevel::Safe: return "SAFE";
        case ThreatLevel::Suspicious: return "SUSPICIOUS";
        case ThreatLevel::Dangerous: return "DANGEROUS";
        case ThreatLevel::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

static ThreatLevel profileThreshold(const std::string& profile) {
    if (profile == "mail")    return ThreatLevel::Suspicious;
    if (profile == "gateway") return ThreatLevel::Dangerous;
    if (profile == "endpoint") return ThreatLevel::Critical;
    return ThreatLevel::Safe;
}

static void printResult(const AnalysisResult& r, ThreatLevel threshold) {
    if (static_cast<int>(r.overall) >= static_cast<int>(threshold)) {
        std::cout << r.file << " [" << r.detected_type << "] => " << lvl(r.overall) << "\n";
        for (const auto& f : r.findings) {
            std::cout << "  - (" << f.source << ") " << f.id << ": " << f.description << "\n";
        }
    }
}

static void exportCsv(const std::vector<AnalysisResult>& results, const std::string& path) {
    std::ofstream out(path);
    if (!out) {
        std::cerr << "Cannot open CSV: " << path << "\n";
        return;
    }
    out << "file,detected_type,overall,source,id,description,level\n";
    for (const auto& r : results) {
        out << "\"" << r.file.string() << "\","
            << "\"" << r.detected_type << "\","
            << lvl(r.overall) << ",";
        if (r.findings.empty()) {
            out << ",,,\n";
        } else {
            for (size_t i = 0; i < r.findings.size(); ++i) {
                const auto& f = r.findings[i];
                if (i > 0) out << ",,,";
                out << "\"" << f.source << "\","
                    << "\"" << f.id << "\","
                    << "\"" << f.description << "\","
                    << lvl(f.level) << "\n";
            }
        }
    }
    std::cout << "CSV exported to: " << path << "\n";
}

#ifdef HAVE_JSON
static void exportJson(const std::vector<AnalysisResult>& results, const std::string& path) {
    nlohmann::json j = nlohmann::json::array();
    for (const auto& r : results) {
        nlohmann::json item;
        item["file"] = r.file.string();
        item["detected_type"] = r.detected_type;
        item["overall"] = lvl(r.overall);
        item["findings"] = nlohmann::json::array();
        for (const auto& f : r.findings) {
            item["findings"].push_back({
                {"source", f.source},
                {"id", f.id},
                {"description", f.description},
                {"level", lvl(f.level)}
            });
        }
        j.push_back(item);
    }
    std::ofstream out(path);
    if (!out) {
        std::cerr << "Cannot open JSON: " << path << "\n";
        return;
    }
    out << j.dump(2);
    std::cout << "JSON exported to: " << path << "\n";
}
#else
static void exportJson(const std::vector<AnalysisResult>&, const std::string&) {
    std::cerr << "JSON export requires nlohmann_json (not found). Rebuild with -Dnlohmann_json_DIR=...\n";
}
#endif

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <file-or-dir> [profile] [options]\n"
              << "\nArguments:\n"
              << "  <file-or-dir>  Path to file or directory to analyze\n"
              << "  [profile]      Scoring profile: mail, gateway, endpoint (default: mail)\n"
              << "\nOptions:\n"
              << "  --csv <file>   Export results to CSV\n"
              << "  --json <file>  Export results to JSON\n"
              << "  --help         Show this help\n"
              << "\nExamples:\n"
              << "  " << prog << " /path/to/file.pdf mail\n"
              << "  " << prog << " /path/to/inbox gateway\n"
              << "  " << prog << " /path/to/data endpoint --csv report.csv --json report.json\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string profile = "mail";
    std::string csvPath, jsonPath;
    std::vector<std::string> paths;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--csv" && i + 1 < argc) {
            csvPath = argv[++i];
        } else if (arg == "--json" && i + 1 < argc) {
            jsonPath = argv[++i];
        } else if (arg == "mail" || arg == "gateway" || arg == "endpoint") {
            profile = arg;
        } else if (!arg.empty() && arg[0] != '-') {
            paths.push_back(arg);
        }
    }

    if (paths.empty()) {
        std::cerr << "Error: no file or directory specified\n";
        printUsage(argv[0]);
        return 1;
    }

    Analyzer a;
    Scanner s;
    std::vector<AnalysisResult> allResults;
    ThreatLevel threshold = profileThreshold(profile);

    std::cout << "Profile: " << profile << " (threshold: " << lvl(threshold) << ")\n";

    for (const auto& p : paths) {
        std::filesystem::path path = p;

        if (std::filesystem::is_regular_file(path)) {
            auto r = a.analyzeFile(path);
            printResult(r, threshold);
            allResults.push_back(r);
        } else if (std::filesystem::is_directory(path)) {
            auto files = s.collect_files(path);
            std::cout << "Scanning " << files.size() << " files in: " << path << "\n";
            for (const auto& f : files) {
                auto r = a.analyzeFile(f);
                printResult(r, threshold);
                allResults.push_back(r);
            }
        } else {
            std::cerr << "Path not found: " << path << "\n";
        }
    }

    if (!csvPath.empty()) exportCsv(allResults, csvPath);
    if (!jsonPath.empty()) exportJson(allResults, jsonPath);

    // Summary
    int critical = 0, dangerous = 0, suspicious = 0, safe = 0;
    for (const auto& r : allResults) {
        switch (r.overall) {
            case ThreatLevel::Critical: ++critical; break;
            case ThreatLevel::Dangerous: ++dangerous; break;
            case ThreatLevel::Suspicious: ++suspicious; break;
            case ThreatLevel::Safe: ++safe; break;
        }
    }
    std::cout << "\nSummary: " << safe << " safe, " << suspicious << " suspicious, "
              << dangerous << " dangerous, " << critical << " critical\n";

    return (critical > 0 || dangerous > 0) ? 1 : 0;
}

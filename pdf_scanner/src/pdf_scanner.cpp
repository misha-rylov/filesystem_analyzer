#include "pdf_scanner.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace pdfscanner {

PDFScanner::PDFScanner() : yara_(std::make_unique<YaraWrapper>()) {}
PDFScanner::~PDFScanner() = default;

bool PDFScanner::initialize(const std::string& rulesPath) {
    if (!yara_->initialize()) return false;
    return yara_->loadRules(rulesPath);
}

std::string PDFScanner::calculateMD5(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "";
    MD5_CTX ctx;
    MD5_Init(&ctx);
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&ctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) MD5_Update(&ctx, buffer, file.gcount());
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &ctx);
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string PDFScanner::calculateSHA1(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "";
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        SHA1_Update(&ctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) SHA1_Update(&ctx, buffer, file.gcount());
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &ctx);
    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string PDFScanner::calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&ctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) SHA256_Update(&ctx, buffer, file.gcount());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

Severity PDFScanner::calculateOverallSeverity(const std::vector<RuleMatch>& matches) {
    Severity overall = Severity::Clean;
    for (const auto& match : matches) {
        if (match.severity == Severity::Critical) return Severity::Critical;
        else if (match.severity == Severity::High && overall != Severity::Critical) overall = Severity::High;
        else if (match.severity == Severity::Medium && overall != Severity::Critical && overall != Severity::High) overall = Severity::Medium;
    }
    return overall;
}

ScanResult PDFScanner::scanFile(const std::string& filePath) {
    ScanResult result;
    result.file_path = filePath;
    result.file_name = std::filesystem::path(filePath).filename().string();
    result.scan_time = std::chrono::system_clock::now();
    try {
        result.file_size = std::filesystem::file_size(filePath);
        result.md5 = calculateMD5(filePath);
        result.sha1 = calculateSHA1(filePath);
        result.sha256 = calculateSHA256(filePath);
        result.matches = yara_->scanFile(filePath);
        result.threats_detected = result.matches.size();
        result.overall_severity = calculateOverallSeverity(result.matches);
    } catch (const std::exception& e) {
        result.error = e.what();
        result.overall_severity = Severity::Medium;
    }
    return result;
}

std::vector<std::string> PDFScanner::findPDFFiles(const std::string& directory, bool recursive) {
    std::vector<std::string> pdfFiles;
    if (recursive) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".pdf") pdfFiles.push_back(entry.path().string());
            }
        }
    } else {
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".pdf") pdfFiles.push_back(entry.path().string());
            }
        }
    }
    return pdfFiles;
}

std::vector<ScanResult> PDFScanner::scanDirectory(const std::string& dirPath, bool recursive) {
    std::vector<ScanResult> results;
    auto pdfFiles = findPDFFiles(dirPath, recursive);
    std::cout << "Found " << pdfFiles.size() << " PDF files to scan" << std::endl;
    for (const auto& pdfFile : pdfFiles) {
        std::cout << "Scanning: " << pdfFile << std::endl;
        results.push_back(scanFile(pdfFile));
    }
    return results;
}

std::string PDFScanner::resultToJSON(const ScanResult& result) {
    json j;
    j["file_path"] = result.file_path;
    j["file_name"] = result.file_name;
    j["file_size"] = result.file_size;
    j["scan_time"] = std::chrono::system_clock::to_time_t(result.scan_time);
    j["threats_detected"] = result.threats_detected;
    j["overall_severity"] = YaraWrapper::severityToString(result.overall_severity);
    if (result.error) j["error"] = *result.error;
    json hashes;
    hashes["md5"] = result.md5;
    hashes["sha1"] = result.sha1;
    hashes["sha256"] = result.sha256;
    j["hashes"] = hashes;
    json matches = json::array();
    for (const auto& match : result.matches) {
        json m;
        m["rule_name"] = match.rule_name;
        m["namespace"] = match.namespace_;
        m["severity"] = YaraWrapper::severityToString(match.severity);
        json meta = json::object();
        for (const auto& [key, value] : match.metadata) meta[key] = value;
        m["metadata"] = meta;
        matches.push_back(m);
    }
    j["matches"] = matches;
    return j.dump(2);
}

std::string PDFScanner::summaryToJSON(const ScanSummary& summary) {
    json j;
    j["total_files"] = summary.total_files;
    j["infected_files"] = summary.infected_files;
    j["clean_files"] = summary.clean_files;
    j["scan_date"] = std::chrono::system_clock::to_time_t(summary.scan_date);
    return j.dump(2);
}

} // namespace pdfscanner

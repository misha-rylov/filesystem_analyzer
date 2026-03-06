#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include "../include/types.h"
#include "yara_wrapper.h"

namespace pdfscanner {

class PDFScanner {
public:
    PDFScanner();
    ~PDFScanner();
    
    bool initialize(const std::string& rulesPath);
    ScanResult scanFile(const std::string& filePath);
    std::vector<ScanResult> scanDirectory(const std::string& dirPath, bool recursive = true);
    
    static std::string resultToJSON(const ScanResult& result);
    static std::string summaryToJSON(const ScanSummary& summary);
    static std::vector<std::string> findPDFFiles(const std::string& directory, bool recursive = true);
    
private:
    std::unique_ptr<YaraWrapper> yara_;
    
    std::string calculateMD5(const std::string& filePath);
    std::string calculateSHA1(const std::string& filePath);
    std::string calculateSHA256(const std::string& filePath);
    Severity calculateOverallSeverity(const std::vector<RuleMatch>& matches);
};

} // namespace pdfscanner

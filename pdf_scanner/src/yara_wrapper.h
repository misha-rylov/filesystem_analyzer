#pragma once

#include <string>
#include <vector>
#include <memory>
#include <yara.h>
#include "../include/types.h"

namespace pdfscanner {

class YaraWrapper {
public:
    YaraWrapper();
    ~YaraWrapper();
    
    YaraWrapper(const YaraWrapper&) = delete;
    YaraWrapper& operator=(const YaraWrapper&) = delete;
    
    bool initialize();
    bool loadRules(const std::string& rulesPath);
    bool compileRulesFromString(const std::string& rules);
    
    std::vector<RuleMatch> scanFile(const std::string& filePath);
    std::vector<RuleMatch> scanMemory(const uint8_t* data, size_t size);
    
    static std::string severityToString(Severity severity);
    static Severity stringToSeverity(const std::string& str);
    
private:
    YARA_RULES* rules_ = nullptr;
    bool initialized_ = false;
    
    static int callbackFunction(
        YR_SCAN_CONTEXT* context,
        int message,
        void* message_data,
        void* user_data
    );
    
    struct ScanContext {
        std::vector<RuleMatch>* matches;
        YaraWrapper* scanner;
    };
};

} // namespace pdfscanner

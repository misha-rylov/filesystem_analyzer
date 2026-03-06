#include "yara_wrapper.h"
#include <iostream>
#include <fstream>
#include <algorithm>

namespace pdfscanner {

YaraWrapper::YaraWrapper() = default;
YaraWrapper::~YaraWrapper() {
    if (rules_) yr_rules_destroy(rules_);
    if (initialized_) yr_finalize();
}

bool YaraWrapper::initialize() {
    if (initialized_) return true;
    int error = yr_initialize();
    if (error != ERROR_SUCCESS) {
        std::cerr << "YARA initialization failed: " << error << std::endl;
        return false;
    }
    initialized_ = true;
    return true;
}

bool YaraWrapper::loadRules(const std::string& rulesPath) {
    if (!initialized_) {
        std::cerr << "YARA not initialized" << std::endl;
        return false;
    }
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    int error = yr_rules_load(rulesPath.c_str(), &rules_);
    if (error != ERROR_SUCCESS) {
        std::cerr << "Failed to load YARA rules: " << error << std::endl;
        return false;
    }
    std::cout << "Loaded YARA rules from: " << rulesPath << std::endl;
    return true;
}

bool YaraWrapper::compileRulesFromString(const std::string& rules) {
    if (!initialized_) {
        std::cerr << "YARA not initialized" << std::endl;
        return false;
    }
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    int error = yr_rules_compile_string(rules.c_str(), nullptr, 0, &rules_);
    if (error != ERROR_SUCCESS) {
        std::cerr << "Failed to compile YARA rules: " << error << std::endl;
        return false;
    }
    std::cout << "Compiled YARA rules from string" << std::endl;
    return true;
}

int YaraWrapper::callbackFunction(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
) {
    auto* ctx = static_cast<ScanContext*>(user_data);
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = static_cast<YR_RULE*>(message_data);
        RuleMatch match;
        match.rule_name = rule->identifier;
        match.namespace_ = rule->ns->name ? rule->ns->name : "default";
        
        const char* key;
        const char* value;
        yr_rule_metas_foreach(rule, key, value) {
            match.metadata[key] = value;
        }
        
        auto it = match.metadata.find("severity");
        if (it != match.metadata.end()) {
            match.severity = stringToSeverity(it->second);
        } else {
            match.severity = Severity::Medium;
        }
        ctx->matches->push_back(std::move(match));
    }
    return CALLBACK_CONTINUE;
}

std::vector<RuleMatch> YaraWrapper::scanFile(const std::string& filePath) {
    auto matches = std::make_unique<std::vector<RuleMatch>>();
    ScanContext ctx{matches.get(), this};
    int flags = 0;
    int timeout = 30000;
    int error = yr_rules_scan_file(rules_, filePath.c_str(), flags, callbackFunction, &ctx, timeout);
    if (error != ERROR_SUCCESS) {
        std::cerr << "YARA scan failed for " << filePath << ": " << error << std::endl;
    }
    return *matches;
}

std::vector<RuleMatch> YaraWrapper::scanMemory(const uint8_t* data, size_t size) {
    auto matches = std::make_unique<std::vector<RuleMatch>>();
    ScanContext ctx{matches.get(), this};
    int flags = 0;
    int timeout = 30000;
    int error = yr_rules_scan_mem(rules_, data, size, flags, callbackFunction, &ctx, timeout);
    if (error != ERROR_SUCCESS) {
        std::cerr << "YARA memory scan failed: " << error << std::endl;
    }
    return *matches;
}

std::string YaraWrapper::severityToString(Severity severity) {
    switch (severity) {
        case Severity::Clean: return "clean";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
        default: return "unknown";
    }
}

Severity YaraWrapper::stringToSeverity(const std::string& str) {
    if (str == "critical") return Severity::Critical;
    if (str == "high") return Severity::High;
    if (str == "medium") return Severity::Medium;
    if (str == "low") return Severity::Low;
    return Severity::Clean;
}

} // namespace pdfscanner

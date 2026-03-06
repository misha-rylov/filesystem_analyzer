#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include "pdf_scanner.h"

using namespace pdfscanner;

void printHelp(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n"
              << "\nOptions:\n"
              << "  -r, --rules PATH      Path to YARA rules (required)\n"
              << "  -f, --file PATH       Single PDF file to scan\n"
              << "  -d, --dir PATH        Directory to scan for PDFs\n"
              << "  -o, --output FILE     Output JSON report\n"
              << "  --recursive           Scan recursively (default)\n"
              << "  --no-recursive        Disable recursive scanning\n"
              << "  -v, --verbose         Verbose output\n"
              << "  -h, --help            Show help\n"
              << "\nExamples:\n"
              << "  " << programName << " -r rules/ -f suspicious.pdf\n"
              << "  " << programName << " -r rules/ -d /path/to/pdfs/ -o report.json\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string rulesPath, filePath, dirPath, outputFile;
    bool recursive = true, verbose = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-r" || arg == "--rules") && i + 1 < argc) rulesPath = argv[++i];
        else if ((arg == "-f" || arg == "--file") && i + 1 < argc) filePath = argv[++i];
        else if ((arg == "-d" || arg == "--dir") && i + 1 < argc) dirPath = argv[++i];
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) outputFile = argv[++i];
        else if (arg == "--recursive") recursive = true;
        else if (arg == "--no-recursive") recursive = false;
        else if (arg == "-v" || arg == "--verbose") verbose = true;
        else if (arg == "-h" || arg == "--help") { printHelp(argv[0]); return 0; }
    }
    
    if (rulesPath.empty()) { std::cerr << "Error: Rules path required (-r)\n"; printHelp(argv[0]); return 1; }
    if (filePath.empty() && dirPath.empty()) { std::cerr << "Error: File or directory required\n"; printHelp(argv[0]); return 1; }
    
    PDFScanner scanner;
    if (!scanner.initialize(rulesPath)) { std::cerr << "Failed to initialize scanner\n"; return 1; }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    std::vector<ScanResult> results;
    
    if (!filePath.empty()) {
        if (!std::filesystem::exists(filePath)) { std::cerr << "File not found: " << filePath << "\n"; return 1; }
        results.push_back(scanner.scanFile(filePath));
    } else if (!dirPath.empty()) {
        if (!std::filesystem::exists(dirPath)) { std::cerr << "Directory not found: " << dirPath << "\n"; return 1; }
        results = scanner.scanDirectory(dirPath, recursive);
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    ScanSummary summary;
    summary.total_files = results.size();
    summary.infected_files = std::count_if(results.begin(), results.end(), [](const ScanResult& r) { return r.threats_detected > 0; });
    summary.clean_files = summary.total_files - summary.infected_files;
    summary.scan_date = std::chrono::system_clock::now();
    
    if (!outputFile.empty()) {
        std::ofstream out(outputFile);
        out << "{\n  \"scan_summary\": " << PDFScanner::summaryToJSON(summary) << ",\n  \"results\": [\n";
        for (size_t i = 0; i < results.size(); i++) {
            out << "    " << PDFScanner::resultToJSON(results[i]);
            if (i < results.size() - 1) out << ",";
            out << "\n";
        }
        out << "  ]\n}\n";
        out.close();
        std::cout << "Report saved to: " << outputFile << "\n";
    } else {
        for (const auto& result : results) std::cout << PDFScanner::resultToJSON(result) << "\n";
    }
    
    std::cout << "\n========================================\n";
    std::cout << "SCAN SUMMARY\n";
    std::cout << "========================================\n";
    std::cout << "Total files:     " << summary.total_files << "\n";
    std::cout << "Infected files:  " << summary.infected_files << "\n";
    std::cout << "Clean files:     " << summary.clean_files << "\n";
    std::cout << "Scan time:       " << duration.count() << " ms\n";
    std::cout << "========================================\n";
    
    return summary.infected_files > 0 ? 1 : 0;
}

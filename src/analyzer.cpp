#include "analyzer.hpp"
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <vector>

namespace {
void add(AnalysisResult& out, std::string src, std::string id, std::string desc, ThreatLevel lvl) {
    out.findings.push_back({std::move(src), std::move(id), std::move(desc), lvl});
    if (static_cast<int>(lvl) > static_cast<int>(out.overall)) out.overall = lvl;
}

std::vector<uint8_t> readHead(const std::filesystem::path& p, size_t n = 8192) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::vector<uint8_t> b(n);
    in.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(n));
    b.resize(static_cast<size_t>(in.gcount()));
    return b;
}

bool contains(const std::vector<uint8_t>& data, const std::string& s) {
    if (s.empty() || data.empty()) return false;
    auto it = std::search(data.begin(), data.end(), s.begin(), s.end());
    return it != data.end();
}
} // namespace

std::string Analyzer::detectTypeByMagic(const std::filesystem::path& file) const {
    auto h = readHead(file, 64);
    if (h.size() < 4) return "unknown";

    auto eq = [&](std::initializer_list<uint8_t> sig) {
        if (h.size() < sig.size()) return false;
        return std::equal(sig.begin(), sig.end(), h.begin());
    };

    if (eq({0x25,0x50,0x44,0x46})) return "pdf";
    if (eq({0x7F,0x45,0x4C,0x46})) return "elf";
    if (eq({0x89,0x50,0x4E,0x47})) return "png";
    if (eq({0xFF,0xD8,0xFF})) return "jpeg";
    if (eq({0x50,0x4B,0x03,0x04})) return "zip_or_ooxml";
    if (eq({0x52,0x61,0x72,0x21})) return "rar";
    if (eq({0xED,0xAB,0xEE,0xDB})) return "rpm";
    if (eq({0x21,0x3C,0x61,0x72,0x63,0x68,0x3E})) return "deb"; // ar archive
    if (eq({0x52,0x49,0x46,0x46})) {
        if (h.size() >= 12 && std::equal(h.begin()+8, h.begin()+12, "AVI ")) return "avi";
        return "riff";
    }
    if (h.size() >= 8 && h[4]=='f' && h[5]=='t' && h[6]=='y' && h[7]=='p') return "mov_or_mp4";
    if (eq({0x00,0x00,0x01,0xBA}) || eq({0x00,0x00,0x01,0xB3})) return "mpeg";
    if (h.size() > 2 && h[0] == 0x30 && (h[1] == 0x82 || h[1] == 0x81)) return "cert_der";
    return "unknown";
}

void Analyzer::runStaticChecks(const std::filesystem::path& file, const std::string& type, AnalysisResult& out) const {
    auto h = readHead(file, 2 * 1024 * 1024);

    if (type == "pdf") {
        if (contains(h, "/JavaScript") || contains(h, "/JS"))
            add(out, "static", "PDF_JS", "JavaScript в PDF", ThreatLevel::Dangerous);
        if (contains(h, "/OpenAction"))
            add(out, "static", "PDF_OPEN_ACTION", "Автодействие при открытии PDF", ThreatLevel::Dangerous);
        if (contains(h, "/Launch"))
            add(out, "static", "PDF_LAUNCH", "Запуск внешней программы из PDF", ThreatLevel::Critical);
    }

    if (type == "zip_or_ooxml") {
        if (contains(h, "word/")) out.detected_type = "docx";
        if (contains(h, "xl/")) out.detected_type = "xlsx";
        if (contains(h, "vbaProject.bin"))
            add(out, "static", "OOXML_MACRO", "Макросы в OOXML", ThreatLevel::Critical);
        if (contains(h, "../") || contains(h, "..\\"))
            add(out, "static", "ZIP_TRAVERSAL", "Path traversal в архиве", ThreatLevel::Dangerous);
    }

    if (type == "elf") {
        if (contains(h, "system(") || contains(h, "/bin/sh"))
            add(out, "static", "ELF_SUSP_STR", "Подозрительные строки в ELF", ThreatLevel::Suspicious);
    }

    if (type == "jpeg" || type == "png") {
        if (contains(h, "MZ"))
            add(out, "static", "IMAGE_EMBED_EXE", "Похоже на внедренный PE-фрагмент", ThreatLevel::Suspicious);
    }

    if (type == "cert_der" && h.size() < 256) {
        add(out, "static", "CERT_TOO_SMALL", "Сертификат слишком маленький", ThreatLevel::Suspicious);
    }

    if (type == "rpm" || type == "deb") {
        if (contains(h, "../") || contains(h, "..\\"))
            add(out, "static", "PKG_TRAVERSAL", "Path traversal в пакете", ThreatLevel::Dangerous);
    }
}

static std::string escapeShell(const std::string& s) {
    std::string r;
    r.reserve(s.size() * 2);
    for (char c : s) {
        if (c == '\'') r += "'\\''";
        else r += c;
    }
    return "'" + r + "'";
}

void Analyzer::runYara(const std::filesystem::path& file, AnalysisResult& out) const {
    std::string cmd = "yara -r rules " + escapeShell(file.string()) + " 2>/dev/null";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return;

    char buf[2048];
    while (fgets(buf, sizeof(buf), p)) {
        std::string line(buf);
        if (!line.empty() && line.back() == '\n') line.pop_back();
        if (!line.empty()) {
            add(out, "yara", "YARA_MATCH", line, ThreatLevel::Dangerous);
        }
    }
    pclose(p);
}

void Analyzer::runClamAV(const std::filesystem::path& file, AnalysisResult& out) const {
    std::string cmd = "clamscan --no-summary --stdout " + escapeShell(file.string()) + " 2>/dev/null";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return;

    char buf[2048];
    while (fgets(buf, sizeof(buf), p)) {
        std::string line(buf);
        if (line.find("FOUND") != std::string::npos) {
            if (!line.empty() && line.back() == '\n') line.pop_back();
            add(out, "clamav", "CLAMAV_FOUND", line, ThreatLevel::Critical);
        }
    }
    pclose(p);
}

AnalysisResult Analyzer::analyzeFile(const std::filesystem::path& file) const {
    AnalysisResult out;
    out.file = file;
    out.detected_type = detectTypeByMagic(file);

    runStaticChecks(file, out.detected_type, out);
    runYara(file, out);
    runClamAV(file, out);
    return out;
}

std::vector<AnalysisResult> Analyzer::analyzeDirectory(const std::filesystem::path& dir) const {
    std::vector<AnalysisResult> all;
    for (auto& e : std::filesystem::recursive_directory_iterator(dir)) {
        if (e.is_regular_file()) all.push_back(analyzeFile(e.path()));
    }
    return all;
}

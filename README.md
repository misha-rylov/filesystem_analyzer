# 🛡️ Filesystem Analyzer

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CMake](https://img.shields.io/badge/CMake-%E2%89%A53.16-green.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

**High-performance static file analyzer** for corporate security workflows.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Supported Formats](#-supported-formats)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Build](#-build)
- [Usage](#-usage)
- [Functional Testing](#-functional-testing)
- [YARA Rules](#-yara-rules)
- [ClamAV Scanning](#-clamav-scanning)
- [Production Recommendations](#-production-recommendations)
- [Quick Start](#-quick-start)
- [License / Disclaimer](#-license--disclaimer)

---

## ✨ Key Features

- Magic-bytes file type detection with extension fallback
- ZIP central directory inspection (no extraction)
- YARA + ClamAV integration
- Scoring profiles: mail, gateway, endpoint
- CSV / JSON SIEM export

---

## 📦 Supported Formats

Documents: pdf, doc, docx, xls, xlsx, ppt, pptx  
Archives: zip, rar, 7z, tar, gz, bz2, xz, cab, iso, rpm, deb  
Executables: so, sys, dylib, pe, macho  
Media: png, jpeg, mpeg, mov, avi  
Mail: eml, ics  
Scripts / Config: html, xml, svg, json, yaml, js, vbs, ps1, bat, cmd, wsf, hta, jar, apk, bin

---

## 🧱 Project Structure

```
filesystem_analyzer/
├── CMakeLists.txt
├── include/
│   └── analyzer.hpp
├── src/
│   ├── analyzer.cpp
│   ├── analyzer.hpp
│   ├── main.cpp
│   ├── scanner.cpp
│   └── scanner.hpp
├── rules/
│   ├── basic.yar
│   └── corp_common.yar
├── test/
│   ├── run_functional_tests.sh
│   └── README.md
└── test_data/
    └── generate_test_data.sh
```

> **Note:** For JSON export, install `nlohmann_json` and rebuild with `-Dnlohmann_json_DIR=...`

---

## 🔧 Requirements

| Component  | Requirement              |
|------------|--------------------------|
| Compiler   | C++20 (g++ or clang++)   |
| Build      | CMake ≥ 3.16             |
| YARA       | CLI (recommended)        |
| ClamAV     | CLI (recommended)        |

Linux (Fedora/RHEL) quick install:

```bash
sudo dnf install -y cmake gcc-c++ yara clamav clamav-freshclam
sudo freshclam
```

---

## 🛠 Build

```bash
cd ~/work/filesystem_analyzer
cmake -S . -B build
cmake --build build -j
```

Run binary:

```bash
./build/filesystem_analyzer
```

---

## 🚀 Usage

```bash
./build/filesystem_analyzer <file-or-dir> [profile] [--csv out.csv] [--json out.json]
```

Arguments:
- <file-or-dir> : Path to file or directory to analyze
- [profile]      : Scoring profile: mail, gateway, endpoint
- --csv <file>   : Export results to CSV
- --json <file>  : Export results to JSON

Examples:

```bash
./build/filesystem_analyzer /path/to/file.pdf mail
./build/filesystem_analyzer /path/to/inbox gateway
./build/filesystem_analyzer /path/to/data endpoint --csv report.csv --json report.json
```

---

## 🧪 Functional Testing

```bash
# make test scripts executable
chmod +x test_data/generate_test_data.sh test/run_functional_tests.sh

# generate test data
bash test_data/generate_test_data.sh test_data

# run functional tests (binary path then test_data)
bash test/run_functional_tests.sh build/filesystem_analyzer test_data

# run with ctest
ctest --test-dir build --output-on-failure
```

---

## 🧩 YARA Rules

Rules are loaded from the rules/ directory. Example usage:

```bash
yara -r rules /path/to/file
```

Add or extend rules in rules/corp_common.yar.

---

## 🛡 ClamAV Scanning

Example:

```bash
clamscan --no-summary --stdout /path/to/file
```

---

## ✅ Production Recommendations

- Run in isolated container/service
- Keep YARA and ClamAV signatures updated
- Stream CSV/JSON results to SIEM (ELK, Splunk, QRadar)
- Implement allowlist for trusted hashes/signers
- Use async queues (Kafka, RabbitMQ) for high throughput

---

## 🚀 Quick Start

```bash
cd ~/work/filesystem_analyzer
chmod +x test_data/generate_test_data.sh test/run_functional_tests.sh
cmake -S . -B build
cmake --build build -j

bash test_data/generate_test_data.sh test_data
./build/filesystem_analyzer test_data mail --csv test_report.csv --json test_report.json
bash test/run_functional_tests.sh build/filesystem_analyzer test_data
```

---

## 📄 License / Disclaimer

This project is intended for legitimate defensive security operations. Use only under your corporate security policy and applicable law.

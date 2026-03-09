#!/bin/bash
# Functional tests for filesystem_analyzer
# Usage: bash run_functional_tests.sh <binary_path> <test_data_dir>

set -e

BINARY="${1:-build/filesystem_analyzer}"
DATADIR="${2:-test_data}"

echo "========================================"
echo "Filesystem Analyzer - Functional Tests"
echo "========================================"
echo "Binary: $BINARY"
echo "Test data: $DATADIR"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

check_result() {
    local test_name="$1"
    local expected="$2"  # "found" or "not_found"
    local result="$3"
    
    if [[ "$expected" == "found" ]]; then
        if echo "$result" | grep -qi "dangerous\|critical\|suspicious"; then
            echo -e "${GREEN}[PASS]${NC} $test_name - Threat detected"
            ((PASS++))
        else
            echo -e "${RED}[FAIL]${NC} $test_name - Expected threat but not detected"
            ((FAIL++))
        fi
    else
        if echo "$result" | grep -qi "safe"; then
            echo -e "${GREEN}[PASS]${NC} $test_name - No threat detected (expected)"
            ((PASS++))
        else
            echo -e "${RED}[FAIL]${NC} $test_name - Unexpected threat detected"
            ((FAIL++))
        fi
    fi
}

echo "========================================"
echo "Testing SAFE files (should be SAFE)"
echo "========================================"

for f in "$DATADIR"/safe.*; do
    if [[ -f "$f" ]]; then
        result=$("$BINARY" "$f" mail 2>&1)
        check_result "Safe file: $(basename $f)" "not_found" "$result"
    fi
done

echo ""
echo "========================================"
echo "Testing MALICIOUS PDF files"
echo "========================================"

result=$("$BINARY" "$DATADIR/mal_pdf_js.pdf" mail 2>&1)
check_result "PDF with JavaScript" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_pdf_launch.pdf" mail 2>&1)
check_result "PDF with Launch action" "found" "$result"

echo ""
echo "========================================"
echo "Testing MALICIOUS Office files"
echo "========================================"

result=$("$BINARY" "$DATADIR/mal_docx_macro.docx" mail 2>&1)
check_result "DOCX with macro" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_xlsx_macro.xlsx" mail 2>&1)
check_result "XLSX with macro" "found" "$result"

echo ""
echo "========================================"
echo "Testing MALICIOUS Archives"
echo "========================================"

result=$("$BINARY" "$DATADIR/mal_zip_traversal.zip" mail 2>&1)
check_result "ZIP with path traversal" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_zip_exe.zip" mail 2>&1)
check_result "ZIP with executable" "found" "$result"

echo ""
echo "========================================"
echo "Testing MALICIOUS Scripts"
echo "========================================"

result=$("$BINARY" "$DATADIR/mal_ps1.ps1" mail 2>&1)
check_result "PowerShell script" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_vbs.vbs" mail 2>&1)
check_result "VBS script" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_bat.bat" mail 2>&1)
check_result "Batch script" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_js.js" mail 2>&1)
check_result "JavaScript" "found" "$result"

echo ""
echo "========================================"
echo "Testing MALICIOUS Media Files (Video)"
echo "========================================"

result=$("$BINARY" "$DATADIR/mal_mp4_url.mp4" mail 2>&1)
check_result "MP4 with URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mp4_js.mp4" mail 2>&1)
check_result "MP4 with JavaScript" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mp4_longurl.mp4" mail 2>&1)
check_result "MP4 with long URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mp4_ipurl.mp4" mail 2>&1)
check_result "MP4 with IP URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_avi_url.avi" mail 2>&1)
check_result "AVI with URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_avi_ps.avi" mail 2>&1)
check_result "AVI with PowerShell" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mpg_js.mpg" mail 2>&1)
check_result "MPG with JavaScript" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mpg_wmi.mpg" mail 2>&1)
check_result "MPG with WMI" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mkv_xxe.mkv" mail 2>&1)
check_result "MKV with XXE" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mkv_net.mkv" mail 2>&1)
check_result "MKV with network" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mov_crypto.mov" mail 2>&1)
check_result "MOV with crypto API" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mov_mz.mov" mail 2>&1)
check_result "MOV with MZ header" "found" "$result"

echo ""
echo "========================================"
echo "Testing MALICIOUS Media Files (Audio)"
echo "========================================"

result=$("$BINARY" "$DATADIR/mal_mp3_id3.mp3" mail 2>&1)
check_result "MP3 with ID3 URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_mp3_ps.mp3" mail 2>&1)
check_result "MP3 with PowerShell" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_wav_b64.wav" mail 2>&1)
check_result "WAV with base64" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_wav_reg.wav" mail 2>&1)
check_result "WAV with registry" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_flac_comment.flac" mail 2>&1)
check_result "FLAC with comment" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_flac_url.flac" mail 2>&1)
check_result "FLAC with URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_ogg_url.ogg" mail 2>&1)
check_result "OGG with URL" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_ogg_ps.ogg" mail 2>&1)
check_result "OGG with PowerShell" "found" "$result"

result=$("$BINARY" "$DATADIR/mal_aac_url.aac" mail 2>&1)
check_result "AAC with URL" "found" "$result"

echo ""
echo "========================================"
echo "Testing Ransomware Indicators"
echo "========================================"

result=$("$BINARY" "$DATADIR/ransom_note.txt" mail 2>&1)
check_result "Ransomware note" "found" "$result"

echo ""
echo "========================================"
echo "Testing Profile Thresholds"
echo "========================================"

# Test with endpoint profile (more strict)
result=$("$BINARY" "$DATADIR/mal_pdf_js.pdf" endpoint 2>&1)
check_result "PDF JS - endpoint profile" "found" "$result"

echo ""
echo "========================================"
echo "Testing Directory Scan"
echo "========================================"

result=$("$BINARY" "$DATADIR" mail 2>&1)
if echo "$result" | grep -qi "dangerous\|critical"; then
    echo -e "${GREEN}[PASS]${NC} Directory scan detects threats"
    ((PASS++))
else
    echo -e "${RED}[FAIL]${NC} Directory scan failed to detect threats"
    ((FAIL++))
fi

echo ""
echo "========================================"
echo "Testing CSV Export"
echo "========================================"

CSV_OUT="/tmp/test_output_$$.csv"
"$BINARY" "$DATADIR" mail --csv "$CSV_OUT" > /dev/null 2>&1
if [[ -f "$CSV_OUT" && -s "$CSV_OUT" ]]; then
    echo -e "${GREEN}[PASS]${NC} CSV export works"
    ((PASS++))
    rm -f "$CSV_OUT"
else
    echo -e "${RED}[FAIL]${NC} CSV export failed"
    ((FAIL++))
fi

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi

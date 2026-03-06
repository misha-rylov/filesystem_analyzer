# filesystem_analyzer

# 🔒 FILE FORMAT SECURITY ANALYSIS DOCUMENTATION

**Comprehensive Guide to File Structures with Malware Detection Points**

---

## 📋 TABLE OF CONTENTS

1. [Danger Legend](#-danger-legend)
2. [PDF File Format](#-pdf-file-format)
3. [ELF (Linux Executable) Format](#-elf-linux-executable-format)
4. [DOCX/Office Open XML Format](#-docxoffice-open-xml-format)
5. [XLSX (Excel) Format](#-xlsx-excel-format)
6. [MP4/MOV (MPEG-4) Format](#-mp4mov-mpeg-4-format)
7. [JPEG Image Format](#-jpeg-image-format)
8. [PNG Image Format](#-png-image-format)
9. [ZIP Archive Format](#-zip-archive-format)
10. [RAR Archive Format](#-rar-archive-format)
11. [X.509 Certificate Format](#-x509-certificate-format)
12. [Email Formats (PST)](#-email-formats-pst)
13. [Quick Reference Table](#-quick-reference-table)
14. [Analysis Tools](#-analysis-tools-recommendations)
15. [Best Practices](#-best-practices-for-safe-analysis)

---

## ⚠️ DANGER LEGEND

| Symbol | Meaning |
|--------|---------|
| 🚨 | **HIGH RISK** - Common malware hiding spots |
| ⚠️ | **MEDIUM RISK** - Should be validated |
| 🔍 | **INSPECT** - Requires careful analysis |
| ✅ | **SAFE** - Standard metadata |

---

## 1. 📄 PDF FILE FORMAT

### **Structure with Security Flags**


┌─────────────────────────────────────────────────────────┐
│  PDF FILE STRUCTURE                                     │
├─────────────────────────────────────────────────────────┤
│  HEADER (8-20 bytes)                                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │ %PDF-1.x (5-8 bytes)                              │  │
│  │ ⚠️ Check: Version < 1.4 (old exploits)            │  │
│  │ %âãÏÓ (4 bytes) - Binary marker                   │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  BODY - OBJECTS (Variable)                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 JAVASCRIPT OBJECTS                             │  │
│  │   /JavaScript - Embedded JS code                  │  │
│  │   /JS - JavaScript actions                        │  │
│  │   /OpenAction - Auto-execute on open              │  │
│  │   /AA - Additional actions                        │  │
│  │                                                    │  │
│  │ 🚨 EMBEDDED FILES                                 │  │
│  │   /EmbeddedFile - Attachments                     │  │
│  │   /Filespec - File specifications                 │  │
│  │                                                    │  │
│  │ ⚠️ LAUNCH ACTIONS                                 │  │
│  │   /Launch - Launch external programs              │  │
│  │   /RichMedia - Flash/ multimedia                  │  │
│  │                                                    │  │
│  │ 🔍 OBFUSCATED STREAMS                             │  │
│  │   Filter: /FlateDecode (compression)              │  │
│  │   Filter: /ASCII85Decode                          │  │
│  │   Filter: Multiple filters (layered obfuscation)  │  │
│  │   High entropy (>7.5) - Packed/encrypted content  │  │
│  │                                                    │  │
│  │ ⚠️ FORMS & ACTIVE CONTENT                         │  │
│  │   /AcroForm - Interactive forms                   │  │
│  │   /XFA - XML Forms Architecture                   │  │
│  │   /SubmitForm - Data submission                   │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  CROSS-REFERENCE TABLE                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check for:                                     │  │
│  │   - Inconsistent offsets                          │  │
│  │   - Missing objects                               │  │
│  │   - Linearized PDF (fast web view) exploits       │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  TRAILER                                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - Encrypt dictionary (password protection)      │  │
│  │   - Permissions (restrictions bypass)             │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical PDF Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| `/JS` or `/JavaScript` | Embedded scripts, `app.launchURL`, `util.printf` exploits | 🚨 HIGH |
| `/OpenAction` | Auto-execute on document open | 🚨 HIGH |
| `/Launch` | Execute external programs (EXE, JS, VBS) | 🚨 HIGH |
| `/EmbeddedFile` | Malicious attachments, droppers | 🚨 HIGH |
| `/AA` (Additional Actions) | Trigger on focus, blur, key press | ⚠️ MEDIUM |
| `/RichMedia` | Flash exploits (CVE-2015-5119, etc.) | 🚨 HIGH |
| `/AcroForm` + `/SubmitForm` | Data exfiltration | ⚠️ MEDIUM |
| Stream filters | Multiple nested filters, unusual encoding | 🔍 INSPECT |
| High entropy sections | Packed/encrypted malware payload | 🔍 INSPECT |

---

## 2. 🐧 ELF (LINUX EXECUTABLE) FORMAT

### **Structure with Security Flags**

┌─────────────────────────────────────────────────────────┐
│  ELF FILE STRUCTURE (64-bit)                            │
├─────────────────────────────────────────────────────────┤
│  ELF HEADER (64 bytes)                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ e_ident[16]      │ 16 bytes │ Magic + Class info  │  │
│  │ ⚠️ Check: Corrupted magic, unusual class          │  │
│  │ e_type           │ 2 bytes  │ Object file type    │  │
│  │ 🔍 ET_EXEC (2), ET_DYN (3) - both can be malicious│  │
│  │ e_machine        │ 2 bytes  │ Architecture        │  │
│  │ e_entry          │ 8 bytes  │ Entry point addr    │  │
│  │ 🚨 Check: Entry in .data, .bss, or unusual section│  │
│  │ e_phoff          │ 8 bytes  │ Program header off  │  │
│  │ e_shoff          │ 8 bytes  │ Section header off  │  │
│  │ ⚠️ Check: e_shoff = 0 (stripped headers)          │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  PROGRAM HEADER TABLE (56 bytes × N segments)           │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 PT_LOAD segments with RWX permissions          │  │
│  │   p_flags: PF_X (execute) + PF_W (write) = BAD    │  │
│  │                                                    │  │
│  │ 🔍 PT_INTERP (interpreter)                        │  │
│  │   Check for unusual paths, relative paths         │  │
│  │                                                    │  │
│  │ ⚠️ PT_GNU_STACK                                   │  │
│  │   Flags: 0 (executable stack) = VULNERABLE        │  │
│  │   Flags: PF_R (readable only) = SAFE              │  │
│  │                                                    │  │
│  │ 🔍 PT_DYNAMIC                                     │  │
│  │   Check for suspicious DT_NEEDED libraries        │  │
│  │   Check for DT_RPATH with writable paths          │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  SECTIONS - DANGEROUS AREAS                             │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 .text section                                  │  │
│  │   - Check for suspicious syscalls                 │  │
│  │   - fork(), execve(), ptrace(), socket()          │  │
│  │   - Check entropy (packed malware)                │  │
│  │                                                    │  │
│  │ 🔍 .init_array / .fini_array                      │  │
│  │   - Constructor/destructor functions              │  │
│  │   - Can execute before main()                     │  │
│  │                                                    │  │
│  │ 🚨 .dynamic section                               │  │
│  │   - DT_INIT, DT_FINI (init/fini functions)        │  │
│  │   - DT_PREINIT_ARRAY                              │  │
│  │                                                    │  │
│  │ ⚠️ .got.plt / .plt                                │  │
│  │   - PLT/GOT overwrite exploits                    │  │
│  │   - Check for unusual relocations                 │  │
│  │                                                    │  │
│  │ 🔍 .debug_* sections                              │  │
│  │   - May contain hidden data                       │  │
│  │   - Unusual for production binaries               │  │
│  │                                                    │  │
│  │ 🚨 Non-standard sections                          │  │
│  │   - Custom section names (e.g., .hack, .payload)  │  │
│  │   - Sections with RWX permissions                 │  │
│  │   - .upx0, .upx1 (UPX packed - common malware)    │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical ELF Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **Entry point** | In `.data`, `.bss`, or non-executable section | 🚨 HIGH |
| **Segment flags** | `PF_W` + `PF_X` (writable + executable) | 🚨 HIGH |
| **.text section** | `ptrace`, `socket`, `execve`, `fork` syscalls | 🚨 HIGH |
| **.init_array** | Hidden constructors running before main() | 🚨 HIGH |
| **.got.plt** | GOT overwrite indicators, unusual relocations | 🚨 HIGH |
| **PT_INTERP** | Unusual interpreter path, relative path | ⚠️ MEDIUM |
| **PT_GNU_STACK** | Executable stack (no NX protection) | ⚠️ MEDIUM |
| **Section entropy** | High entropy (>7.5) in `.text` (packed) | 🔍 INSPECT |
| **Non-standard sections** | Custom names, RWX permissions | 🔍 INSPECT |
| **Stripped binary** | No symbols + suspicious behavior | 🔍 INSPECT |

---

## 3. 📝 DOCX/OFFICE OPEN XML FORMAT

### **Structure with Security Flags**
┌─────────────────────────────────────────────────────────┐
│  DOCX FILE STRUCTURE (ZIP Archive)                      │
├─────────────────────────────────────────────────────────┤
│  ZIP STRUCTURE CHECKS                                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - ZIP bomb (extreme compression ratio)          │  │
│  │   - File path traversal (../) in filenames        │  │
│  │   - Duplicate file entries                        │  │
│  │   - Invalid ZIP structure                         │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  🚨 CRITICAL FILES TO INSPECT                           │
│  ┌───────────────────────────────────────────────────┐  │
│  │ word/document.xml                                 │  │
│  │   🔍 Check for:                                   │  │
│  │   - w:object (embedded OLE objects)               │  │
│  │   - w:link (external links to malicious URLs)     │  │
│  │   - w:script (script tags - rare but dangerous)   │  │
│  │                                                    │  │
│  │ 🚨 word/_rels/document.xml.rels                   │  │
│  │   - External relationships                        │  │
│  │   - Links to remote templates                     │  │
│  │   - Remote images/scripts                         │  │
│  │                                                    │  │
│  │ 🚨 word/vbaProject.bin                            │  │
│  │   - VBA MACROS (if present = HIGH RISK)           │  │
│  │   - AutoOpen, AutoClose, Document_Open            │  │
│  │   - Shell, CreateObject, WScript                  │  │
│  │   - PowerShell execution                          │  │
│  │                                                    │  │
│  │ ⚠️ word/settings.xml                              │  │
│  │   - w:template (remote template injection)        │  │
│  │   - w:linkToTemplate                              │  │
│  │                                                    │  │
│  │ 🔍 word/media/*                                   │  │
│  │   - Check for executable files disguised as media │  │
│  │   - Unusual file extensions                       │  │
│  │                                                    │  │
│  │ 🚨 word/embeddings/*                              │  │
│  │   - Embedded OLE objects (Excel, EXE, etc.)       │  │
│  │   - Package objects                               │  │
│  │   - Check embedded file magic bytes               │  │
│  │                                                    │  │
│  │ ⚠️ docProps/custom.xml                            │  │
│  │   - Custom properties with macros                 │  │
│  │   - Unusual metadata                              │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical DOCX Detection Points**

| File/Location | Dangerous Indicators | Risk Level |
|---------------|---------------------|------------|
| **word/vbaProject.bin** | VBA macros present, AutoOpen, Shell commands | 🚨 HIGH |
| **word/embeddings/** | Embedded OLE objects, EXE, script files | 🚨 HIGH |
| **word/document.xml** | `w:object`, `w:link`, external references | ⚠️ MEDIUM |
| **word/settings.xml** | `w:template` pointing to remote UNC/SMB path | 🚨 HIGH |
| **word/_rels/*.rels** | External relationships to malicious URLs | ⚠️ MEDIUM |
| **word/media/** | Executable files with fake extensions | 🔍 INSPECT |
| **ZIP structure** | Path traversal, ZIP bomb, invalid entries | 🔍 INSPECT |

---

## 4. 📊 XLSX (EXCEL) FORMAT

### **Structure with Security Flags**

┌─────────────────────────────────────────────────────────┐
│  XLSX FILE STRUCTURE                                    │
├─────────────────────────────────────────────────────────┤
│  🚨 CRITICAL FILES TO INSPECT                           │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 xl/vbaProject.bin                              │  │
│  │   - VBA MACROS (if present)                       │  │
│  │   - Auto_Open, Workbook_Open                      │  │
│  │   - Shell, CreateObject, Execute                  │  │
│  │   - PowerShell, cmd.exe execution                 │  │
│  │                                                    │  │
│  │ 🚨 xl/worksheets/sheet*.xml                       │  │
│  │   🔍 Check for:                                   │  │
│  │   - External links (xl:externalReference)         │  │
│  │   - WEBSERVICE function calls                     │  │
│  │   - HYPERLINK to malicious URLs                   │  │
│  │   - Embedded objects                              │  │
│  │                                                    │  │
│  │ ⚠️ xl/externalLinks/externalLink*.xml             │  │
│  │   - Links to external workbooks                   │  │
│  │   - Remote data connections                       │  │
│  │   - UNC/SMB paths (\server\share)                │  │
│  │                                                    │  │
│  │ 🚨 xl/embeddings/*                                │  │
│  │   - Embedded OLE objects                          │  │
│  │   - Package, Script, Executable files             │  │
│  │                                                    │  │
│  │ ⚠️ xl/connections.xml                             │  │
│  │   - External data connections                     │  │
│  │   - ODBC, OLEDB connections                       │  │
│  │   - Web queries                                   │  │
│  │                                                    │  │
│  │ 🔍 xl/pivotCache/pivotCacheDefinition*.xml        │  │
│  │   - External data sources                         │  │
│  │   - Remote connections                            │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### 🚨 Critical XLSX Detection Points

| File/Location | Dangerous Indicators | Risk Level |
|---------------|---------------------|------------|
| **xl/vbaProject.bin** | VBA macros, Auto_Open, Shell, PowerShell | 🚨 HIGH |
| **xl/embeddings/** | Embedded executables, OLE objects | 🚨 HIGH |
| **xl/externalLinks/** | External workbook links, UNC paths | ⚠️ MEDIUM |
| **xl/worksheets/sheet*.xml** | `WEBSERVICE`, `HYPERLINK`, external refs | ⚠️ MEDIUM |
| **xl/connections.xml** | ODBC/OLEDB connections, web queries | 🔍 INSPECT |

---

## 5. 🎬 MP4/MOV (MPEG-4) FORMAT

### Structure with Security Flags


┌─────────────────────────────────────────────────────────┐
│  MP4/MOV FILE STRUCTURE                                 │
├─────────────────────────────────────────────────────────┤
│  FTYP BOX                                                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - Unusual brand compatibility                   │  │
│  │   - Mismatched file extension vs brand            │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  MOOV BOX - METADATA (Exploit Target)                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 MALFORMED BOXES                                │  │
│  │   - Integer overflow in box size fields           │  │
│  │   - Negative sizes                                │  │
│  │   - Overlapping boxes                             │  │
│  │                                                    │  │
│  │ 🔍 UNUSUAL BOX TYPES                              │  │
│  │   - Custom/private boxes (vendor-specific)        │  │
│  │   - Boxes with executable data                    │  │
│  │                                                    │  │
│  │ ⚠️ METADATA BOXES                                 │  │
│  │   - udta (user data) - can contain scripts        │  │
│  │   - meta (metadata) - XMP with scripts            │  │
│  │   - Check for embedded JavaScript                 │  │
│  │                                                    │  │
│  │ 🚨 SAMPLE TABLE CORRUPTION                        │  │
│  │   - stsz (sample size) - extreme values           │  │
│  │   - stco/co64 (chunk offset) - out of bounds      │  │
│  │   - stsc (sample-to-chunk) - invalid entries      │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  MDAT BOX - MEDIA DATA                                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - Actual codec data vs claimed codec            │  │
│  │   - Mismatched codec FourCC                       │  │
│  │   - Embedded files in metadata                    │  │
│  │   - Steganography in video frames                 │  │
│  │                                                    │  │
│  │ 🚨 MALFORMED CODEC DATA                           │  │
│  │   - Buffer overflow exploits in parsers           │  │
│  │   - CVE-2019-11236 (libx265), CVE-2020-10199      │  │
│  │   - Integer overflows in dimension fields         │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical MP4 Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **Box sizes** | Integer overflow, negative values, overlapping | 🚨 HIGH |
| **Sample tables** | Extreme values, out-of-bounds offsets | 🚨 HIGH |
| **Codec data** | Malformed H.264/HEVC, known CVE exploits | 🚨 HIGH |
| **udta/meta boxes** | Embedded scripts, XMP with JavaScript | ⚠️ MEDIUM |
| **FourCC mismatch** | Claimed codec ≠ actual codec | 🔍 INSPECT |
| **Dimensions** | Extreme width/height (DoS, overflow) | 🔍 INSPECT |

---

## 6. 🖼️ JPEG IMAGE FORMAT

### **Structure with Security Flags**

┌─────────────────────────────────────────────────────────┐
│  JPEG FILE STRUCTURE                                    │
├─────────────────────────────────────────────────────────┤
│  SOI + APP0/JFIF                                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ✅ Standard header                                │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  🚨 APP1/EXIF - METADATA                                │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check for:                                     │  │
│  │   - Malformed TIFF structure                      │  │
│  │   - Integer overflow in IFD entries               │  │
│  │   - CVE-2016-3739 (ImageMagick), CVE-2018-19664   │  │
│  │   - Unusual tag values                            │  │
│  │   - Embedded scripts in XMP                       │  │
│  │   - GPS data with extreme values                  │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  🚨 APPn SEGMENTS (APP1-APP15)                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - APPn with unusual data                        │  │
│  │   - Embedded files in APP segments                │  │
│  │   - Steganography payloads                        │  │
│  │   - Oversized APP segments (DoS)                  │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  SOS + ENTROPY-CODED DATA                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 MALFORMED SCAN DATA                            │  │
│  │   - Buffer overflow in Huffman decoder            │  │
│  │   - CVE-2019-12900 (libjpeg-turbo)                │  │
│  │   - Arithmetic coding exploits                    │  │
│  │   - Progressive JPEG exploits                     │  │
│  │                                                    │  │
│  │ 🔍 Check:                                         │  │
│  │   - Mismatched scan parameters                    │  │
│  │   - Invalid restart intervals                     │  │
│  │   - Truncated data                                │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  COM (Comment) SEGMENTS                                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - Embedded scripts/commands                     │  │
│  │   - Encoded payloads                              │  │
│  │   - Steganography                                 │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### 🚨 Critical JPEG Detection Points

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **APP1/EXIF** | Malformed TIFF, integer overflow, XMP scripts | 🚨 HIGH |
| **APPn segments** | Oversized, embedded files, steganography | ⚠️ MEDIUM |
| **SOS/scan data** | Buffer overflow, malformed Huffman tables | 🚨 HIGH |
| **COM segments** | Embedded scripts, encoded payloads | 🔍 INSPECT |
| **Image dimensions** | Extreme values (DoS, overflow) | 🔍 INSPECT |

---

## 7. 🎨 PNG IMAGE FORMAT

### Structure with Security Flags


┌─────────────────────────────────────────────────────────┐
│  PNG FILE STRUCTURE                                     │
├─────────────────────────────────────────────────────────┤
│  PNG SIGNATURE (8 bytes)                                │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ✅ Fixed signature - verify integrity             │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  IHDR CHUNK                                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 Check:                                         │  │
│  │   - Width/Height: Extreme values (DoS)            │  │
│  │   - Bit depth: Invalid values                     │  │
│  │   - Color type: Mismatched with data              │  │
│  │   - CVE-2016-3739, CVE-2018-14598                 │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  ANCILLARY CHUNKS - DANGEROUS AREAS                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 tEXt / zTXt / iTXt chunks                      │  │
│  │   - Embedded scripts in text data                 │  │
│  │   - XMP metadata with JavaScript                  │  │
│  │   - Oversized text chunks (DoS)                   │  │
│  │                                                    │  │
│  │ 🔍 iTXt (International Text)                      │  │
│  │   - Can contain compressed data                   │  │
│  │   - Language tags with exploits                   │  │
│  │                                                    │  │
│  │ ⚠️ Unknown/private chunks                         │  │
│  │   - Custom chunks (vendor-specific)               │  │
│  │   - May contain hidden payloads                   │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  IDAT CHUNKS (Compressed Data)                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 Check:                                         │  │
│  │   - zlib compression bomb                         │  │
│  │   - Buffer overflow in inflate                    │  │
│  │   - CVE-2019-6129 (libpng)                        │  │
│  │   - Truncated or corrupted data                   │  │
│  │   - Multiple IDAT with inconsistent data          │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  tRNS CHUNK (Transparency)                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - Invalid palette indices                       │  │
│  │   - Out-of-bounds alpha values                    │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical PNG Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **IHDR** | Extreme dimensions, invalid color type/bit depth | 🚨 HIGH |
| **tEXt/zTXt/iTXt** | Embedded scripts, XMP with JS, oversized | ⚠️ MEDIUM |
| **IDAT** | zlib bomb, buffer overflow, CVE exploits | 🚨 HIGH |
| **Unknown chunks** | Custom chunks with payloads | 🔍 INSPECT |
| **tRNS** | Invalid palette indices, out-of-bounds | 🔍 INSPECT |

---

## 8. 📦 ZIP ARCHIVE FORMAT

### **Structure with Security Flags**


┌─────────────────────────────────────────────────────────┐
│  ZIP FILE STRUCTURE                                     │
├─────────────────────────────────────────────────────────┤
│  🚨 CRITICAL SECURITY CHECKS                            │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ZIP BOMB                                          │  │
│  │   - Compression ratio > 1000:1                    │  │
│  │   - Small ZIP, huge uncompressed size             │  │
│  │   - Example: 42.zip (42KB → 4.5PB)                │  │
│  │                                                    │  │
│  │ PATH TRAVERSAL                                    │  │
│  │   - Filenames with "../" sequences                │  │
│  │   - Absolute paths (C:, /etc/)                   │  │
│  │   - Write to sensitive locations                  │  │
│  │                                                    │  │
│  │ SYMLINK ATTACK                                    │  │
│  │   - Symlinks pointing to sensitive files          │  │
│  │   - Extract to overwrite system files             │  │
│  │                                                    │  │
│  │ DUPLICATE FILE ENTRIES                            │  │
│  │   - Same file multiple times                      │  │
│  │   - Last entry wins (overwrite)                   │  │
│  │                                                    │  │
│  │ SLIPSTREAM ATTACK                                 │  │
│  │   - Antivirus scans first entry only              │  │
│  │   - Malicious file as second entry                │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  LOCAL FILE HEADERS                                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check each entry:                              │  │
│  │   - Filename: Path traversal, absolute paths      │  │
│  │   - Compressed/Uncompressed size mismatch         │  │
│  │   - Compression method: Unknown methods           │  │
│  │   - File extension vs actual content              │  │
│  │   - Executable files (.exe, .js, .vbs, .ps1)      │  │
│  │   - Script files in unexpected locations          │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  ENCRYPTED ZIP FILES                                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ⚠️ Check:                                         │  │
│  │   - Weak encryption (ZipCrypto)                   │  │
│  │   - Password-protected malicious content          │  │
│  │   - Encrypted filenames (ZIP 6.3+)                │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical ZIP Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **Compression ratio** | >1000:1 (ZIP bomb) | 🚨 HIGH |
| **Filenames** | Path traversal (`../`), absolute paths | 🚨 HIGH |
| **File entries** | Executables, scripts, symlinks | 🚨 HIGH |
| **Duplicate entries** | Same file multiple times (overwrite) | ⚠️ MEDIUM |
| **Encrypted ZIP** | Hidden malicious content | 🔍 INSPECT |
| **Size fields** | Mismatch compressed/uncompressed | 🔍 INSPECT |

---

## 9. 🗜️ RAR ARCHIVE FORMAT

### **Structure with Security Flags**

┌─────────────────────────────────────────────────────────┐
│  RAR FILE STRUCTURE                                     │
├─────────────────────────────────────────────────────────┤
│  🚨 CRITICAL SECURITY CHECKS                            │
│  ┌───────────────────────────────────────────────────┐  │
│  │ RAR BOMB                                          │  │
│  │   - Extreme compression ratios                    │  │
│  │   - Solid archives with huge decompressed size    │  │
│  │                                                    │  │
│  │ PATH TRAVERSAL                                    │  │
│  │   - Absolute paths in filenames                   │  │
│  │   - UNC paths (\server\share)                    │  │
│  │   - Symlinks to sensitive files                   │  │
│  │                                                    │  │
│  │ SOLID ARCHIVE EXPLOITS                            │  │
│  │   - All files compressed together                 │  │
│  │   - Harder to scan individual files               │  │
│  │   - Decompression DoS                             │  │
│  │                                                    │  │
│  │ RECOVERY RECORDS                                  │  │
│  │   - Can contain arbitrary data                    │  │
│  │   - May hide malicious payloads                   │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  FILE HEADERS                                             │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - Filename: Path traversal, absolute paths      │  │
│  │   - File attributes: Hidden, system files         │  │
│  │   - Encrypted files (hidden content)              │  │
│  │   - Executable files, scripts                     │  │
│  │   - File size inconsistencies                     │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  ENCRYPTION                                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ⚠️ Check:                                         │  │
│  │   - AES-128/AES-256 encryption                    │  │
│  │   - Password-protected malicious archives         │  │
│  │   - Encrypted filenames (RAR 5.0+)                │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical RAR Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **Compression** | Extreme ratios (RAR bomb) | 🚨 HIGH |
| **Filenames** | Path traversal, absolute paths, UNC | 🚨 HIGH |
| **Solid archives** | Hard to scan, DoS risk | ⚠️ MEDIUM |
| **Encrypted files** | Hidden malicious content | 🔍 INSPECT |
| **Recovery records** | Arbitrary data, hidden payloads | 🔍 INSPECT |

---

## 10. 🔐 X.509 CERTIFICATE FORMAT (.cert, .crt, .pem, .der)

### **Structure with Security Flags**


┌─────────────────────────────────────────────────────────┐
│  X.509 CERTIFICATE STRUCTURE                            │
├─────────────────────────────────────────────────────────┤
│  🚨 CRITICAL SECURITY CHECKS                            │
│  ┌───────────────────────────────────────────────────┐  │
│  │ WEAK ALGORITHMS                                   │  │
│  │   - Signature: MD5, SHA-1 (deprecated)            │  │
│  │   - Key: RSA < 2048 bits, DSA < 2048 bits         │  │
│  │   - ECC curves: Weak curves                       │  │
│  │                                                    │  │
│  │ SELF-SIGNED CERTIFICATES                          │  │
│  │   - issuer == subject                             │  │
│  │   - Not trusted by default                        │  │
│  │   - Common in MITM attacks                        │  │
│  │                                                    │  │
│  │ INVALID DATES                                     │  │
│  │   - notBefore > now (not yet valid)               │  │
│  │   - notAfter < now (expired)                      │  │
│  │   - Extremely long validity periods               │  │
│  │                                                    │  │
│  │ COMMON NAME MISMATCH                              │  │
│  │   - CN doesn't match expected domain              │  │
│  │   - subjectAltName mismatches                     │  │
│  │                                                    │  │
│  │ WEAK PUBLIC KEYS                                  │  │
│  │   - RSA modulus with known factors                │  │
│  │   - Shared modulus across certs                   │  │
│  │   - Predictable key generation                    │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  TBS CERTIFICATE (To Be Signed)                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - version: Should be v3 (2)                     │  │
│  │   - serialNumber: Negative, duplicate, weak RNG   │  │
│  │   - signature: Algorithm strength                 │  │
│  │   - issuer: Trusted CA? Self-signed?              │  │
│  │   - validity: Date ranges                         │  │
│  │   - subject: Expected entity                      │  │
│  │   - subjectPublicKeyInfo: Key strength            │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  EXTENSIONS (Critical Security Area)                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 basicConstraints                               │  │
│  │   - cA:TRUE without keyCertSign = BAD             │  │
│  │   - Missing basicConstraints in CA cert = BAD     │  │
│  │   - End-entity with cA:TRUE = SUSPICIOUS          │  │
│  │                                                    │  │
│  │ 🔍 keyUsage                                       │  │
│  │   - digitalSignature, keyEncipherment             │  │
│  │   - keyCertSign (only for CAs)                    │  │
│  │   - Mismatch with extendedKeyUsage                │  │
│  │                                                    │  │
│  │ ⚠️ extendedKeyUsage                               │  │
│  │   - serverAuth, clientAuth, codeSigning           │  │
│  │   - anyExtendedKeyUsage (dangerous)               │  │
│  │   - Mismatch with intended use                    │  │
│  │                                                    │  │
│  │ 🚨 subjectAltName                                 │  │
│  │   - DNS names, IP addresses                       │  │
│  │   - Wildcards (*.example.com)                     │  │
│  │   - Unexpected IPs/domains                        │  │
│  │   - Internal IPs (10.x, 192.168.x)                │  │
│  │                                                    │  │
│  │ 🔍 authorityKeyIdentifier                         │  │
│  │   - Links to issuing CA                           │  │
│  │   - Verify chain integrity                        │  │
│  │                                                    │  │
│  │ ⚠️ cRLDistributionPoints                          │  │
│  │   - CRL URLs (check accessibility)                │  │
│  │   - Revocation status                             │  │
│  │                                                    │  │
│  │ 🔍 authorityInfoAccess                            │  │
│  │   - OCSP URLs                                     │  │
│  │   - CA Issuers URL                                │  │
│  │                                                    │  │
│  │ 🚨 certificatePolicies                            │  │
│  │   - Policy OIDs                                   │  │
│  │   - anyPolicy (2.5.29.32.0) = less restrictive    │  │
│  │                                                    │  │
│  │ ⚠️ nameConstraints (CA certs only)               │  │
│  │   - Permitted/excluded subtrees                   │  │
│  │   - Missing in intermediate CAs = RISK            │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  SIGNATURE VERIFICATION                                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🚨 MUST VERIFY:                                   │  │
│  │   - Signature algorithm strength                  │  │
│  │   - Signature validity (cryptographic)            │  │
│  │   - Chain of trust to trusted root                │  │
│  │   - Revocation status (CRL/OCSP)                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical Certificate Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **Signature algorithm** | MD5, SHA-1, weak RSA (<2048) | 🚨 HIGH |
| **basicConstraints** | `cA:TRUE` on end-entity, missing on CA | 🚨 HIGH |
| **subjectAltName** | Unexpected domains/IPs, internal IPs | 🚨 HIGH |
| **Validity dates** | Expired, not yet valid, extremely long | ⚠️ MEDIUM |
| **Self-signed** | `issuer == subject`, not in trust store | ⚠️ MEDIUM |
| **keyUsage** | Missing, mismatched with extendedKeyUsage | 🔍 INSPECT |
| **extendedKeyUsage** | `anyExtendedKeyUsage`, mismatch | 🔍 INSPECT |
| **Public key** | Weak key, shared modulus, predictable | 🚨 HIGH |
| **Serial number** | Negative, duplicate, weak RNG | 🔍 INSPECT |
| **CRL/OCSP** | Missing, inaccessible, revoked | 🔍 INSPECT |

---

## 11. 📧 EMAIL FORMATS (PST)

### **Structure with Security Flags**

┌─────────────────────────────────────────────────────────┐
│  PST FILE STRUCTURE                                     │
├─────────────────────────────────────────────────────────┤
│  🚨 CRITICAL SECURITY CHECKS                            │
│  ┌───────────────────────────────────────────────────┐  │
│  │ EMBEDDED EXECUTABLES                              │  │
│  │   - Attachments: .exe, .js, .vbs, .ps1, .bat      │  │
│  │   - OLE embedded objects                          │  │
│  │   - RTF exploits (CVE-2017-11882)                 │  │
│  │                                                    │  │
│  │ MALICIOUS LINKS                                   │  │
│  │   - URLs to phishing sites                        │  │
│  │   - Shortened URLs (bit.ly, etc.)                 │  │
│  │   - IP addresses instead of domains               │  │
│  │   - Homograph attacks (xn-- domains)              │  │
│  │                                                    │  │
│  │ HTML EMAIL EXPLOITS                               │  │
│  │   - JavaScript in HTML emails                     │  │
│  │   - External images (tracking/beacons)            │  │
│  │   - CSS exploits                                  │  │
│  │   - IFRAME injection                              │  │
│  │                                                    │  │
│  │ HEADER SPOOFING                                   │  │
│  │   - From: address spoofing                        │  │
│  │   - Reply-To: mismatch                            │  │
│  │   - Missing/malformed SPF, DKIM, DMARC            │  │
│  │                                                    │  │
│  │ ATTACHMENT OBFUSCATION                            │  │
│  │   - Double extensions: file.pdf.exe               │  │
│  │   - Archive passwords                             │  │
│  │   - Encrypted attachments                         │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  MESSAGE PROPERTIES                                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 🔍 Check:                                         │  │
│  │   - PR_BODY (plain text body) - phishing links    │  │
│  │   - PR_BODY_HTML - HTML exploits                  │  │
│  │   - PR_ATTACH_FILENAME - malicious attachments    │  │
│  │   - PR_ATTACH_DATA_BIN - embedded files           │  │
│  │   - PR_SENDER_EMAIL - spoofed addresses           │  │
│  │   - PR_RECEIVED_BY_EMAIL - routing analysis       │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘


### **🚨 Critical Email Detection Points**

| Location | Dangerous Indicators | Risk Level |
|----------|---------------------|------------|
| **Attachments** | Executables, scripts, OLE objects, RTF exploits | 🚨 HIGH |
| **HTML body** | JavaScript, IFRAMEs, external resources | 🚨 HIGH |
| **Links/URLs** | Phishing, shortened URLs, IP addresses | 🚨 HIGH |
| **Headers** | Spoofed From, missing SPF/DKIM/DMARC | ⚠️ MEDIUM |
| **Attachment names** | Double extensions, disguised files | 🚨 HIGH |
| **Embedded images** | Tracking pixels, external beacons | 🔍 INSPECT |

---

## 📊 QUICK REFERENCE TABLE

| Format | Min Size | Typical Size | Max Size | Key Sections |
|--------|----------|--------------|----------|--------------|
| **PDF** | 1 KB | 100 KB - 10 MB | 10 GB+ | Header, Body, XREF, Trailer |
| **ELF** | 1 KB | 10 KB - 100 MB | 2 GB+ | ELF Header, Sections, Segments |
| **DOCX** | 5 KB | 50 KB - 10 MB | 2 GB | ZIP + XML files |
| **XLSX** | 5 KB | 100 KB - 50 MB | 2 GB | ZIP + worksheets |
| **MP4** | 10 KB | 5 MB - 5 GB | 256 GB | ftyp, moov, mdat |
| **JPEG** | 2 KB | 100 KB - 10 MB | 2³² pixels | SOI, APPn, DQT, SOF, IDAT, EOI |
| **PNG** | 50 B | 100 KB - 20 MB | 2³¹ pixels | IHDR, IDAT, IEND + chunks |
| **ZIP** | 22 B | 1 KB - 100 GB | 16 EB | Local headers, data, central dir |
| **RAR** | 8 B | 1 KB - 100 GB | 16 EB | Main hdr, file hdrs, data, end |
| **X.509** | 200 B | 1 KB - 10 KB | 100 KB | DER/PEM encoded ASN.1 |
| **PST** | 512 B | 1 MB - 20 GB | 50 GB | NDB, LTP, Messaging layers |

### **🚨 HIGHEST RISK AREAS BY FILE TYPE**

| File Type | Highest Risk Areas | Common Exploits |
|-----------|-------------------|-----------------|
| **PDF** | JavaScript, /OpenAction, /Launch, Embedded files | CVE-2010-2883, CVE-2015-5119 |
| **ELF** | RWX segments, .init_array, GOT/PLT, entry point | CVE-2021-3156, CVE-2021-4034 |
| **DOCX** | VBA macros, embedded OLE, remote templates | CVE-2017-11882, CVE-2017-0199 |
| **XLSX** | VBA macros, external links, embedded objects | CVE-2016-0031, CVE-2017-0199 |
| **MP4** | Malformed boxes, sample tables, codec data | CVE-2019-11236, CVE-2020-10199 |
| **JPEG** | EXIF/TIFF, APPn segments, scan data | CVE-2016-3739, CVE-2018-19664 |
| **PNG** | IHDR dimensions, IDAT compression, text chunks | CVE-2016-3739, CVE-2019-6129 |
| **ZIP** | Path traversal, ZIP bomb, symlinks | CVE-2021-44228 (log4j in ZIP) |
| **RAR** | Path traversal, solid archives, encryption | CVE-2022-30333 |
| **X.509** | Weak algorithms, basicConstraints, SANs | SHA-1 collision, ROCA vulnerability |
| **Email/PST** | Attachments, HTML exploits, header spoofing | CVE-2017-11882, phishing |

---

## 🔍 ANALYSIS TOOLS RECOMMENDATIONS

| Tool | Purpose | File Types |
|------|---------|------------|
| **peepdf, pdf-parser** | PDF analysis | PDF |
| **LIEF, readelf** | ELF analysis | ELF |
| **oledump, oledump.py** | OLE/Office analysis | DOC, XLS, PPT |
| **exiftool** | Metadata extraction | All |
| **yara** | Pattern matching | All |
| **file, TrID** | File type identification | All |
| **binwalk** | Embedded file extraction | All |
| **VirusTotal** | Multi-engine scanning | All |
| **Any.Run, Hybrid Analysis** | Dynamic analysis | All |
| **strings** | Extract readable strings | All binaries |
| **xxd, hexdump** | Hex inspection | All |
| **7z, unzip** | Archive extraction | ZIP, RAR |
| **openssl** | Certificate analysis | X.509 |
| **pst2mdb, readpst** | PST analysis | PST |

---

## ✅ BEST PRACTICES FOR SAFE ANALYSIS

### **Environment Setup**

1. **Use isolated VMs** - Never analyze on host system
   - VirtualBox, VMware, QEMU/KVM
   - Take snapshots before analysis
   - Restore after each analysis

2. **Disable network** - Prevent C2 communication
   - Host-only networking
   - Disable network adapters
   - Use network simulation tools (INetSim)

3. **Use read-only mounts** - Prevent accidental execution
   - Mount files as read-only
   - Use write-blockers for physical media

### **Analysis Procedures**

4. **Validate checksums** - Ensure file integrity
   - Calculate MD5, SHA-1, SHA-256
   - Compare with known databases

5. **Update tools** - Latest CVE signatures
   - Update YARA rules regularly
   - Keep antivirus engines current
   - Update analysis tools weekly

6. **Document findings** - Maintain analysis records
   - File hashes
   - IOCs (Indicators of Compromise)
   - Behavioral patterns
   - Network indicators

7. **Report to authorities** - If illegal content found
   - Follow legal procedures
   - Maintain chain of custody
   - Document everything

### **Safety Checks**

8. **Never execute unknown files** on production systems
9. **Use sandboxing** for dynamic analysis
10. **Monitor system calls** during execution
11. **Check for anti-analysis** techniques
12. **Verify tool integrity** before use

---

## 📚 ADDITIONAL RESOURCES

### **Documentation**
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence framework
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### **Training**
- SANS FOR500 - Windows Forensic Analysis
- SANS FOR508 - Advanced Incident Response
- Offensive Security - OSCP, OSCE

### **Communities**
- MalwareTech Blog
- Reverse Engineering Stack Exchange
- /r/Malware (Reddit)
- VirusTotal Community

---

## ⚠️ LEGAL DISCLAIMER

**This document is for EDUCATIONAL and DEFENSIVE purposes only.**

- ✅ Use for: Security research, malware analysis, defensive programming, incident response
- ❌ Do NOT use for: Creating malware, unauthorized access, illegal activities

**Always:**
- Obtain proper authorization before analyzing files
- Work within legal boundaries
- Follow your organization's security policies
- Respect privacy and data protection laws

**Unauthorized analysis or distribution of malware is ILLEGAL and may result in:**
- Criminal charges
- Civil lawsuits
- Professional consequences
- Imprisonment

---

**Document Version:** 1.0  




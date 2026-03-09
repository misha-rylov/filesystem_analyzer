/*
 * Corporate Security YARA Rules
 * Basic rules for static file analysis
 * Version: 1.0.0
 */

rule pdf_javascript
{
  meta:
    author = "CorpSec"
    description = "PDF contains JavaScript or JS action"
    severity = "high"
  strings:
    $js1 = "/JavaScript" ascii
    $js2 = "/JS" ascii
    $js3 = "/OpenAction" ascii
    $js4 = "/AA" ascii  // Additional Action
  condition:
    any of them
}

rule pdf_launch_action
{
  meta:
    author = "CorpSec"
    description = "PDF contains launch action - may execute external programs"
    severity = "critical"
  strings:
    $launch = "/Launch" ascii
  condition:
    $launch
}

rule pdf_suspicious_action
{
  meta:
    author = "CorpSec"
    description = "PDF contains suspicious action (Print, Import, Export)"
    severity = "medium"
  strings:
    $print = "/Print" ascii
    $import = "/Import" ascii
    $export = "/Export" ascii
  condition:
    any of them
}

rule office_macro
{
  meta:
    author = "CorpSec"
    description = "Office document contains VBA macros"
    severity = "critical"
  strings:
    $vba = "vbaProject.bin" ascii
  condition:
    $vba
}

rule office_ole_object
{
  meta:
    author = "CorpSec"
    description = "Office document contains embedded OLE object"
    severity = "high"
  strings:
    $ole = "OLECompoundFile" ascii
    $embed = "embeddings/" ascii
  condition:
    any of them
}

rule archive_path_traversal
{
  meta:
    author = "CorpSec"
    description = "Archive contains path traversal attempts"
    severity = "high"
  strings:
    $pt1 = ".." ascii
    $pt2 = "..\\" ascii
  condition:
    $pt1 or $pt2
}

rule archive_suspicious_extension
{
  meta:
    author = "CorpSec"
    description = "Archive contains potentially dangerous file types"
    severity = "medium"
  strings:
    $exe = ".exe" ascii nocase
    $dll = ".dll" ascii nocase
    $bat = ".bat" ascii nocase
    $cmd = ".cmd" ascii nocase
    $ps1 = ".ps1" ascii nocase
    $vbs = ".vbs" ascii nocase
    $scr = ".scr" ascii nocase
    $hta = ".hta" ascii nocase
  condition:
    any of them
}

rule script_powershell_suspicious
{
  meta:
    author = "CorpSec"
    description = "PowerShell script with suspicious commands"
    severity = "high"
  strings:
    $ps1 = "Invoke-Expression" nocase
    $ps2 = "IEX" nocase
    $ps3 = "DownloadString" nocase
    $ps4 = "DownloadFile" nocase
    $ps5 = "Start-Process" nocase
    $ps6 = "New-Object Net.WebClient" nocase
    $ps7 = "Set-ExecutionPolicy" nocase
    $ps8 = "Invoke-WebRequest" nocase
    $ps9 = "Invoke-RestMethod" nocase
    $ps10 = "编码" wide  // Encoded command
  condition:
    any of them
}

rule script_vbs_suspicious
{
  meta:
    author = "CorpSec"
    description = "VBScript with suspicious commands"
    severity = "high"
  strings:
    $vbs1 = "CreateObject" nocase
    $vbs2 = "WScript.Shell" nocase
    $vbs3 = "Shell.Application" nocase
    $vbs4 = "ADODB.Stream" nocase
    $vbs5 = "MSXML2.XMLHTTP" nocase
    $vbs6 = "window.execScript" nocase
    $vbs7 = "eval(" nocase
  condition:
    any of them
}

rule script_js_suspicious
{
  meta:
    author = "CorpSec"
    description = "JavaScript with suspicious actions"
    severity = "high"
  strings:
    $js1 = "ActiveXObject" nocase
    $js2 = "WScript.Shell" nocase
    $js3 = "Shell.Application" nocase
    $js4 = "document.write" nocase
    $js5 = "eval(" nocase
    $js6 = "setTimeout" nocase
    $js7 = "XMLHttpRequest" nocase
    $js8 = "fetch(" nocase
  condition:
    any of them
}

rule script_batch_suspicious
{
  meta:
    author = "CorpSec"
    description = "Batch script with suspicious commands"
    severity = "high"
  strings:
    $bat1 = "del /" nocase
    $bat2 = "format" nocase
    $bat3 = "net user" nocase
    $bat4 = "reg add" nocase
    $bat5 = "reg delete" nocase
    $bat6 = "powershell" nocase
    $bat7 = "certutil" nocase
    $bat8 = "bitsadmin" nocase
    $bat9 = "mshta" nocase
    $bat10 = "cscript" nocase
    $bat11 = "wscript" nocase
  condition:
    any of them
}

rule executable_packed
{
  meta:
    author = "CorpSec"
    description = "Executable appears to be packed or obfuscated"
    severity = "medium"
  strings:
    $upx = "UPX" ascii
    $aspack = ".aspack" ascii
    $petite = ".petite" ascii
  condition:
    any of them
}

rule executable_suspicious_section
{
  meta:
    author = "CorpSec"
    description = "Executable contains suspicious section names"
    severity = "medium"
  strings:
    $sec1 = ".upx" ascii nocase
    $sec2 = ".aspack" ascii nocase
    $sec3 = ".petite" ascii nocase
    $sec4 = ".upx0" ascii nocase
    $sec5 = ".upx1" ascii nocase
  condition:
    any of them
}

rule html_suspicious
{
  meta:
    author = "CorpSec"
    description = "HTML with suspicious content"
    severity = "high"
  strings:
    $html1 = "<script" nocase
    $html2 = "javascript:" nocase
    $html3 = "vbscript:" nocase
    $html4 = "onerror=" nocase
    $html5 = "onload=" nocase
    $html6 = "onclick=" nocase
    $html7 = "iframe" nocase
    $html8 = "<object" nocase
    $html9 = "<embed" nocase
    $html10 = "<applet" nocase
  condition:
    any of them
}

rule xml_suspicious
{
  meta:
    author = "CorpSec"
    description = "XML with potentially dangerous content"
    severity = "medium"
  strings:
    $xml1 = "<?xml-stylesheet" nocase
    $xml2 = "XSLT" nocase
    $xml3 = "XInclude" nocase
    $xml4 = "DOCTYPE html" nocase
  condition:
    any of them
}

rule jar_apk_suspicious
{
  meta:
    author = "CorpSec"
    description = "JAR/APK contains suspicious content"
    severity = "high"
  strings:
    $jar1 = "classes.dex" ascii
    $jar2 = "AndroidManifest.xml" ascii
    $jar3 = "META-INF/MANIFEST.MF" ascii
    $jar4 = "javax.crypto" ascii
    $jar5 = "java.lang.Runtime" ascii
  condition:
    any of them
}

rule email_suspicious
{
  meta:
    author = "CorpSec"
    description = "Email with suspicious content"
    severity = "high"
  strings:
    $email1 = "Content-Type: application/" ascii
    $email2 = "Content-Disposition: attachment" ascii
    $email3 = "filename=" ascii
    $email4 = "smime.p7s" ascii
    $email5 = "Signed-data" ascii
  condition:
    any of them
}

rule suspicious_url
{
  meta:
    author = "CorpSec"
    description = "File contains suspicious URLs"
    severity = "medium"
  strings:
    $url1 = /http:\/\/[^\s]{50,}/  // Long HTTP URLs
    $url2 = /https:\/\/[^\s]{50,}/
    $url3 = "ftp://" ascii
    $url4 = "tftp://" ascii
    $url5 = "smb://" ascii
    $url6 = "\\\\" ascii  // UNC path
  condition:
    any of them
}

rule encoded_content
{
  meta:
    author = "CorpSec"
    description = "File contains encoded content (base64, hex)"
    severity = "medium"
  strings:
    $b64_1 = "JVBERi0x" ascii  // PDF header base64
    $b64_2 = "TVRQVg==" ascii  // Generic base64 (MZ in base64)
    $hex1 = /0x[0-9A-Fa-f]{8}/  // Hex encoded dword
  condition:
    any of them
}

rule ransomware_indicator
{
  meta:
    author = "CorpSec"
    description = "Potential ransomware-related content"
    severity = "critical"
  strings:
    $r1 = "encrypted" nocase
    $r2 = "ransom" nocase
    $r3 = "bitcoin" nocase
    $r4 = "wallet" nocase
    $r5 = "decrypt" nocase
    $r6 = "restore" nocase
    $r7 = ".locked" nocase
    $r8 = ".crypt" nocase
  condition:
    2 of them
}

/*
 * Media File Rules - Video/Audio with malicious metadata
 */

rule media_embedded_executable
{
  meta:
    author = "CorpSec"
    description = "Media file contains embedded executable (MZ header)"
    severity = "critical"
  strings:
    $mz = "MZ" ascii
  condition:
    $mz
}

rule media_xml_entity_injection
{
  meta:
    author = "CorpSec"
    description = "Media file contains XML external entity (XXE) - potential SSRF"
    severity = "high"
  strings:
    $xxe1 = "<!ENTITY" nocase
    $xxe2 = "SYSTEM " nocase
    $xxe3 = "PUBLIC " nocase
  condition:
    any of them
}

rule media_script_in_metadata
{
  meta:
    author = "CorpSec"
    description = "Media file metadata contains script-like content"
    severity = "high"
  strings:
    $script1 = "<script" nocase
    $script2 = "javascript:" nocase
    $script3 = "vbscript:" nocase
    $script4 = "onerror=" nocase
    $script5 = "onload=" nocase
  condition:
    any of them
}

rule media_suspicious_url
{
  meta:
    author = "CorpSec"
    description = "Media file contains suspicious URL in metadata"
    severity = "medium"
  strings:
    $url1 = "http://" ascii
    $url2 = "https://" ascii
    $url3 = "ftp://" ascii
    $url4 = "tftp://" ascii
  condition:
    any of them
}

rule media_long_url
{
  meta:
    author = "CorpSec"
    description = "Media file contains unusually long URL - potential exfiltration"
    severity = "medium"
  strings:
    $longurl = /https?:\/\/[a-zA-Z0-9\-\.\_\~\:\/\?\#\[\@\!\$\&\'\(\)\*\+\,\;\=\%]{100,}/
  condition:
    $longurl
}

rule media_ip_in_url
{
  meta:
    author = "CorpSec"
    description = "Media file contains IP-based URL - suspicious"
    severity = "medium"
  strings:
    $ipurl = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
  condition:
    $ipurl
}

rule media_base64_content
{
  meta:
    author = "CorpSec"
    description = "Media file contains base64 encoded content"
    severity = "medium"
  strings:
    $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/
  condition:
    $b64
}

rule media_powershell_command
{
  meta:
    author = "CorpSec"
    description = "Media file contains PowerShell command"
    severity = "high"
  strings:
    $ps1 = "powershell" nocase
    $ps2 = "powershell.exe" nocase
    $ps3 = "IEX " nocase
    $ps4 = "Invoke-Expression" nocase
    $ps5 = "DownloadString" nocase
    $ps6 = "cmd.exe" nocase
    $ps7 = "certutil" nocase
  condition:
    any of them
}

rule media_wmi_command
{
  meta:
    author = "CorpSec"
    description = "Media file contains WMI command"
    severity = "high"
  strings:
    $wmi1 = "winmgmt" nocase
    $wmi2 = "IWbemServices" nocase
    $wmi3 = "ExecQuery" nocase
  condition:
    any of them
}

rule media_registry_modification
{
  meta:
    author = "CorpSec"
    description = "Media file contains registry modification commands"
    severity = "high"
  strings:
    $reg1 = "reg add" nocase
    $reg2 = "reg delete" nocase
    $reg3 = "HKLM\\" nocase
    $reg4 = "HKCU\\" nocase
    $reg5 = "HKEY_LOCAL_MACHINE" nocase
    $reg6 = "HKEY_CURRENT_USER" nocase
  condition:
    any of them
}

rule media_network_connection
{
  meta:
    author = "CorpSec"
    description = "Media file contains network connection indicators"
    severity = "medium"
  strings:
    $net1 = "socket" nocase
    $net2 = "connect(" nocase
    $net3 = "tcp://" nocase
    $net4 = "udp://" nocase
    $net5 = "WinSock" nocase
  condition:
    any of them
}

rule media_crypto_api
{
  meta:
    author = "CorpSec"
    description = "Media file contains cryptographic API usage"
    severity = "medium"
  strings:
    $crypto1 = "CryptEncrypt" nocase
    $crypto2 = "CryptDecrypt" nocase
    $crypto3 = "CreateCryptContext" nocase
    $crypto4 = "RsaEncrypt" nocase
    $crypto5 = "AesEncrypt" nocase
  condition:
    any of them
}

rule media_id3_suspicious
{
  meta:
    author = "CorpSec"
    description = "ID3 tag contains suspicious content"
  strings:
    $id3 = "ID3" ascii
    $url = "http" ascii
  condition:
    $id3 and $url
}

rule media_flac_metadata
{
  meta:
    author = "CorpSec"
    description = "FLAC metadata block contains suspicious content"
  strings:
    $flac = "fLaC" ascii
    $comment = "COMMENT" nocase
  condition:
    $flac and $comment
}

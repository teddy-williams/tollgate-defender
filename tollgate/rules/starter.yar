/*
  Tollgate starter rules: generic, original, hygiene-level detections for the file types Tollgate targets.
  They flag risky *structure*, not specific malware families, so expect some false positives.
  PDF and LNK files are also parsed structurally (pdf_analyzer / lnk_analyzer); these PDF/LNK rules are a backstop for
  files the parsers cannot read, so they are medium severity.
  Add family-specific rules in data/rules/ (or via `tollgate yara add`) when a new attack emerges.
  meta.severity: critical | high | medium | low   (critical = decisive Malicious verdict)
*/

rule PDF_JavaScript_AutoAction : pdf
{
    meta:
        description = "PDF contains JavaScript wired to run automatically"
        severity = "medium"
    strings:
        $hdr  = "%PDF-" ascii
        $js   = "/JavaScript" ascii
        $open = "/OpenAction" ascii
        $aa   = "/AA" ascii fullword
    condition:
        $hdr in (0..1023) and $js and ($open or $aa)
}

rule PDF_Launch_Action : pdf
{
    meta:
        description = "PDF /Launch action (can start a program)"
        severity = "medium"
    strings:
        $hdr    = "%PDF-" ascii
        $launch = "/Launch" ascii
    condition:
        $hdr in (0..1023) and $launch
}

rule PDF_Embedded_Executable_Name : pdf
{
    meta:
        description = "PDF embeds a file whose name is an executable or script"
        severity = "medium"
    strings:
        $hdr  = "%PDF-" ascii
        $emb  = "/EmbeddedFile" ascii
        $name = /\/F\s*\([^)]{1,100}\.(exe|scr|js|jse|vbs|bat|cmd|ps1|hta|jar|lnk)\)/ nocase
    condition:
        $hdr in (0..1023) and $emb and $name
}

rule LNK_Script_Host_Command : lnk
{
    meta:
        description = "Shortcut launches a script host or living-off-the-land binary with risky arguments"
        severity = "medium"
    strings:
        $h1 = "powershell" ascii wide nocase
        $h2 = "cmd.exe" ascii wide nocase
        $h3 = "mshta" ascii wide nocase
        $h4 = "wscript" ascii wide nocase
        $h5 = "cscript" ascii wide nocase
        $h6 = "rundll32" ascii wide nocase
        $h7 = "regsvr32" ascii wide nocase
        $h8 = "certutil" ascii wide nocase
        $a1 = "-enc" ascii wide nocase
        $a2 = "-w hidden" ascii wide nocase
        $a3 = "-windowstyle hidden" ascii wide nocase
        $a4 = "-nop" ascii wide nocase
        $a5 = "bypass" ascii wide nocase
        $a6 = "downloadstring" ascii wide nocase
        $a7 = "frombase64string" ascii wide nocase
        $a8 = "http://" ascii wide nocase
        $a9 = "https://" ascii wide nocase
        $a10 = "/c " ascii wide nocase
    condition:
        uint32(0) == 0x4C and uint32(4) == 0x00021401 and any of ($h*) and any of ($a*)
}

rule LNK_Oversized_Shortcut : lnk
{
    meta:
        description = "Shortcut is unusually large (appended payload?)"
        severity = "medium"
    condition:
        uint32(0) == 0x4C and uint32(4) == 0x00021401 and filesize > 100KB
}

rule Embedded_Windows_Executable : generic
{
    meta:
        description = "Windows executable embedded inside a file that is not itself an executable"
        severity = "high"
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        $dos and uint16(0) != 0x5A4D
}

rule Base64_Encoded_PE : generic
{
    meta:
        description = "Base64-encoded Windows executable (MZ header)"
        severity = "high"
    strings:
        $b1 = "TVqQAAMAAAAEAAAA" ascii
        $b2 = "TVpQAAIAAAAEAA8A" ascii
        $b3 = "TVoAAAAAAAAAAAAA" ascii
        $b4 = "TVqAAAEAAAAEAP//" ascii
    condition:
        any of them
}

rule Script_Download_And_Execute : script
{
    meta:
        description = "Script downloads content and executes it (PowerShell/WSH style cradle)"
        severity = "medium"
    strings:
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-WebRequest" ascii wide nocase
        $d4 = "Net.WebClient" ascii wide nocase
        $d5 = "Start-BitsTransfer" ascii wide nocase
        $e1 = "Invoke-Expression" ascii wide nocase
        $e2 = /\biex\b/ nocase
        $e3 = "FromBase64String" ascii wide nocase
        $e4 = "Start-Process" ascii wide nocase
    condition:
        filesize < 5MB and any of ($d*) and any of ($e*)
}

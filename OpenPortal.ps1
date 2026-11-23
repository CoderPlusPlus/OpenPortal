<#
.SYNOPSIS
    Provision the Meta Portal+ (aloha) to run the latest Google Services with the
    privileges it needs, using the root exploit.

.DESCRIPTION
    GOAL: get the latest Google Play Services supported on this hardware working
    by using the exploit to give it the signature|privileged permissions it needs
    (MANAGE_USERS above all). This is NOT about restoring the old stub / old-GMS /
    disabled-components workaround.

    Cumulative, idempotent, re-runnable: each run brings the Portal up to the
    highest implemented AND verified phase, so it is the single "get back to the
    last verified step" command. New phases are appended as they are proven.

    Implemented phases
      1  Root exploit provisioned + TCP 5555 wireless-adb recovery channel
         (persist.adb.tcp.port=5555). Verified end to end: property set, adbd
         listening on 5555, and a working shell over `adb connect`.
      2  Install the latest Google Play Services supported on this hardware,
         with the real GSF and Play Store it needs. No stub.
      3  Use the exploit to grant the Google apps the signature|privileged
         permissions they need (MANAGE_USERS etc.).
      4  Disable Meta's FacebookAppVerifier so the Play Store can install apps
         (INSTALL_FAILED_VERIFICATION_FAILURE otherwise), and confirm the grant
         holds for com.google.android.gms and com.android.vending.
      5  Install the genuine, unmodified Messenger (com.facebook.orca) with no
         rename/re-sign workaround. Uses the exploit to put presence's OWN cert
         first in its past-signature list, then Messenger's cert, so presence
         keeps its identity (other Facebook apps still trust it) while Android's
         duplicate-permission check accepts Messenger.

    Every phase is safe to run again: if the target state already holds, the
    phase is skipped and reported as already-satisfied.

.PARAMETER Phases
    Comma-separated list of phases to run. Default runs all of them
    (1,2,3,4,5). A phase that isn't listed is skipped: its heading is printed
    followed by a single "[Skipped]" line. Example: -Phases 1,2,5 runs 1, 2 and
    5, skipping 3 and 4.

.PARAMETER Serial
    adb serial of the Portal (USB). Auto-detected when omitted.

.PARAMETER ToolRoot
    Path to the portal-root-kiosk-satellite-main checkout (holds the provisioner).

.PARAMETER LogRoot
    Directory for per-run provisioner logs.

.PARAMETER Attempts
    Max exploit attempts passed to the provisioner (1..100). Default 12.

.PARAMETER Rebuild
    Check the payload-build requirements. The build is Linux only and this
    Windows launcher cannot run it, so -Rebuild stops with the requirements
    instead of building. Off by default, which uses the prebuilt payloads in the
    repo and is what you want for a quick restore. To rebuild, run the
    provisioner on a Linux host (WSL counts), then run OpenPortal without
    -Rebuild.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\OpenPortal.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\OpenPortal.ps1 -Serial 818PGA02P1200D15

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\OpenPortal.ps1 -Phases 1,2,5
#>
[CmdletBinding()]
param(
    [string]$Phases = "1,2,3,4,5",
    [string]$Serial = "",
    [string]$ToolRoot = "",
    [string]$LogRoot = "$env:LOCALAPPDATA\Temp\opencode\portal-provision",
    [int]$Attempts = 12,
    [switch]$Rebuild,

    # Phase 2 inputs (real Google stack; no stub). Empty = auto-find in -PlayDir,
    # then a bundled "stack" folder, then Downloads\play.
    [string]$PlayDir = "",
    [string]$GmsApk = "",
    [string]$GsfApk = "",
    [string]$GsfLoginApk = "",
    [string]$VendingBundle = "",

    # Phase 3: packages whose signing cert is injected as a PERMISSION-capable
    # past signature of the framework. All the Google apps share one cert, so
    # naming any one of them injects the same cert.
    [string]$GrantPackages = "com.google.android.gms",

    # Phase 5 inputs: the genuine com.facebook.orca APK (downloaded if absent),
    # and where to look for it. Java and apksig (both auto-fetched if missing)
    # are used to read APK signing certs.
    [string]$MessengerApk = "",
    [string]$MessengerDir = "$env:USERPROFILE\Downloads",
    [string]$SdkRoot = ""
)

$ErrorActionPreference = "Stop"

# Default the exploit checkout to the copy bundled next to this script.
if (-not $ToolRoot) { $ToolRoot = Join-Path $PSScriptRoot "portal-root-kiosk-satellite-main" }

$script:Serial = $Serial
$script:PortalIp = $null
$script:PythonExe = "python"

function Write-Phase([string]$m) { Write-Host "`n== $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)    { Write-Host "[ok]  $m" -ForegroundColor Green }
function Write-Notice([string]$m){ Write-Host "[..]  $m" -ForegroundColor Yellow }
function Write-Bad([string]$m)   { Write-Host "[!!]  $m" -ForegroundColor Red }

# A padded ASCII box for the final message.
function Write-DoneBox([string]$Text, [int]$Width = 64) {
    if ($Text.Length -gt $Width - 2) { $Width = $Text.Length + 2 }
    $border = "+" + ("-" * $Width) + "+"
    $blank  = "|" + (" " * $Width) + "|"
    $pad    = $Width - $Text.Length
    $left   = [math]::Floor($pad / 2)
    $right  = $pad - $left
    $mid    = "|" + (" " * $left) + $Text + (" " * $right) + "|"
    Write-Host ""
    Write-Host $border -ForegroundColor Green
    Write-Host $blank  -ForegroundColor Green
    Write-Host $mid    -ForegroundColor Green
    Write-Host $blank  -ForegroundColor Green
    Write-Host $border -ForegroundColor Green
    Write-Host ""
}

# Prompt for a single Y/N keypress. Returns $true for Y and $false for N; any
# other key prints $Invalid and asks again. Reads one keystroke (no Enter), or a
# line when input is redirected (so a scripted/piped run can't hang).
function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string]$Invalid
    )
    while ($true) {
        Write-Host $Prompt -ForegroundColor Cyan
        $key = ""
        if ([Console]::IsInputRedirected) {
            $line = [Console]::In.ReadLine()
            if ($null -eq $line) { return $false }   # no more input: decline, don't hang
            $key = $line.Trim().ToUpperInvariant()
        } else {
            try {
                $key = [Console]::ReadKey($true).Key.ToString().ToUpperInvariant()
                Write-Host $key
            } catch {
                # No console (e.g. ISE or remoting): read a line instead.
                $line = Read-Host
                if (-not $line) { return $false }
                $key = $line.Trim().ToUpperInvariant()
            }
        }
        if ($key -eq "Y") { return $true }
        if ($key -eq "N") { return $false }
        Write-Host $Invalid -ForegroundColor Red
        Write-Host ""
    }
}

# Show the risk warning and require an explicit Y. Returns $true to continue.
function Confirm-RiskWarning {
    Write-Host ""
    Write-Host "USE AT YOUR OWN RISK.  I AM NOT RESPONSIBLE IF THE SCRIPT RESULTS IN A BRICKED DEVICE!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "I've tested the script myself, but like any script that uses exploits, there's always a"
    Write-Host "small risk of a boot loop or other unrecoverable error happening.  You agree by using the"
    Write-Host "script that you have read and understand this warning."
    Write-Host ""
    return Read-YesNo `
        -Prompt "Press [Y] to acknowledge and continue or [N] to exit." `
        -Invalid "Invalid key, please choose [Y] to acknowledge the warning and continue or [N] to exit."
}

# ---------------------------------------------------------------------------
# Dependency bootstrap. For each tool we first look for one that is already
# present (on PATH, in JAVA_HOME, or in an installed Android SDK); we only
# download into <script>\deps\ when nothing usable exists.
# ---------------------------------------------------------------------------
$script:DepsDir = Join-Path $PSScriptRoot "deps"

function Download-File {
    param([string]$Url, [string]$OutFile)
    New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null
    Write-Notice "downloading $(Split-Path $OutFile -Leaf) ..."
    $tmp = "$OutFile.download"
    $prev = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing } finally { $ProgressPreference = $prev }
    Move-Item -LiteralPath $tmp -Destination $OutFile -Force
}

function Download-Base64File {
    param([string]$Url, [string]$OutFile, [string]$DisplayName = "")
    New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null
    $label = if ($DisplayName) { $DisplayName } else { Split-Path $OutFile -Leaf }
    Write-Notice "downloading $label ..."
    $prev = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try { $response = Invoke-WebRequest -Uri $Url -UseBasicParsing } finally { $ProgressPreference = $prev }
    $encoded = if ($response.Content -is [byte[]]) {
        [Text.Encoding]::ASCII.GetString($response.Content)
    } else {
        [string]$response.Content
    }
    try { $bytes = [Convert]::FromBase64String($encoded) } catch { throw "Could not decode the download from $Url." }
    $tmp = "$OutFile.download"
    [IO.File]::WriteAllBytes($tmp, $bytes)
    Move-Item -LiteralPath $tmp -Destination $OutFile -Force
}

# --- find-what-already-exists helpers (return a path, or $null) ---

function Get-AdbPath {
    $cmd = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $local = Join-Path $script:DepsDir "platform-tools\adb.exe"
    if (Test-Path -LiteralPath $local) { return $local }
    foreach ($root in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, (Join-Path $env:LOCALAPPDATA "Android\Sdk"))) {
        if ($root) {
            $p = Join-Path $root "platform-tools\adb.exe"
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    return $null
}

function Get-JavaPath {
    $cands = @()
    if ($env:JAVA_HOME) { $cands += (Join-Path $env:JAVA_HOME "bin\java.exe") }
    $cands += @(Get-Command java.exe -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    $cands += @(Get-ChildItem "C:\Program Files\*\bin\java.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $cands += @(Get-ChildItem "C:\Program Files (x86)\*\bin\java.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $cands += (Join-Path $script:DepsDir "jre\bin\java.exe")
    return ($cands | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1)
}

function Get-ApksigJar {
    $local = Join-Path $script:DepsDir "apksig.jar"
    if (Test-Path -LiteralPath $local) { return $local }
    # An installed Android SDK's apksigner.jar works just as well.
    $roots = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, (Join-Path $env:LOCALAPPDATA "Android\Sdk"), $SdkRoot) |
        Where-Object { $_ }
    foreach ($root in $roots) {
        $bt = Join-Path $root "build-tools"
        if (-not (Test-Path -LiteralPath $bt)) { continue }
        $hit = Get-ChildItem $bt -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]($_.Name -replace '[^0-9.].*$', '') } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName "lib\apksigner.jar" } |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}

# --- ensure-available: use what exists, download only what is missing ---

function Ensure-Adb {
    $adb = Get-AdbPath
    if ($adb) {
        Write-Host "adb:    $adb"
        $env:PATH = "$(Split-Path $adb -Parent);$env:PATH"
        return
    }
    Write-Notice "adb not found; fetching Android platform-tools ..."
    $zip = Join-Path $script:DepsDir "platform-tools.zip"
    Download-File "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" $zip
    Expand-Archive -LiteralPath $zip -DestinationPath $script:DepsDir -Force
    Remove-Item -LiteralPath $zip -Force
    $dir = Join-Path $script:DepsDir "platform-tools"
    if (-not (Test-Path -LiteralPath (Join-Path $dir "adb.exe"))) { throw "Could not obtain adb (platform-tools download failed)." }
    Write-Host "adb:    $(Join-Path $dir 'adb.exe')  (downloaded)"
    $env:PATH = "$dir;$env:PATH"
}

function Ensure-Java {
    $java = Get-JavaPath
    if ($java) {
        Write-Host "Java:   $java"
        $env:PATH = "$(Split-Path $java -Parent);$env:PATH"
        return
    }
    Write-Notice "Java not found; fetching a JRE ..."
    $zip = Join-Path $script:DepsDir "jre.zip"
    Download-File "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse" $zip
    $tmp = Join-Path $script:DepsDir "jre-extract"
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
    Remove-Item -LiteralPath $zip -Force
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    $dir = Join-Path $script:DepsDir "jre"
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    if ($inner) { Move-Item -LiteralPath $inner.FullName -Destination $dir -Force }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath (Join-Path $dir "bin\java.exe"))) { throw "Could not obtain Java (JRE download failed)." }
    Write-Host "Java:   $(Join-Path $dir 'bin\java.exe')  (downloaded)"
    $env:PATH = "$dir\bin;$env:PATH"
}

function Ensure-Apksig {
    $jar = Get-ApksigJar
    if ($jar) { Write-Host "apksig: $jar"; return $jar }
    Write-Notice "apksig not found; fetching it ..."
    $jar = Join-Path $script:DepsDir "apksig.jar"
    Download-File "https://dl.google.com/dl/android/maven2/com/android/tools/build/apksig/8.7.3/apksig-8.7.3.jar" $jar
    Write-Host "apksig: $jar  (downloaded)"
    return $jar
}

# A Python runtime (the provisioner is a Python program; Windows has no built-in).
function Get-PythonPath {
    $cands = @()
    $cands += @(Get-Command python.exe -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    $cands += @(Get-Command python3.exe -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    $cands += (Join-Path $script:DepsDir "python\python.exe")
    foreach ($c in $cands) {
        if (-not $c) { continue }
        if ($c -match '\\WindowsApps\\') { continue }   # Microsoft Store alias stub (0-byte)
        if (-not (Test-Path -LiteralPath $c)) { continue }
        try { if ((Get-Item -LiteralPath $c).Length -le 0) { continue } } catch { continue }
        return $c
    }
    return $null
}

function Ensure-Python {
    $dir = Join-Path $script:DepsDir "python"
    $py = Get-PythonPath
    if (-not $py) {
        Write-Notice "Python not found; fetching a portable Python ..."
        $zip = Join-Path $script:DepsDir "python.zip"
        Download-File "https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip" $zip
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
        Remove-Item -LiteralPath $zip -Force
        $py = Join-Path $dir "python.exe"
        if (-not (Test-Path -LiteralPath $py)) { throw "Could not obtain Python." }
        Write-Host "Python: $py  (downloaded)"
    } else {
        Write-Host "Python: $py"
    }
    # The embeddable build pins sys.path via a python*._pth file, so the
    # provisioner's sibling imports (meta_debloat_components, portal_targets)
    # would not resolve. Add its folder to the ._pth (system Pythons don't
    # have this file, so this is a no-op for them).
    if ((Split-Path $py -Parent) -eq $dir) {
        $pth = Get-ChildItem $dir -Filter "python*._pth" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pth) {
            $toolsDir = Join-Path $ToolRoot "tools"
            $content = [IO.File]::ReadAllText($pth.FullName)
            if ($content -notmatch [regex]::Escape($toolsDir)) {
                [IO.File]::AppendAllText($pth.FullName, "`r`n$toolsDir`r`n")
            }
        }
    }
    return $py
}

# The published simpleperf binary: exact size, SHA-256 and ELF magic. A partial
# file left by an interrupted download fails this, so it is fetched again.
function Test-SimpleperfBinary {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if ((Get-Item -LiteralPath $Path).Length -ne 4106416) { return $false }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($hash -ne "7EB29ECBA8AE792397BD8C1B0FCD874FED0DC4C44D0CF9CB284E948F80CFE7E5") { return $false }
    $magic = New-Object byte[] 4
    $stream = [IO.File]::OpenRead($Path)
    try { $magicRead = $stream.Read($magic, 0, 4) } finally { $stream.Close() }
    return $magicRead -eq 4 -and $magic[0] -eq 0x7F -and $magic[1] -eq 0x45 -and $magic[2] -eq 0x4C -and $magic[3] -eq 0x46
}

function Ensure-Simpleperf {
    # The exploit needs simpleperf (arm64 Android binary) for KASLR discovery.
    # The bundled copy is always the one used, even when a real NDK is installed:
    # deps\ndk holds only this binary, so it must never become the NDK a build
    # uses. The provisioner takes the path from PORTAL_SIMPLEPERF and still finds
    # a real NDK for builds through ANDROID_NDK_HOME, ANDROID_NDK_ROOT, NDK or
    # the SDK.
    $bundledNdk = Join-Path $script:DepsDir "ndk"
    $expected = Join-Path $bundledNdk "simpleperf\bin\android\arm64\simpleperf"
    if (Test-SimpleperfBinary $expected) {
        Write-Host "simpleperf: $expected"
    } else {
        if (Test-Path -LiteralPath $expected) {
            Write-Notice "simpleperf is damaged; fetching a fresh copy ..."
        } else {
            Write-Notice "simpleperf not found; fetching from AOSP prebuilts ..."
        }
        $dir = Join-Path $bundledNdk "simpleperf\bin\android\arm64"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $tmpFile = Join-Path $script:DepsDir "simpleperf.download"
        Download-Base64File "https://android.googlesource.com/platform/prebuilts/simpleperf/+/refs/tags/ndk-r28c/bin/android/arm64/simpleperf?format=TEXT" $tmpFile -DisplayName "simpleperf"
        if (-not (Test-SimpleperfBinary $tmpFile)) {
            $actualSha256 = (Get-FileHash -LiteralPath $tmpFile -Algorithm SHA256).Hash
            $size = (Get-Item -LiteralPath $tmpFile).Length
            Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            throw "simpleperf download failed verification (sha256=$actualSha256 size=$size)."
        }
        Move-Item -LiteralPath $tmpFile -Destination $expected -Force
        Write-Host "simpleperf: $expected  (downloaded)"
    }
    $env:PORTAL_SIMPLEPERF = $expected
}

function Get-AndroidSdkRoot {
    # Same order the provisioner resolves: an explicit -SdkRoot, then the
    # environment, then the user's home folders, then the Windows default. The
    # child names use forward slashes so the home folders also resolve on Linux.
    $roots = @($SdkRoot, $env:ANDROID_SDK_ROOT, $env:ANDROID_HOME)
    $homeDir = if ($env:USERPROFILE) { $env:USERPROFILE } elseif ($env:HOME) { $env:HOME } else { $null }
    if ($homeDir) {
        $roots += @(
            (Join-Path $homeDir "Android/Sdk"),
            (Join-Path $homeDir "Android/sdk"),
            (Join-Path $homeDir "android-sdk")
        )
    }
    if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA "Android/Sdk") }
    foreach ($root in $roots) {
        if ($root -and (Test-Path -LiteralPath $root)) { return $root }
    }
    return $null
}

function Test-AnyFile {
    param([string]$Directory, [string[]]$Names)
    foreach ($name in $Names) {
        $path = Join-Path $Directory $name
        if (Test-Path -LiteralPath $path) { return $path }
    }
    return $null
}

function Format-CheckLine {
    param([bool]$Found, [string]$Label, [string]$Path)
    $mark = if ($Found) { "[x]" } else { "[ ]" }
    if ($Found -and $Path) { return ("  {0} {1}    {2}" -f $mark, $Label, $Path) }
    return ("  {0} {1}" -f $mark, $Label)
}

function Assert-RebuildToolchain {
    $sdk = Get-AndroidSdkRoot

    $makeCmd = Get-Command make -CommandType Application -ErrorAction SilentlyContinue
    $makePath = if ($makeCmd) { $makeCmd.Source } else { $null }

    $javac = Get-Command javac -CommandType Application -ErrorAction SilentlyContinue
    $jarTool = Get-Command jar -CommandType Application -ErrorAction SilentlyContinue
    $keytool = Get-Command keytool -CommandType Application -ErrorAction SilentlyContinue
    $jdkFound = [bool]($javac -and $jarTool -and $keytool)
    $jdkPath = if ($jdkFound) { Split-Path $javac.Source -Parent } else { $null }

    # Each tool is accepted in the Unix form the Linux build uses or the Windows
    # form an installed SDK ships, so this list reports what the machine has.
    # Whether it can build here is the separate Linux host line below.
    $toolNames = @{
        aapt      = @("aapt", "aapt.exe")
        apksigner = @("apksigner", "apksigner.bat", "apksigner.exe")
        zipalign  = @("zipalign", "zipalign.exe")
        d8        = @("d8", "d8.bat", "d8.exe")
    }

    $ndkPath = $null
    $ndkCandidates = @()
    foreach ($name in @("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK")) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $ndkCandidates += $value }
    }
    # Only the version the provisioner defaults to counts, so a different NDK
    # sitting in the SDK is not reported as the one a build would use.
    if ($sdk) { $ndkCandidates += (Join-Path $sdk "ndk/28.2.13676358") }
    $bundledNdk = Join-Path $script:DepsDir "ndk"
    foreach ($candidate in $ndkCandidates) {
        if (-not $candidate -or -not (Test-Path -LiteralPath $candidate)) { continue }
        if ($candidate -ieq $bundledNdk) { continue }
        if (Test-Path -LiteralPath (Join-Path $candidate "toolchains/llvm/prebuilt")) {
            $ndkPath = $candidate
            break
        }
    }

    $androidJarPath = $null
    if ($env:ANDROID_JAR -and (Test-Path -LiteralPath $env:ANDROID_JAR)) {
        $androidJarPath = $env:ANDROID_JAR
    } elseif ($sdk) {
        $candidate = Join-Path $sdk "platforms/android-36/android.jar"
        if (Test-Path -LiteralPath $candidate) { $androidJarPath = $candidate }
    }

    $buildToolsDir = $null
    if ($env:BUILD_TOOLS -and (Test-Path -LiteralPath $env:BUILD_TOOLS)) {
        $buildToolsDir = $env:BUILD_TOOLS
    } elseif ($sdk) {
        $candidate = Join-Path $sdk "build-tools/37.0.0"
        if (Test-Path -LiteralPath $candidate) { $buildToolsDir = $candidate }
    }
    $buildToolsPath = $null
    if ($buildToolsDir) {
        $d8Path = $null
        $d8Usable = $true
        if ($env:D8) {
            # The override has to be a d8 of an accepted shape, the same rule the
            # folder search below uses.
            $override = Get-Item -LiteralPath $env:D8 -ErrorAction SilentlyContinue
            if ($override -and ($toolNames["d8"] -contains $override.Name)) {
                $d8Path = $override.FullName
            } else {
                $d8Usable = $false
            }
        }
        if (-not $d8Path -and $d8Usable) {
            $d8Path = Test-AnyFile $buildToolsDir $toolNames["d8"]
        }
        if ($d8Path) {
            $toolsFound = $true
            foreach ($tool in @("aapt", "apksigner", "zipalign")) {
                if (-not (Test-AnyFile $buildToolsDir $toolNames[$tool])) {
                    $toolsFound = $false
                    break
                }
            }
            if ($toolsFound) { $buildToolsPath = $buildToolsDir }
        }
    }

    # The payload build is Linux only, so a Windows host can show every tool as
    # present and still not be able to build. That is reported as its own
    # requirement, and the path uses forward slashes so it resolves on Linux too.
    $linuxCompiler = $null
    if ($ndkPath) {
        $candidate = Join-Path $ndkPath "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang"
        if (Test-Path -LiteralPath $candidate) { $linuxCompiler = $candidate }
    }
    $isLinuxHost = $false
    if (Get-Variable -Name IsLinux -Scope Global -ErrorAction SilentlyContinue) {
        $isLinuxHost = [bool]$IsLinux
    }
    $linuxHostReady = $isLinuxHost -and [bool]$linuxCompiler

    $lines = @(
        "-Rebuild compiles the exploit payloads from source, but the build is",
        "Linux only. OpenPortal normally uses the prebuilt payloads in the repo, so",
        "this is only needed if you changed the exploit or helper source.",
        "",
        "OpenPortal provides these automatically:",
        "  [x] adb",
        "  [x] Python",
        "  [x] Java runtime (JRE)",
        "  [x] apksig",
        "  [x] simpleperf",
        "",
        "-Rebuild needs these on the build host (NDK 28.2.13676358):",
        (Format-CheckLine ([bool]$makePath) "GNU Make" $makePath),
        (Format-CheckLine $jdkFound "JDK (javac, jar, keytool)" $jdkPath),
        (Format-CheckLine ([bool]$ndkPath) "Android NDK" $ndkPath),
        (Format-CheckLine ([bool]$androidJarPath) "Android SDK Platform 36 (android.jar)" $androidJarPath),
        (Format-CheckLine ([bool]$buildToolsPath) "Android SDK Build Tools 37.0.0 (aapt, zipalign, apksigner, d8)" $buildToolsPath),
        "",
        "-Rebuild also needs a Linux build host:",
        (Format-CheckLine $linuxHostReady "Linux with the NDK's linux-x86_64 toolchain" $linuxCompiler),
        "",
        "The native payloads are built with the NDK's linux-x86_64 toolchain. This",
        "Windows launcher only has Windows tools, so -Rebuild cannot run the build",
        "here. Build on a Linux host (WSL counts) by running the provisioner there,",
        "then run OpenPortal without -Rebuild to use the prebuilt payloads."
    )
    throw ($lines -join [Environment]::NewLine)
}

# adb is always needed. The other tools are fetched only when a selected phase
# uses them, so a Google-stack or Play-Store run does not depend on downloads it
# never touches.
function Bootstrap-Deps {
    param([string[]]$Needs = @("java", "python", "apksig", "simpleperf"))
    Write-Phase "Checking tools"
    Ensure-Adb
    if ($Needs -contains "java") { Ensure-Java }
    if ($Needs -contains "python") { $script:PythonExe = Ensure-Python }
    if ($Needs -contains "apksig") { $null = Ensure-Apksig }
    if ($Needs -contains "simpleperf") { Ensure-Simpleperf }
    Write-Ok "tools ready"
}

function Get-DeviceArgs {
    if ($script:Serial) { return @("-s", $script:Serial) }
    return @()
}

# Run adb with the selected device. Throws on non-zero exit. Native stderr (e.g.
# adb pull's progress line) is tolerated: with $ErrorActionPreference=Stop it
# would otherwise surface as a terminating NativeCommandError even on success.
function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$AdbArgs)
    $all = @()
    $all += Get-DeviceArgs
    $all += $AdbArgs
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = @(& adb @all 2>&1 | ForEach-Object { "$_" })
    } finally {
        $ErrorActionPreference = $prev
    }
    $code = $LASTEXITCODE
    $text = ($out -join [Environment]::NewLine)
    if ($code -ne 0) {
        throw "adb $($AdbArgs -join ' ') failed ($code): $text"
    }
    return $text.Trim()
}

# Run adb, returning output + exit code without throwing.
function Invoke-AdbQuiet {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$AdbArgs)
    $all = @()
    $all += Get-DeviceArgs
    $all += $AdbArgs
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = @(& adb @all 2>&1 | ForEach-Object { "$_" })
    } finally {
        $ErrorActionPreference = $prev
    }
    return [pscustomobject]@{ Output = (($out -join [Environment]::NewLine).Trim()); Code = $LASTEXITCODE }
}

# Pick the USB serial if -Serial was not given.
function Resolve-Serial {
    if ($script:Serial) {
        $state = (Invoke-AdbQuiet get-state).Output
        if ($state -ne "device") {
            throw "Serial '$($script:Serial)' is not ready (state: '$state'). Enable USB debugging and replug."
        }
        return
    }
    $devices = @()
    foreach ($line in ((Invoke-AdbQuiet devices).Output -split "`r?`n")) {
        if ($line -match "^(\S+)\s+device\b") { $devices += $Matches[1] }
    }
    $usb = $devices | Where-Object { $_ -notmatch ":" } | Select-Object -First 1
    if (-not $usb) { $usb = $devices | Select-Object -First 1 }
    if (-not $usb) {
        throw "No adb device. Enable Developer options + USB debugging, replug, and accept the prompt on the Portal."
    }
    $script:Serial = $usb
}

function Get-PortalIp {
    if ($script:PortalIp) { return $script:PortalIp }
    $out = (Invoke-AdbQuiet shell "ip -4 addr show wlan0").Output
    if ($out -match "inet (\d+\.\d+\.\d+\.\d+)") {
        $script:PortalIp = $Matches[1]
        return $script:PortalIp
    }
    return $null
}

# True when persist.adb.tcp.port=5555 AND a shell works over adb connect.
function Test-RecoveryChannel {
    $prop = (Invoke-AdbQuiet shell getprop persist.adb.tcp.port).Output
    if ($prop -ne "5555") { return $false }
    $ip = Get-PortalIp
    if (-not $ip) { return $false }
    # adb writes to stderr when the TCP device is offline; under
    # $ErrorActionPreference=Stop that would throw and defeat the retry loop.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & adb connect "${ip}:5555" 2>&1 | Out-Null
        $id = (& adb -s "${ip}:5555" shell id 2>&1 | Out-String)
    } finally { $ErrorActionPreference = $prev }
    return ($id -match "uid=2000")
}

# Like Test-RecoveryChannel but tolerant of the channel still coming up: after a
# reboot (or a factory reset) wlan0/adbd-5555 can take a little while, so retry.
function Wait-RecoveryChannel {
    param([int]$TimeoutSeconds = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        if (Test-RecoveryChannel) { return $true }
        if ((Get-Date) -ge $deadline) { return $false }
        $script:PortalIp = $null   # re-read the IP each time (it may appear late)
        Start-Sleep -Seconds 5
    }
}

# True if the file begins with the ZIP/APK magic "PK" (browsers sometimes save
# APKs without an extension, and download pages save HTML instead).
function Test-IsZip([string]$Path) {
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $b = New-Object byte[] 2
            if ($fs.Read($b, 0, 2) -lt 2) { return $false }
        } finally { $fs.Close() }
        return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B)
    } catch { return $false }
}

# Newest file matching a wildcard in a directory (by LastWriteTime), or $null.
# A .apk filter also matches an APK saved without an extension (browsers drop it);
# other filters require their exact extension. Only real zip/APK files count.
function Get-NewestFile {
    param([string]$Directory, [string]$Filter)
    if (-not $Directory -or -not (Test-Path -LiteralPath $Directory)) { return $null }
    $isApkFilter = $Filter -match '\.apk$'
    $base = $Filter -replace '\.(apk|apkm|xapk)$', ''
    $hit = Get-ChildItem -LiteralPath $Directory -File -ErrorAction SilentlyContinue |
        Where-Object {
            $n = $_.Name
            $match = $n -like $Filter
            if (-not $match -and $isApkFilter) {
                $match = ($n -like $base) -and ($n -notmatch '\.(apk|apkm|xapk)$')
            }
            $match -and (Test-IsZip $_.FullName)
        } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $null
}

# Highest-version com.google.android.gms_<x.y.z>* in a directory (not mtime).
function Get-NewestGms {
    param([string]$Directory)
    if (-not $Directory -or -not (Test-Path -LiteralPath $Directory)) { return $null }
    $best = $null; $bestVer = $null
    foreach ($f in (Get-ChildItem -LiteralPath $Directory -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -match '\.(xapk|apkm)$') { continue }   # a bundle container, not the APK
        if ($f.Name -match "com\.google\.android\.gms_(\d+\.\d+\.\d+)") {
            if (-not (Test-IsZip $f.FullName)) { continue }
            $v = [version]$Matches[1]
            if (-not $bestVer -or $v -gt $bestVer) { $bestVer = $v; $best = $f.FullName }
        }
    }
    return $best
}

function Test-PackageInstalled {
    param([string]$Package)
    $out = (Invoke-AdbQuiet shell pm list packages $Package).Output
    # Match the whole line: "pm list packages <x>" filters by substring, so
    # com.google.android.gsf would otherwise also match com.google.android.gsf.login.
    foreach ($line in ($out -split "`r?`n")) {
        if ($line.Trim() -eq "package:$Package") { return $true }
    }
    return $false
}

# Install a single APK (upgrade in place), then confirm the package exists.
function Install-Apk {
    param([string]$Path, [string]$Package)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing APK for ${Package}: $Path" }
    Write-Host "install $Package  <- $(Split-Path $Path -Leaf)"
    Invoke-Adb install -r $Path | Write-Host
    if (-not (Test-PackageInstalled $Package)) {
        throw "Install reported success but $Package is not present"
    }
}

# Meta's FacebookAppVerifier rejects every app not signed by Facebook. Disable it
# so installs go through: the framework verifier setting, adb-install
# verification, and Meta's own verifier package (com.facebook.appverifier), which
# gates app-initiated Play Store installs. Harmless to re-run.
function Disable-AppVerifier {
    $cur = (Invoke-AdbQuiet shell settings get global package_verifier_enable).Output
    if ($cur -ne "0") {
        Write-Host "disabling package verifier (was $cur)"
        Invoke-Adb shell settings put global package_verifier_enable 0 | Out-Null
    }
    $adbcur = (Invoke-AdbQuiet shell settings get global verifier_verify_adb_installs).Output
    if ($adbcur -ne "0") {
        Write-Host "disabling adb-install verification (was $adbcur)"
        Invoke-Adb shell settings put global verifier_verify_adb_installs 0 | Out-Null
    }
    $disabled = (Invoke-AdbQuiet shell "pm list packages -d -u | grep com.facebook.appverifier").Output
    if ($disabled -notmatch 'com\.facebook\.appverifier') {
        Write-Host "disabling Meta's app verifier (com.facebook.appverifier)"
        Invoke-Adb shell pm disable-user --user 0 com.facebook.appverifier | Out-Null
    }
}

# What to do when the Portal is not reachable over ADB. The Portal does not keep
# ADB on across reboots (Meta's ADB switch turns itself off at boot), so this is
# common while the exploit is rebooting the device.
function Write-AdbRecoveryHint {
    Write-Host ""
    Write-Notice "The Portal is not reachable over ADB. The Portal does not keep ADB enabled"
    Write-Notice "across reboots, so after each reboot you may need to:"
    Write-Notice "  1. On the Portal: Settings -> Debug -> ADB Enabled (turn it back on)."
    Write-Notice "  2. Tap Allow if an 'Allow USB debugging?' prompt appears."
    Write-Notice "  3. If it still will not reconnect, run:  adb -d tcpip 5555"
    Write-Notice "Then re-run OpenPortal; it resumes where it left off."
}

# Wait until the Portal is connected AND finished booting (sys.boot_completed=1).
# Returns $true when ready, $false on timeout. A device whose adbd is up but is
# still booting would otherwise pass Resolve-Serial, then fail inside the exploit.
function Wait-PortalReady {
    param([int]$TimeoutSeconds = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $toldUnauthorized = $false
    while ($true) {
        $state = (Invoke-AdbQuiet get-state).Output
        if ($state -eq "device") {
            if ((Invoke-AdbQuiet shell getprop sys.boot_completed).Output -eq "1") { return $true }
        } elseif ($state -eq "unauthorized" -and -not $toldUnauthorized) {
            Write-Notice "On the Portal's screen, tap 'Allow' on the 'Allow USB debugging?' prompt."
            $toldUnauthorized = $true
        }
        if ((Get-Date) -ge $deadline) { return $false }
        Start-Sleep -Seconds 3
    }
}

# Run the provisioner, streaming its output and saving it to
# <LogDir>\provisioner.log (so the log folder is never empty). Returns its exit code.
function Invoke-Provisioner {
    param([string[]]$PyArgs, [string]$LogDir)
    $logFile = Join-Path $LogDir "provisioner.log"
    # Write UTF-8 throughout (Tee-Object would mix encodings with a pre-written header).
    $writer = New-Object System.IO.StreamWriter($logFile, $false, (New-Object System.Text.UTF8Encoding($false)))
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # native stderr must not become a terminating error
    try {
        $writer.WriteLine("# OpenPortal provisioner run $(Get-Date -Format o)")
        & $script:PythonExe @PyArgs 2>&1 | ForEach-Object {
            $line = "$_"
            # Keep the provisioner's stderr (its banner and PROVISION_ERROR) red, as before.
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Write-Host $line -ForegroundColor Red
            } else {
                Write-Host $line
            }
            $writer.WriteLine($line)
        }
    } finally {
        $writer.Dispose()
        $ErrorActionPreference = $prev
    }
    return $LASTEXITCODE
}

# The prebuilt files a --skip-build run needs. The provisioner builds them only
# when it is NOT passed --skip-build, so a downloaded bundle has to contain them
# all: the exploit and its sentinel, plus the UID-1000 helper, boot hook and
# runtime APK that the wireless-ADB and permission-grant steps install. A bundle
# that ships only the first two leaves those steps failing mid-run.
function Assert-BuildOutputs {
    $required = @(
        (Join-Path $ToolRoot "exploit\build\preload-portal-aloha-1041515800015050.so"),
        (Join-Path $ToolRoot "exploit-sentinel\build\portal-exploit-sentinel.apk"),
        (Join-Path $ToolRoot "uid1000-helper\build\portal-camera-led-watch-aloha"),
        (Join-Path $ToolRoot "uid1000-helper\build\portal-uid1000-hook-aloha.bin"),
        (Join-Path $ToolRoot "uid1000-helper\build\portal-uid1000-runtime.apk")
    )
    $missing = @($required | Where-Object { -not (Test-Path -LiteralPath $_) })
    if ($missing.Count -gt 0) {
        $list = ($missing | ForEach-Object { "    $_" }) -join [Environment]::NewLine
        throw ("Missing prebuilt file(s) needed by this run:`n$list`n" +
               "Run with -Rebuild so the provisioner builds them, or restore them from the release bundle.")
    }
}

# The log folder for the phase that is running. Every phase gets a fresh one, and
# any failure -- even one that happens before the provisioner starts -- is written
# into it, so a failed run always leaves something to read.
$script:LogDir = $null

function New-LogDir {
    $dir = Join-Path $LogRoot (Get-Date -Format "yyyyMMdd-HHmmss")
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $script:LogDir = $dir
    Write-Host "Logs:          $dir"
    return $dir
}

# Append an error to the current log folder (it is already on the console). Falls
# back to a fresh folder if the failure happened before a phase made one.
function Write-RunError {
    param([string]$Message)
    try {
        if (-not $script:LogDir) { $null = New-LogDir }
        $line = "{0}  ERROR  {1}" -f (Get-Date -Format o), $Message
        Add-Content -LiteralPath (Join-Path $script:LogDir 'error.log') -Value $line
        Write-Host "See $($script:LogDir)\error.log" -ForegroundColor DarkGray
    } catch { }
}

# ---------------------------------------------------------------------------
# Phase 1 - root exploit + TCP 5555 recovery channel
# ---------------------------------------------------------------------------
function Invoke-Phase1 {
    Write-Phase "Phase 1 - root exploit + TCP 5555 recovery channel"

    $provisioner = Join-Path $ToolRoot "tools\provision_portal.py"
    if (-not (Test-Path $provisioner)) { throw "Provisioner not found: $provisioner" }

    Resolve-Serial
    Write-Host "Device serial: $($script:Serial)"

    # Pre-flight: the exploit's first act is to connect to the Portal. Make sure
    # it is connected AND finished booting, with a clear message if it is not.
    if (-not (Wait-PortalReady -TimeoutSeconds 120)) {
        Write-AdbRecoveryHint
        throw "The Portal is not ready (ADB not connected, or still booting)."
    }
    Write-Host "Model:         $(Invoke-Adb shell getprop ro.product.model)"
    Write-Host "Fingerprint:   $(Invoke-Adb shell getprop ro.build.fingerprint)"

    if (Wait-RecoveryChannel -TimeoutSeconds 15) {
        Write-Ok "Already at step 1 (persist.adb.tcp.port=5555 and a TCP shell works). Skipping."
        return
    }

    # The provisioner builds these itself unless it is passed --skip-build, so
    # only require them up front for a --skip-build run.
    if (-not $Rebuild) { Assert-BuildOutputs }

    $logDir = $script:LogDir
    Write-Notice "This runs the kernel exploit and reboots the Portal a few times. Keep USB connected."

    $pyArgs = @($provisioner, "--serial", $script:Serial, "--persistent-wireless-adb",
                "--attempts", $Attempts, "--log-dir", $logDir)
    if (-not $Rebuild) { $pyArgs += "--skip-build" }

    $code = Invoke-Provisioner -PyArgs $pyArgs -LogDir $logDir
    if ($code -ne 0) {
        Write-AdbRecoveryHint
        throw "Provisioner exited with code $code (see $logDir\provisioner.log)"
    }

    # Re-read state after the provisioner's reboots. Give the channel time to
    # come back (wlan0 IP + adbd's TCP listener) rather than failing instantly.
    $script:PortalIp = $null
    if (-not (Wait-PortalReady -TimeoutSeconds 180)) {
        Write-AdbRecoveryHint
        throw "Phase 1 did not verify: the Portal did not come back after the exploit."
    }
    if (-not (Wait-RecoveryChannel -TimeoutSeconds 180)) {
        Write-AdbRecoveryHint
        throw ("Phase 1 did not verify: persist.adb.tcp.port=5555 / TCP shell not working. " +
               "Make sure the Portal is connected to Wi-Fi (the TCP channel needs a wlan0 IP).")
    }
    Write-Ok "Phase 1 verified: TCP 5555 recovery channel is live."
}

# ---------------------------------------------------------------------------
# Phase 2 - install the real Google stack (no stub)
# ---------------------------------------------------------------------------
function Invoke-Phase2 {
    Write-Phase "Phase 2 - install the real Google stack (no stub)"
    Resolve-Serial
    if (-not (Wait-PortalReady -TimeoutSeconds 120)) {
        Write-AdbRecoveryHint
        throw "The Portal is not ready (ADB not connected, or still booting)."
    }

    # The Google stack is not signed by Facebook, so Meta's verifier would reject
    # these adb installs on a fresh device. Disable it before installing.
    Disable-AppVerifier

    # Where the stack APKs live: -PlayDir, then a bundled "stack" folder next to
    # this script, then Downloads\play. Prefer a folder that actually holds the
    # stack, so an empty "stack" folder can't shadow Downloads\play. A folder is
    # only needed for the files not given explicitly.
    $candidates = @()
    if ($PlayDir) { $candidates += $PlayDir }
    $candidates += (Join-Path $PSScriptRoot "stack")
    $candidates += "$env:USERPROFILE\Downloads\play"
    $stackDir = $candidates | Where-Object { (Get-NewestGms $_) } | Select-Object -First 1
    if (-not $stackDir) {
        $stackDir = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
    if ($stackDir) { Write-Host "stack:  $stackDir" }

    $gms      = if ($GmsApk)        { $GmsApk }        else { Get-NewestGms $stackDir }
    $gsf      = if ($GsfApk)        { $GsfApk }        else { Get-NewestFile $stackDir "com.google.android.gsf_*.apk" }
    $gsfLogin = if ($GsfLoginApk)   { $GsfLoginApk }   else { Get-NewestFile $stackDir "com.google.android.gsf.login_*.apk" }
    $vending  = if ($VendingBundle) { $VendingBundle } else { Get-NewestFile $stackDir "com.android.vending_*.apkm" }

    foreach ($pair in @(
        @{n="GMS";        p=$gms},
        @{n="GSF";        p=$gsf},
        @{n="GSF login";  p=$gsfLogin},
        @{n="Play Store"; p=$vending}
    )) {
        if (-not $pair.p -or -not (Test-Path -LiteralPath $pair.p)) {
            $where = if ($stackDir) { "in $stackDir" } else { "in the stack folder" }
            throw "Missing $($pair.n) APK. Put the Google stack files $where (or pass -GmsApk/-GsfApk/-GsfLoginApk/-VendingBundle)."
        }
        Write-Host ("{0,-11} {1}" -f $pair.n, (Split-Path $pair.p -Leaf))
    }

    # The stub's com.google.android.gsf.gservices authority collides with real GSF.
    if (Test-PackageInstalled "com.portal.gsfstub") {
        Write-Notice "Removing GSF stub (com.portal.gsfstub)"
        Invoke-Adb uninstall com.portal.gsfstub | Write-Host
    }

    # Order matters: GSF, then GSF login, then GMS, then the Play Store.
    # Skip anything already present (keeps re-runs fast and avoids the 266 MB push).
    if (Test-PackageInstalled "com.google.android.gsf") {
        Write-Host "com.google.android.gsf already installed; skipping"
    } else {
        Install-Apk $gsf "com.google.android.gsf"
    }
    if (Test-PackageInstalled "com.google.android.gsf.login") {
        Write-Host "com.google.android.gsf.login already installed; skipping"
    } else {
        Install-Apk $gsfLogin "com.google.android.gsf.login"
    }

    # GMS: skip only when the wanted version is already installed.
    $wantGms = if ($gms -match "com\.google\.android\.gms_(\d+\.\d+\.\d+)") { $Matches[1] } else { "" }
    $haveGms = ""
    if (Test-PackageInstalled "com.google.android.gms") {
        $d = (Invoke-AdbQuiet shell dumpsys package com.google.android.gms).Output
        if ($d -match "versionName=([^\s]+)") { $haveGms = $Matches[1] }
    }
    if ($haveGms -and $wantGms -and $haveGms.StartsWith($wantGms)) {
        Write-Host "com.google.android.gms $haveGms already installed; skipping"
    } else {
        Install-Apk $gms "com.google.android.gms"
    }

    if (Test-PackageInstalled "com.android.vending") {
        Write-Host "com.android.vending already installed; leaving it"
    } else {
        $splits = Join-Path $env:TEMP "vending_splits"
        Remove-Item $splits -Recurse -Force -ErrorAction SilentlyContinue
        $zip = Join-Path $env:TEMP "vending.zip"
        Copy-Item -LiteralPath $vending -Destination $zip -Force
        Expand-Archive -LiteralPath $zip -DestinationPath $splits -Force
        $parts = @(Join-Path $splits "base.apk")
        foreach ($name in @("split_config.arm64_v8a.apk", "split_config.en.apk")) {
            $fp = Join-Path $splits $name
            if (Test-Path -LiteralPath $fp) { $parts += $fp }
        }
        Write-Host "install-multiple com.android.vending  <- $($parts.Count) apk(s)"
        Invoke-Adb install-multiple @parts | Write-Host
    }

    foreach ($pkg in @("com.google.android.gsf", "com.google.android.gsf.login", "com.google.android.gms", "com.android.vending")) {
        if (-not (Test-PackageInstalled $pkg)) { throw "Phase 2 did not verify: $pkg not installed" }
    }
    $ver = (Invoke-AdbQuiet shell dumpsys package com.google.android.gms).Output
    if ($ver -match "versionName=([^\s]+)") { Write-Host "GMS versionName=$($Matches[1])" }
    Write-Ok "Phase 2 verified: real Google stack installed (no stub)."
}


# ---------------------------------------------------------------------------
# Phase 3 - grant the Google apps the signature|privileged permissions they need
# ---------------------------------------------------------------------------
function Invoke-Phase3 {
    Write-Phase "Phase 3 - grant the Google apps their signature|privileged permissions"
    Resolve-Serial

    $fwsigs = (Invoke-AdbQuiet shell "dumpsys package android | grep -i 'past signatures'").Output
    if ($fwsigs -match "past signatures:\[.*flags: 4") {
        Write-Ok "Framework already has a PERMISSION-capable past signature; skipping Phase 3."
        return
    }

    $provisioner = Join-Path $ToolRoot "tools\provision_portal.py"
    if (-not (Test-Path $provisioner)) { throw "Provisioner not found: $provisioner" }

    # Phase 3's action installs the same UID-1000 helper and boot hook the exploit
    # carries, so a --skip-build run needs those prebuilt files too.
    if (-not $Rebuild) { Assert-BuildOutputs }

    if (-not (Wait-PortalReady -TimeoutSeconds 120)) {
        Write-AdbRecoveryHint
        throw "The Portal is not ready (ADB not connected, or still booting)."
    }
    if (Test-RecoveryChannel) {
        Write-Ok "Recovery channel verified (persist.adb.tcp.port=5555, TCP shell works)."
    } else {
        Write-Notice "TCP 5555 recovery channel is NOT working; a boot loop would need a factory reset."
    }

    $logDir = $script:LogDir
    Write-Host "Grant cert of: $GrantPackages"
    Write-Notice "This injects Google's cert as a PERMISSION-capable past signature of the framework, then reboots."

    $pyArgs = @($provisioner, "--serial", $script:Serial, "--permission-grants",
                "--permission-grant-packages", $GrantPackages,
                "--attempts", $Attempts, "--log-dir", $logDir)
    if (-not $Rebuild) { $pyArgs += "--skip-build" }

    $code = Invoke-Provisioner -PyArgs $pyArgs -LogDir $logDir
    if ($code -ne 0) {
        Write-AdbRecoveryHint
        throw ("Provisioner exited with code $code (see $logDir\provisioner.log). If the Portal is " +
               "boot-looping, recover with: adb connect <ip>:5555 ; " +
               "`"$script:PythonExe`" `"$provisioner`" --serial <ip>:5555 --permission-grants-restore --skip-build")
    }

    $script:PortalIp = $null
    if (-not (Wait-PortalReady -TimeoutSeconds 180)) {
        Write-AdbRecoveryHint
        throw "Phase 3 did not verify: the Portal did not come back after the exploit."
    }
    $boot = (Invoke-AdbQuiet shell getprop sys.boot_completed).Output
    if ($boot -ne "1") { throw "Phase 3 did not verify: sys.boot_completed=$boot" }
    Write-Host (Invoke-AdbQuiet shell "dumpsys package android | grep -i 'past signatures'").Output
    Write-Ok "Phase 3 ran and the device booted. (Launching the Play Store and signing in are manual, after Phase 4.)"
}


# ---------------------------------------------------------------------------
# Phase 4 - let the Play Store install apps + verify Google Services
# ---------------------------------------------------------------------------
function Invoke-Phase4 {
    Write-Phase "Phase 4 - allow Play Store installs + verify Google Services"
    Resolve-Serial
    if (-not (Wait-PortalReady -TimeoutSeconds 120)) {
        Write-AdbRecoveryHint
        throw "The Portal is not ready (ADB not connected, or still booting)."
    }

    # Meta's FacebookAppVerifier rejects every app not signed by Facebook, so the
    # Play Store (and Aurora) cannot install anything until Android is told to
    # skip that check. (Phase 2 already did this for the stack installs.)
    Disable-AppVerifier
    if ((Invoke-AdbQuiet shell settings get global package_verifier_enable).Output -ne "0") {
        throw "could not disable the package verifier"
    }

    # Confirm the grant from Phase 3 still holds for the Google apps.
    foreach ($pkg in @("com.google.android.gms", "com.android.vending")) {
        $d = (Invoke-AdbQuiet shell dumpsys package $pkg).Output
        if ($d -notmatch "MANAGE_USERS: granted=true") {
            throw "$pkg does not have MANAGE_USERS granted (run Phase 3 first)"
        }
        Write-Ok "$pkg MANAGE_USERS granted"
    }

    Write-Ok "Phase 4 done: the Play Store can install apps and Google Services is privileged."
    Write-Host "Manual: in the Play Store, install Google Home / Photos / YouTube, then sign in through Photos."
}


# ---------------------------------------------------------------------------
# Phase 5 helpers - read APK signing certs
# ---------------------------------------------------------------------------
# Returns the cert (hex DER + sha256) that Android <Sdk> would use for <Apk>.
# Uses tools\ExtractApkCert.class with apksig (found or fetched by
# Bootstrap-Deps), or the .java source when the class is missing or older.
function Get-ApkSignerCert {
    param([string]$Apk, [int]$Sdk)
    $java = Get-JavaPath
    if (-not $java) { throw "Java is required to read APK signing certs." }
    $jar = Get-ApksigJar
    if (-not $jar) { throw "apksig is required to read APK signing certs." }
    $classDir = Join-Path $PSScriptRoot "tools"
    $class = Join-Path $classDir "ExtractApkCert.class"
    $src = Join-Path $classDir "ExtractApkCert.java"
    $hasClass = Test-Path -LiteralPath $class
    $hasSource = Test-Path -LiteralPath $src
    if (-not $hasClass -and -not $hasSource) {
        throw "The ExtractApkCert tool is missing from tools\."
    }
    # The committed class is what the bundled JRE can run. If you change the
    # source, rebuild the class as described in AGENTS.md.
    $runSource = -not $hasClass -and $hasSource
    # java writes to stderr for warnings or a missing signer; under
    # $ErrorActionPreference=Stop that would throw before we can read the output.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($runSource) {
            $out = @(& $java -cp $jar $src $Apk $Sdk 2>&1 | ForEach-Object { "$_" })
        } else {
            $out = @(& $java -cp "$jar;$classDir" ExtractApkCert $Apk $Sdk 2>&1 | ForEach-Object { "$_" })
        }
    } finally { $ErrorActionPreference = $prev }
    $hex = ($out | Where-Object { $_ -match '^DER=([0-9a-fA-F]+)' } | ForEach-Object { $Matches[1] } | Select-Object -First 1)
    $sha = ($out | Where-Object { $_ -match '^SHA256=([0-9a-fA-F]+)' } | ForEach-Object { $Matches[1] } | Select-Object -First 1)
    if (-not $hex) { throw "Could not extract a signing cert from $Apk`n$($out | Out-String)" }
    return [pscustomobject]@{ Hex = $hex.Trim(); Sha256 = $sha.Trim() }
}

# android.content.pm.Signature.hashCode() == java.util.Arrays.hashCode(byte[]) (32-bit).
# AOSP prints this with Integer.toHexString(), which is NOT zero-padded, so the
# value here is unpadded too (to match the "past signatures:[...]" text dumpsys emits).
function Get-SignatureHashCode {
    param([string]$Hex)
    $h = [uint32]1
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $b = [Convert]::ToByte($Hex.Substring($i, 2), 16)
        $sx = if ($b -gt 127) { $b - 256 } else { [int]$b }
        $h = [uint32]((31 * [int64]$h + $sx) -band [int64][uint32]::MaxValue)
    }
    return ('{0:x}' -f $h)
}

# Find (or download) a genuine com.facebook.orca APK. Returns an object with the
# base APK (used to read its signing cert) and every install part (a split
# bundle is more than one APK).
function Get-MessengerApk {
    if ($MessengerApk) {
        if (-not (Test-Path -LiteralPath $MessengerApk)) { throw "-MessengerApk not found: $MessengerApk" }
        return [pscustomobject]@{ Base = $MessengerApk; Parts = @($MessengerApk) }
    }
    $hit = Get-NewestFile $MessengerDir "com.facebook.orca*.apk"
    if ($hit) { return [pscustomobject]@{ Base = $hit; Parts = @($hit) } }
    $hitXapk = Get-ChildItem $MessengerDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "com.facebook.orca*.xapk" } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($hitXapk) { return (Expand-MessengerXapk $hitXapk.FullName) }
    $apkeep = Join-Path $PSScriptRoot "messenger-patch\tools\apkeep.exe"
    if (Test-Path -LiteralPath $apkeep) {
        $dir = Join-Path $env:TEMP "portal-messenger-dl"
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Notice "Downloading the newest Messenger via apkeep ..."
        & $apkeep -a "com.facebook.orca" -d apk-pure -o "acknowledge_dangers=true,arch=arm64-v8a" $dir | Out-Null
        $apk = Get-ChildItem $dir -Recurse -File -Filter "*.apk" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($apk) { return [pscustomobject]@{ Base = $apk.FullName; Parts = @($apk.FullName) } }
        $xapk = Get-ChildItem $dir -Recurse -File -Filter "*.xapk" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($xapk) { return (Expand-MessengerXapk $xapk.FullName) }
    }
    throw "No Messenger APK. Put a genuine com.facebook.orca APK in $MessengerDir, pass -MessengerApk <path>, or add messenger-patch\tools\apkeep.exe."
}

# Unpack an .xapk (a zip holding a base APK plus splits) and return its parts.
function Expand-MessengerXapk([string]$Xapk) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $u = Join-Path (Split-Path $Xapk -Parent) "unpacked"
    Remove-Item $u -Recurse -Force -ErrorAction SilentlyContinue
    [IO.Compression.ZipFile]::ExtractToDirectory($Xapk, $u)
    $parts = @(Get-ChildItem $u -Recurse -File -Filter "*.apk" | ForEach-Object { $_.FullName })
    if ($parts.Count -eq 0) { throw "The Messenger bundle contained no APKs: $Xapk" }
    $base = $parts | Where-Object { (Split-Path $_ -Leaf) -eq "base.apk" } | Select-Object -First 1
    if (-not $base) { $base = $parts[0] }
    return [pscustomobject]@{ Base = $base; Parts = $parts }
}

# ---------------------------------------------------------------------------
# Phase 5 - install the genuine Messenger with no rename/re-sign workaround
# ---------------------------------------------------------------------------

# Facebook's Android app-signing certificate for com.facebook.orca (Messenger).
# Issued 2009, valid to 2050, identical across versions and never rotated, so it
# is treated as a constant: it lets the patch run without fetching the APK.  If
# the APK we later fetch is ever signed by a different cert, Phase 5 notices and
# re-applies the patch with the real one.
$script:MessengerCertHex = "30820268308201d102044a9c4610300d06092a864886f70d0101040500307a310b3009060355040613025553310b3009060355040813024341311230100603550407130950616c6f20416c746f31183016060355040a130f46616365626f6f6b204d6f62696c653111300f060355040b130846616365626f6f6b311d301b0603550403131446616365626f6f6b20436f72706f726174696f6e3020170d3039303833313231353231365a180f32303530303932353231353231365a307a310b3009060355040613025553310b3009060355040813024341311230100603550407130950616c6f20416c746f31183016060355040a130f46616365626f6f6b204d6f62696c653111300f060355040b130846616365626f6f6b311d301b0603550403131446616365626f6f6b20436f72706f726174696f6e30819f300d06092a864886f70d010101050003818d0030818902818100c207d51df8eb8c97d93ba0c8c1002c928fab00dc1b42fca5e66e99cc3023ed2d214d822bc59e8e35ddcf5f44c7ae8ade50d7e0c434f500e6c131f4a2834f987fc46406115de2018ebbb0d5a3c261bd97581ccfef76afc7135a6d59e8855ecd7eacc8f8737e794c60a761c536b72b11fac8e603f5da1a2d54aa103b8a13c0dbc10203010001300d06092a864886f70d0101040500038181005ee9be8bcbb250648d3b741290a82a1c9dc2e76a0af2f2228f1d9f9c4007529c446a70175c5a900d5141812866db46be6559e2141616483998211f4a673149fb2232a10d247663b26a9031e15f84bc1c74d141ff98a02d76f85b2c8ab2571b6469b232d8e768a7f7ca04f7abe4a775615916c07940656b58717457b42bd928a2"

# Inject presence's own cert (first) plus $ClientCertHex into presence's past
# signatures, then reboot.  Returns the presence (host) signing-cert object.
function Set-PresenceMessengerTrust {
    param([Parameter(Mandatory)][string]$ClientCertHex)
    # This run installs the UID-1000 helper and boot hook, so a --skip-build run
    # needs those prebuilt files before any device work starts. A device that is
    # already patched never gets here, so it is not blocked by the check.
    if (-not $Rebuild) { Assert-BuildOutputs }
    $sdk = [int](Invoke-AdbQuiet shell getprop ro.build.version.sdk).Output
    $remote = (Invoke-AdbQuiet shell "ls /system/priv-app/aloha_presence_release/ | grep -i '\.apk'").Output.Trim()
    if (-not $remote) { throw "Could not locate the installed presence APK." }
    $local = Join-Path $env:TEMP "portal-presence.apk"
    Invoke-Adb pull "/system/priv-app/aloha_presence_release/$remote" $local | Out-Null
    $hostCert = Get-ApkSignerCert $local $sdk
    Write-Host "presence cert  sha256=$($hostCert.Sha256.Substring(0,16))... hashCode=$(Get-SignatureHashCode $hostCert.Hex)"

    $provisioner = Join-Path $ToolRoot "tools\provision_portal.py"
    if (-not (Test-Path $provisioner)) { throw "Provisioner not found: $provisioner" }
    $logDir = $script:LogDir
    Write-Notice "Injecting presence's own cert first, then the Messenger cert."
    $env:PORTAL_SKIP_CLEAN_BOOT = "1"
    $pyArgs = @($provisioner, "--serial", $script:Serial, "--permission-grants",
                "--permission-grant-host", "com.facebook.alohaservices.presence",
                "--permission-grant-packages", "com.facebook.alohaservices.presence",
                "--permission-grant-cert", "$($hostCert.Hex),$ClientCertHex",
                "--attempts", $Attempts, "--log-dir", $logDir)
    if (-not $Rebuild) { $pyArgs += "--skip-build" }
    try {
        $code = Invoke-Provisioner -PyArgs $pyArgs -LogDir $logDir
    } finally {
        Remove-Item Env:\PORTAL_SKIP_CLEAN_BOOT -ErrorAction SilentlyContinue
    }
    if ($code -ne 0) {
        Write-AdbRecoveryHint
        throw "Provisioner exited with code $code (see $logDir\provisioner.log)"
    }
    $script:PortalIp = $null
    if (-not (Wait-PortalReady -TimeoutSeconds 180)) {
        Write-AdbRecoveryHint
        throw "The Portal did not come back after the Messenger patch."
    }
    return $hostCert
}

function Invoke-Phase5 {
    Write-Phase "Phase 5 - genuine Messenger (no rename/re-sign workaround)"
    Resolve-Serial

    if (-not (Wait-PortalReady -TimeoutSeconds 120)) {
        Write-AdbRecoveryHint
        throw "The Portal is not ready (ADB not connected, or still booting)."
    }

    $knownHash = Get-SignatureHashCode $script:MessengerCertHex
    Write-Host "Messenger cert (known) hashCode=$knownHash"

    # Apply the patch (unless presence already trusts the cert).  presence's OWN
    # cert goes first (so its identity is unchanged and every other Facebook app
    # still trusts it), then the Messenger cert (so Android's duplicate-permission
    # check accepts the install).  This runs regardless of the install answer below.
    $presenceSigs = (Invoke-AdbQuiet shell "dumpsys package com.facebook.alohaservices.presence | grep -i 'past signatures'").Output
    if ($presenceSigs -match [regex]::Escape($knownHash)) {
        Write-Ok "presence already trusts the Messenger cert; skipping the injection."
    } else {
        $null = Set-PresenceMessengerTrust -ClientCertHex $script:MessengerCertHex
    }

    # The patch is in place.  Whether to install Messenger itself is the user's
    # call; declining skips only the install, not the patch.
    Write-Host ""
    Write-Host "The Messenger patch is installed.  Do you want to install the latest Facebook Messenger now?"
    $doInstall = Read-YesNo `
        -Prompt "Type [Y] to install Facebook Messenger on the Portal now or [N] to skip this step." `
        -Invalid "Invalid key, please type [Y] to install Facebook Messenger on the Portal now or [N] to skip this step."
    if (-not $doInstall) {
        Write-Ok "Skipping the Messenger install.  The patch is applied, so you can install Messenger from the Play Store any time."
        return
    }

    # Fetch the actual APK, then make sure it is signed by the cert we trusted.
    # If it is not, re-apply the patch with its real cert before installing.
    $mp = Get-MessengerApk
    $apk = $mp.Base
    Write-Host "Messenger APK: $(Split-Path $apk -Leaf)"
    $sdk = [int](Invoke-AdbQuiet shell getprop ro.build.version.sdk).Output
    $client = Get-ApkSignerCert $apk $sdk
    $clientHash = Get-SignatureHashCode $client.Hex
    Write-Host "Messenger cert sha256=$($client.Sha256.Substring(0,16))... hashCode=$clientHash"
    if ($clientHash -ne $knownHash) {
        Write-Notice "The fetched Messenger is signed by a different certificate ($clientHash); re-applying the patch."
        $null = Set-PresenceMessengerTrust -ClientCertHex $client.Hex
    }

    # Meta's verifier rejects non-Facebook-signed apps; keep it off for installs.
    Disable-AppVerifier

    $parts = @($mp.Parts)
    if ($parts.Count -gt 1) {
        Write-Host "install-multiple -r  ($($parts.Count) apks)"
        $r = Invoke-AdbQuiet install-multiple -r @parts
    } else {
        Write-Host "install -r $(Split-Path $apk -Leaf)"
        $r = Invoke-AdbQuiet install -r $apk
    }
    if ($r.Code -ne 0 -or $r.Output -notmatch 'Success') { throw "Messenger install failed:`n$($r.Output)" }
    if (-not (Test-PackageInstalled "com.facebook.orca")) { throw "com.facebook.orca is not present after install" }
    $d = (Invoke-AdbQuiet shell "dumpsys package com.facebook.orca").Output
    if ($d -match "versionName=([^\s]+)") { Write-Host "Messenger versionName=$($Matches[1])" }
    Write-Ok "Phase 5 verified: genuine Messenger installed (no rename/re-sign)."
}


# ------------------------------- run ---------------------------------------
if (-not (Confirm-RiskWarning)) {
    Write-Host "`nExiting at your request. Nothing was changed." -ForegroundColor Yellow
    exit 0
}

# Phase catalogue, in order. Only the phases named in -Phases are run; the rest
# print a single "[Skipped]" line. needsBuild marks the phases that run the
# provisioner without --skip-build, so -Rebuild has something to compile. deps
# names the host tools a phase needs beyond adb.
$PhaseCatalogue = @(
    @{ n = 1; label = "Phase 1 - root exploit + TCP 5555 recovery channel";                     needsBuild = $true;  deps = @("python", "simpleperf");                    run = { Invoke-Phase1 } },
    @{ n = 2; label = "Phase 2 - install the real Google stack (no stub)";                      needsBuild = $false; deps = @();                                           run = { Invoke-Phase2 } },
    @{ n = 3; label = "Phase 3 - grant the Google apps their signature|privileged permissions"; needsBuild = $true;  deps = @("python", "simpleperf");                    run = { Invoke-Phase3 } },
    @{ n = 4; label = "Phase 4 - allow Play Store installs + verify Google Services";           needsBuild = $false; deps = @();                                           run = { Invoke-Phase4 } },
    @{ n = 5; label = "Phase 5 - genuine Messenger (no rename/re-sign workaround)";             needsBuild = $true;  deps = @("python", "simpleperf", "java", "apksig"); run = { Invoke-Phase5 } }
)
$KnownPhases = @($PhaseCatalogue | ForEach-Object { $_.n })

$wanted = @{}
foreach ($tok in ($Phases -split ',')) {
    $t = $tok.Trim()
    if ($t -eq "") { continue }
    if ($t -notmatch '^\d+$') {
        Write-Bad "-Phases: '$t' is not a phase number. Known phases: $($KnownPhases -join ', ')"
        exit 1
    }
    $wanted[[int]$t] = $true
}
$unknown = @($wanted.Keys | Where-Object { $KnownPhases -notcontains $_ })
if ($unknown.Count -gt 0) {
    Write-Bad "-Phases: unknown phase(s): $($unknown -join ', '). Known phases: $($KnownPhases -join ', ')"
    exit 1
}

$selected = @($PhaseCatalogue | Where-Object { $wanted.ContainsKey($_.n) } | ForEach-Object { $_.n })
# Phases that never build (2 and 4) must not be blocked by a missing toolchain.
$selectedBuilds = @($PhaseCatalogue | Where-Object { $wanted.ContainsKey($_.n) -and $_.needsBuild }).Count -gt 0
$selectedDeps = @($PhaseCatalogue | Where-Object { $wanted.ContainsKey($_.n) } | ForEach-Object { $_.deps } | Select-Object -Unique)
Write-Host "Meta Portal+ provisioning - phases: $($selected -join ',')" -ForegroundColor White

$ran = @()
try {
    if ($Rebuild -and $selectedBuilds) { Assert-RebuildToolchain }
    Bootstrap-Deps -Needs $selectedDeps
    foreach ($ph in $PhaseCatalogue) {
        if ($wanted.ContainsKey($ph.n)) {
            $null = New-LogDir
            & $ph.run
            $ran += $ph.n
        } else {
            Write-Phase $ph.label
            Write-Host "[Skipped]" -ForegroundColor DarkGray
        }
    }
}
catch {
    Write-Bad $_.Exception.Message
    Write-RunError $_.Exception.Message
    Write-Host "PORTAL_PROVISION_FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "`nPORTAL_PROVISION_OK phases=$($ran -join ',')" -ForegroundColor Green
if ($ran.Count -eq $KnownPhases.Count) {
    Write-DoneBox "Done!  Your Portal has been opened!"
} else {
    Write-Host "`nStopped after phase(s) $($ran -join ','). Re-run with -Phases 1,2,3,4,5 for the full setup." -ForegroundColor Green
}

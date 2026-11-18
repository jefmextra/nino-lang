Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    Write-Host "NinoLang Cross-Platform E2E Runner (PowerShell)"
    Write-Host "Usage:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File tests/e2e/run_e2e.ps1 [options]"
    Write-Host "Options:"
    Write-Host "  -Tier | --tier <1|2|3|4|all>        Filter by tier (default: all)"
    Write-Host "  -Feature | --feature <F1..F16>      Filter by feature (comma-separated or repeated)"
    Write-Host "  -Id | --id <test_id>                Filter by test ID (comma-separated or repeated)"
    Write-Host "  -Ninoc | --ninoc <path>             Override ninoc compiler path"
    Write-Host "  -StrictCompliance | --strict-compliance  Enforce strict compliance checks"
    Write-Host "  -Bootstrap | --bootstrap            Allow bootstrap fallback from bootstrap/ninoc_seed.c"
    Write-Host "  -VerboseOutput | -Verbose | --verbose    Verbose diagnostic output"
    Write-Host "  -Help | --help | -h                 Show this help"
}

$TierFilters = New-Object System.Collections.Generic.List[string]
$FeatureFilters = New-Object System.Collections.Generic.List[string]
$IdFilters = New-Object System.Collections.Generic.List[string]
$NinocOverride = ""
$StrictCompliance = $false
$Bootstrap = $false
$VerboseMode = $false

function Add-SplitValues {
    param(
        [System.Collections.Generic.List[string]]$TargetList,
        $RawValue,
        [switch]$UpperCase,
        [switch]$LowerCase
    )
    if ($null -eq $RawValue) { return }
    if ($RawValue -is [System.Array]) {
        foreach ($el in $RawValue) {
            Add-SplitValues -TargetList $TargetList -RawValue $el -UpperCase:$UpperCase -LowerCase:$LowerCase
        }
        return
    }
    $s = [string]$RawValue
    foreach ($part in ($s -split ",")) {
        $t = $part.Trim()
        if ($t.Length -gt 0) {
            if ($UpperCase) { $t = $t.ToUpperInvariant() }
            elseif ($LowerCase) { $t = $t.ToLowerInvariant() }
            $TargetList.Add($t)
        }
    }
}

$i = 0
while ($i -lt $args.Count) {
    $rawArg = $args[$i]
    $argStr = [string]$rawArg
    $key = $argStr
    $inlineVal = $null
    $hasInlineVal = $false

    if ($argStr -match '^(--?[A-Za-z0-9_-]+)[=:](.*)$') {
        $key = $Matches[1]
        $inlineVal = $Matches[2]
        $hasInlineVal = $true
    }
    $keyLower = $key.ToLowerInvariant()

    switch ($keyLower) {
        { $_ -in @("-h", "-help", "--help") } {
            Show-Usage
            exit 0
        }
        { $_ -in @("-tier", "--tier") } {
            if ($hasInlineVal) {
                Add-SplitValues -TargetList $TierFilters -RawValue $inlineVal -LowerCase
            } else {
                $i++
                if ($i -ge $args.Count) { throw "Missing value for $key" }
                Add-SplitValues -TargetList $TierFilters -RawValue $args[$i] -LowerCase
            }
        }
        { $_ -in @("-feature", "--feature") } {
            if ($hasInlineVal) {
                Add-SplitValues -TargetList $FeatureFilters -RawValue $inlineVal -UpperCase
            } else {
                $i++
                if ($i -ge $args.Count) { throw "Missing value for $key" }
                Add-SplitValues -TargetList $FeatureFilters -RawValue $args[$i] -UpperCase
            }
        }
        { $_ -in @("-id", "--id") } {
            if ($hasInlineVal) {
                Add-SplitValues -TargetList $IdFilters -RawValue $inlineVal
            } else {
                $i++
                if ($i -ge $args.Count) { throw "Missing value for $key" }
                Add-SplitValues -TargetList $IdFilters -RawValue $args[$i]
            }
        }
        { $_ -in @("-ninoc", "--ninoc") } {
            if ($hasInlineVal) {
                $NinocOverride = $inlineVal.Trim()
            } else {
                $i++
                if ($i -ge $args.Count) { throw "Missing value for $key" }
                $NinocOverride = ([string]$args[$i]).Trim()
            }
        }
        { $_ -in @("-strictcompliance", "--strict-compliance") } {
            if ($hasInlineVal) {
                $StrictCompliance = ($inlineVal.Trim().ToLowerInvariant() -notin @("false", "0", "`$false"))
            } else {
                $StrictCompliance = $true
            }
        }
        { $_ -in @("-bootstrap", "--bootstrap") } {
            if ($hasInlineVal) {
                $Bootstrap = ($inlineVal.Trim().ToLowerInvariant() -notin @("false", "0", "`$false"))
            } else {
                $Bootstrap = $true
            }
        }
        { $_ -in @("-verboseoutput", "-verbose", "--verbose") } {
            if ($hasInlineVal) {
                $VerboseMode = ($inlineVal.Trim().ToLowerInvariant() -notin @("false", "0", "`$false"))
            } else {
                $VerboseMode = $true
            }
        }
        default {
            throw "Unknown argument: $argStr"
        }
    }
    $i++
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$E2EDir = (Resolve-Path $ScriptDir).Path
$RepoRoot = (Resolve-Path (Join-Path (Join-Path $E2EDir "..") "..")).Path
$TmpRoot = Join-Path $E2EDir ".tmp"
$ManifestDir = Join-Path $E2EDir "manifests"
$IsWin = ($env:OS -eq "Windows_NT") -or ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)

function Get-Prop {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    $prop = $Obj.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function To-StringArray {
    param($Val)
    $list = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Val) {
        if ($Val -is [System.Array] -or $Val -is [System.Collections.IList]) {
            foreach ($x in $Val) {
                if ($null -ne $x) { $list.Add([string]$x) }
            }
        } else {
            $list.Add([string]$Val)
        }
    }
    return ,([string[]]$list.ToArray())
}

function Strip-Ansi {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    $esc = [char]27
    return [System.Text.RegularExpressions.Regex]::Replace($Text, "$esc\[[0-9;]*[A-Za-z]", "")
}

function Quote-WinArg {
    param([string]$Arg)
    if ($null -eq $Arg -or $Arg.Length -eq 0) { return '""' }
    if ($Arg -notmatch '[\s"]') { return $Arg }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bsCount = 0
    for ($idx = 0; $idx -lt $Arg.Length; $idx++) {
        $c = $Arg[$idx]
        if ($c -eq '\') {
            $bsCount++
        } elseif ($c -eq '"') {
            if ($bsCount -gt 0) {
                [void]$sb.Append('\', $bsCount * 2)
                $bsCount = 0
            }
            [void]$sb.Append('\"')
        } else {
            if ($bsCount -gt 0) {
                [void]$sb.Append('\', $bsCount)
                $bsCount = 0
            }
            [void]$sb.Append($c)
        }
    }
    if ($bsCount -gt 0) {
        [void]$sb.Append('\', $bsCount * 2)
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Invoke-ProcessBounded {
    param(
        [string]$FilePath,
        [string[]]$ArgList,
        [string]$WorkDir,
        [int]$TimeoutSec = 30,
        [string]$StdinText = $null
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $quotedArgs = @()
    if ($null -ne $ArgList) {
        foreach ($a in $ArgList) {
            $quotedArgs += (Quote-WinArg ([string]$a))
        }
    }
    $psi.Arguments = ($quotedArgs -join " ")
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = ($null -ne $StdinText)
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()

    if ($null -ne $StdinText) {
        $proc.StandardInput.Write($StdinText)
        $proc.StandardInput.Close()
    }

    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    $timeoutMs = [Math]::Max(1, $TimeoutSec) * 1000
    $exited = $proc.WaitForExit($timeoutMs)
    $timedOut = $false
    if (-not $exited) {
        $timedOut = $true
        try { $proc.Kill() } catch {}
        try { [void]$proc.WaitForExit(2000) } catch {}
        try { [void][System.Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), 1000) } catch {}
        $exitCode = -1
    } else {
        $proc.WaitForExit()
        [void][System.Threading.Tasks.Task]::WaitAll(@($outTask, $errTask))
        $exitCode = $proc.ExitCode
    }

    $stdoutStr = if ($outTask.IsCompleted -and -not $outTask.IsFaulted) { $outTask.Result } else { "" }
    $stderrStr = if ($errTask.IsCompleted -and -not $errTask.IsFaulted) { $errTask.Result } else { "" }
    $proc.Dispose()

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Stdout = Strip-Ansi $stdoutStr
        Stderr = Strip-Ansi $stderrStr
        TimedOut = $timedOut
    }
}

function Test-BytesContain {
    param([byte[]]$Haystack, [byte[]]$Needle)
    if ($null -eq $Needle -or $Needle.Length -eq 0) { return $true }
    if ($null -eq $Haystack -or $Haystack.Length -lt $Needle.Length) { return $false }
    $first = $Needle[0]
    $limit = $Haystack.Length - $Needle.Length
    $pos = 0
    while ($pos -le $limit) {
        $idx = [System.Array]::IndexOf($Haystack, $first, $pos)
        if ($idx -lt 0 -or $idx -gt $limit) { return $false }
        $match = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$idx + $j] -ne $Needle[$j]) {
                $match = $false
                break
            }
        }
        if ($match) { return $true }
        $pos = $idx + 1
    }
    return $false
}

function Invoke-E2EComplianceGate {
    param([string]$RootDir, [string]$TmpDirPath, [bool]$Strict)
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $altSep = [System.IO.Path]::AltDirectorySeparatorChar
    $tmpNorm = [System.IO.Path]::GetFullPath($TmpDirPath).TrimEnd($sep, $altSep) + $sep
    $ninoFiles = @(Get-ChildItem -Path $RootDir -Filter "*.nino" -Recurse -File |
        Where-Object { -not ([System.IO.Path]::GetFullPath($_.FullName)).StartsWith($tmpNorm, [System.StringComparison]::OrdinalIgnoreCase) } |
        Sort-Object FullName)

    $violations = New-Object System.Collections.Generic.List[string]
    foreach ($f in $ninoFiles) {
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $n = $bytes.Length
        $line = 1
        $inStr = $false
        $inLineCmt = $false
        $inBlockCmt = $false
        $idx = 0
        while ($idx -lt $n) {
            $b0 = $bytes[$idx]
            if ($b0 -eq 226 -and ($idx + 2) -lt $n) {
                $b1 = $bytes[$idx + 1]
                $b2 = $bytes[$idx + 2]
                if ($b1 -eq 128 -and ($b2 -eq 148 -or $b2 -eq 147)) {
                    $violations.Add("$($f.FullName):$line Forbidden UTF-8 em/en dash")
                }
            }
            if ($b0 -eq 10) {
                $line++
                $inStr = $false
                $inLineCmt = $false
                $idx++
                continue
            }
            if ($inLineCmt) {
                $idx++
                continue
            }
            if ($inBlockCmt) {
                if ($b0 -eq 42 -and ($idx + 1) -lt $n -and $bytes[$idx + 1] -eq 47) {
                    $inBlockCmt = $false
                    $idx += 2
                    continue
                }
                $idx++
                continue
            }
            if ($inStr) {
                if ($b0 -eq 92) {
                    if (($idx + 1) -lt $n -and $bytes[$idx + 1] -eq 10) {
                        $line++
                    }
                    $idx += 2
                    continue
                }
                if ($b0 -eq 34) {
                    $inStr = $false
                }
                $idx++
                continue
            }
            if ($b0 -eq 34) {
                $inStr = $true
                $idx++
                continue
            }
            if ($b0 -eq 47 -and ($idx + 1) -lt $n -and $bytes[$idx + 1] -eq 47) {
                $inLineCmt = $true
                $idx += 2
                continue
            }
            if ($b0 -eq 47 -and ($idx + 1) -lt $n -and $bytes[$idx + 1] -eq 42) {
                $inBlockCmt = $true
                $idx += 2
                continue
            }
            if ($b0 -eq 42 -and ($idx + 1) -lt $n -and $bytes[$idx + 1] -eq 47) {
                $violations.Add("$($f.FullName):$line Unmatched block comment close '*/'")
                $idx += 2
                continue
            }
            if ($b0 -eq 35) {
                $isNoStd = $false
                if (($idx + 7) -le $n) {
                    $tag = [System.Text.Encoding]::ASCII.GetString($bytes, $idx, 7)
                    if ($tag -eq "#no_std") {
                        $isNoStd = $true
                    }
                }
                if ($isNoStd) {
                    $idx += 7
                } else {
                    $violations.Add("$($f.FullName):$line Forbidden '#' directive/comment (only #no_std allowed)")
                    $idx++
                }
                continue
            }
            $idx++
        }
        if ($inBlockCmt) {
            $violations.Add("$($f.FullName):$line Unclosed block comment '/*'")
        }
    }

    if ($Strict) {
        $textFiles = @(Get-ChildItem -Path $RootDir -Include "*.json", "*.ps1", "*.sh" -Recurse -File |
            Where-Object { -not ([System.IO.Path]::GetFullPath($_.FullName)).StartsWith($tmpNorm, [System.StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object FullName)
        foreach ($tf in $textFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($tf.FullName)
            $line = 1
            for ($idx = 0; $idx -lt $bytes.Length; $idx++) {
                $b0 = $bytes[$idx]
                if ($b0 -eq 10) { $line++ }
                elseif ($b0 -eq 226 -and ($idx + 2) -lt $bytes.Length) {
                    $b1 = $bytes[$idx + 1]
                    $b2 = $bytes[$idx + 2]
                    if ($b1 -eq 128 -and ($b2 -eq 148 -or $b2 -eq 147)) {
                        $violations.Add("$($tf.FullName):$line Forbidden UTF-8 em/en dash")
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        FileCount = $ninoFiles.Count
        Violations = $violations
    }
}

function Resolve-GccCompiler {
    param([bool]$IsWindowsHost)
    foreach ($envName in @("NINO_CC", "CC")) {
        $val = [System.Environment]::GetEnvironmentVariable($envName)
        if (-not [string]::IsNullOrWhiteSpace($val)) {
            $trimmed = $val.Trim()
            if (Test-Path $trimmed) { return (Resolve-Path $trimmed).Path }
            $cmd = Get-Command $trimmed -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $cmd) { return $cmd.Source }
        }
    }
    $pathGcc = Get-Command "gcc" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pathGcc) { return $pathGcc.Source }
    if ($IsWindowsHost) {
        $fallbacks = @(
            (Join-Path $env:LOCALAPPDATA "Programs\CLion\bin\mingw\bin\gcc.exe"),
            "C:\msys64\mingw64\bin\gcc.exe",
            "C:\msys64\ucrt64\bin\gcc.exe"
        )
        foreach ($fb in $fallbacks) {
            if (Test-Path $fb) { return $fb }
        }
    }
    return ""
}

function Resolve-NinocCompiler {
    param(
        [string]$RepoDir,
        [string]$TmpDirPath,
        [string]$OverridePath,
        [bool]$AllowBootstrap,
        [string]$GccPath,
        [bool]$IsWindowsHost
    )
    $exeExt = if ($IsWindowsHost) { ".exe" } else { "" }
    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) {
        $cand = $OverridePath
        if (-not [System.IO.Path]::IsPathRooted($cand)) {
            $rel = Join-Path $RepoDir $cand
            if (Test-Path $rel) { return (Resolve-Path $rel).Path }
        }
        if (Test-Path $cand) { return (Resolve-Path $cand).Path }
        $cmd = Get-Command $cand -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $cmd) { return $cmd.Source }
        throw "Specified ninoc compiler not found: $OverridePath"
    }

    $candidates = @(
        (Join-Path $RepoDir ("ninoc" + $exeExt)),
        (Join-Path (Join-Path $RepoDir "bin") ("ninoc" + $exeExt))
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }

    if ($AllowBootstrap) {
        $seedC = Join-Path (Join-Path $RepoDir "bootstrap") "ninoc_seed.c"
        if (-not (Test-Path $seedC)) {
            throw "Bootstrap requested, but missing $seedC"
        }
        if ([string]::IsNullOrWhiteSpace($GccPath)) {
            throw "Bootstrap requested, but no GCC compiler was found"
        }
        if (-not (Test-Path $TmpDirPath)) {
            New-Item -ItemType Directory -Path $TmpDirPath -Force | Out-Null
        }
        $stage1Out = Join-Path $TmpDirPath ("stage1" + $exeExt)
        $linkLibs = if ($IsWindowsHost) {
            @("-lm", "-lgdi32", "-luser32", "-lbcrypt", "-lws2_32")
        } else {
            @("-lm", "-lpthread", "-ldl")
        }
        $gccArgs = @("-O2", "-std=c11", $seedC, "-o", $stage1Out) + $linkLibs
        $res = Invoke-ProcessBounded -FilePath $GccPath -ArgList $gccArgs -WorkDir $RepoDir -TimeoutSec 120
        if ($res.TimedOut -or $res.ExitCode -ne 0 -or -not (Test-Path $stage1Out)) {
            throw "Failed to compile bootstrap/ninoc_seed.c: $($res.Stdout)`n$($res.Stderr)"
        }
        return $stage1Out
    }

    throw "Could not locate ninoc compiler (checked ./ninoc$exeExt, ./bin/ninoc$exeExt). Pass --ninoc <path> or --bootstrap."
}

function Find-EbpfExecPacketEnd {
    param([string]$CSource)
    $searchPos = 0
    $n = $CSource.Length
    while ($true) {
        $ebpfIdx = $CSource.IndexOf("ebpf_exec_packet(", $searchPos, [System.StringComparison]::Ordinal)
        if ($ebpfIdx -lt 0) { return -1 }
        $scan = $ebpfIdx + "ebpf_exec_packet(".Length
        $inStr = $false
        $inChr = $false
        $inLc = $false
        $inBc = $false
        $bodyStart = -1
        while ($scan -lt $n) {
            $ch = $CSource[$scan]
            if ($inLc) {
                if ($ch -eq "`n") { $inLc = $false }
                $scan++
                continue
            }
            if ($inBc) {
                if ($ch -eq '*' -and ($scan + 1) -lt $n -and $CSource[$scan + 1] -eq '/') {
                    $inBc = $false
                    $scan += 2
                    continue
                }
                $scan++
                continue
            }
            if ($inStr) {
                if ($ch -eq '\' -and ($scan + 1) -lt $n) { $scan += 2; continue }
                if ($ch -eq '"') { $inStr = $false }
                $scan++
                continue
            }
            if ($inChr) {
                if ($ch -eq '\' -and ($scan + 1) -lt $n) { $scan += 2; continue }
                if ($ch -eq "'") { $inChr = $false }
                $scan++
                continue
            }
            if ($ch -eq '/' -and ($scan + 1) -lt $n -and $CSource[$scan + 1] -eq '/') { $inLc = $true; $scan += 2; continue }
            if ($ch -eq '/' -and ($scan + 1) -lt $n -and $CSource[$scan + 1] -eq '*') { $inBc = $true; $scan += 2; continue }
            if ($ch -eq '"') { $inStr = $true; $scan++; continue }
            if ($ch -eq "'") { $inChr = $true; $scan++; continue }
            if ($ch -eq ';') { break }
            if ($ch -eq '{') { $bodyStart = $scan; break }
            $scan++
        }
        if ($bodyStart -lt 0) {
            $searchPos = $ebpfIdx + "ebpf_exec_packet(".Length
            continue
        }
        $depth = 0
        $k = $bodyStart
        while ($k -lt $n) {
            $ch = $CSource[$k]
            if ($inLc) {
                if ($ch -eq "`n") { $inLc = $false }
                $k++
                continue
            }
            if ($inBc) {
                if ($ch -eq '*' -and ($k + 1) -lt $n -and $CSource[$k + 1] -eq '/') {
                    $inBc = $false
                    $k += 2
                    continue
                }
                $k++
                continue
            }
            if ($inStr) {
                if ($ch -eq '\' -and ($k + 1) -lt $n) { $k += 2; continue }
                if ($ch -eq '"') { $inStr = $false }
                $k++
                continue
            }
            if ($inChr) {
                if ($ch -eq '\' -and ($k + 1) -lt $n) { $k += 2; continue }
                if ($ch -eq "'") { $inChr = $false }
                $k++
                continue
            }
            if ($ch -eq '/' -and ($k + 1) -lt $n -and $CSource[$k + 1] -eq '/') { $inLc = $true; $k += 2; continue }
            if ($ch -eq '/' -and ($k + 1) -lt $n -and $CSource[$k + 1] -eq '*') { $inBc = $true; $k += 2; continue }
            if ($ch -eq '"') { $inStr = $true; $k++; continue }
            if ($ch -eq "'") { $inChr = $true; $k++; continue }
            if ($ch -eq '{') {
                $depth++
            } elseif ($ch -eq '}') {
                $depth--
                if ($depth -eq 0) {
                    $endPos = $k + 1
                    while ($endPos -lt $n -and ($CSource[$endPos] -eq "`r" -or $CSource[$endPos] -eq "`n")) {
                        $endPos++
                    }
                    return $endPos
                }
            }
            $k++
        }
        return -1
    }
}

function Get-CScanText {
    param([string]$CSource, [string]$Scope)
    $startIdx = 0
    if ($Scope -eq "generated") {
        $markerIdx = -1
        foreach ($marker in @("/* NINO_RUNTIME_HEADER_END */", "// NINO_RUNTIME_HEADER_END")) {
            $mpos = $CSource.IndexOf($marker, [System.StringComparison]::Ordinal)
            if ($mpos -ge 0) {
                $nlM = $CSource.IndexOf("`n", $mpos)
                $markerIdx = if ($nlM -ge 0) { $nlM + 1 } else { $mpos + $marker.Length }
                break
            }
        }
        if ($markerIdx -ge 0) {
            $startIdx = $markerIdx
        } else {
            $lineIdx = -1
            if ($CSource.StartsWith("#line ", [System.StringComparison]::Ordinal)) {
                $lineIdx = 0
            } else {
                $nlLine = $CSource.IndexOf("`n#line ", [System.StringComparison]::Ordinal)
                if ($nlLine -ge 0) { $lineIdx = $nlLine + 1 }
            }
            $afterEbpf = Find-EbpfExecPacketEnd -CSource $CSource
            if ($afterEbpf -ge 0) {
                if ($lineIdx -ge 0 -and $lineIdx -lt $afterEbpf) {
                    $startIdx = $lineIdx
                } else {
                    $startIdx = $afterEbpf
                }
            } elseif ($lineIdx -ge 0) {
                $startIdx = $lineIdx
            } else {
                throw "Cannot locate generated C boundary for c11_scan_scope='generated' (neither runtime header end nor #line directive found)"
            }
        }
    }
    $raw = if ($startIdx -gt 0) { $CSource.Substring($startIdx) } else { $CSource }
    $sb = New-Object System.Text.StringBuilder($raw.Length)
    $len = $raw.Length
    $k = 0
    while ($k -lt $len) {
        $ch = $raw[$k]
        if ($ch -eq '/' -and ($k + 1) -lt $len -and $raw[$k + 1] -eq '/') {
            [void]$sb.Append(' ')
            $k += 2
            while ($k -lt $len -and $raw[$k] -ne "`n") { $k++ }
            continue
        }
        if ($ch -eq '/' -and ($k + 1) -lt $len -and $raw[$k + 1] -eq '*') {
            [void]$sb.Append(' ')
            $k += 2
            while (($k + 1) -lt $len -and -not ($raw[$k] -eq '*' -and $raw[$k + 1] -eq '/')) { $k++ }
            $k += 2
            continue
        }
        if ($ch -eq '"') {
            [void]$sb.Append(' ')
            $k++
            while ($k -lt $len) {
                if ($raw[$k] -eq '\' -and ($k + 1) -lt $len) {
                    $k += 2
                    continue
                }
                if ($raw[$k] -eq '"') {
                    $k++
                    break
                }
                $k++
            }
            continue
        }
        if ($ch -eq "'") {
            [void]$sb.Append(' ')
            $k++
            while ($k -lt $len) {
                if ($raw[$k] -eq '\' -and ($k + 1) -lt $len) {
                    $k += 2
                    continue
                }
                if ($raw[$k] -eq "'") {
                    $k++
                    break
                }
                $k++
            }
            continue
        }
        [void]$sb.Append($ch)
        $k++
    }
    return $sb.ToString()
}

function Test-C11TokenPresent {
    param([string]$ScanText, [string]$Token)
    if ($Token -eq "({") {
        return [regex]::IsMatch($ScanText, '\(\s*\{')
    }
    if ($Token -eq "__sync_") {
        return [regex]::IsMatch($ScanText, '\b__sync_[A-Za-z0-9_]*')
    }
    if ($Token -match '^[A-Za-z_][A-Za-z0-9_]*$') {
        $pat = '\b' + [regex]::Escape($Token) + '\b'
        return [regex]::IsMatch($ScanText, $pat)
    }
    return $ScanText.Contains($Token)
}

function Load-AndValidateManifests {
    param([string]$ManifestFolder)
    if (-not (Test-Path $ManifestFolder)) {
        throw "Manifest directory not found: $ManifestFolder"
    }
    $files = @(Get-ChildItem -Path $ManifestFolder -Filter "*.json" -File | Sort-Object Name)
    if ($files.Count -eq 0) {
        throw "No manifest files found in $ManifestFolder"
    }
    $validModes = @("build-run", "run", "compile-fail", "c11-audit", "verify-proof", "binary-inspect", "command-check")
    $seenIds = New-Object System.Collections.Generic.HashSet[string]
    $allTests = New-Object System.Collections.Generic.List[object]

    foreach ($mf in $files) {
        $rawJson = [System.IO.File]::ReadAllText($mf.FullName, [System.Text.Encoding]::UTF8)
        $parsed = $rawJson | ConvertFrom-Json
        $entries = $null
        if ($parsed -is [System.Array]) {
            $entries = $parsed
        } else {
            $testsProp = Get-Prop $parsed "tests" $null
            if ($null -ne $testsProp) {
                $entries = @($testsProp)
            } elseif ($null -ne (Get-Prop $parsed "id" $null)) {
                $entries = @($parsed)
            } elseif ($rawJson.Trim() -match '^\[\s*\]$') {
                $entries = @()
            }
        }
        if ($null -eq $entries) {
            throw "Manifest $($mf.Name) missing 'tests' array"
        }
        foreach ($t in @($entries)) {
            $tid = Get-Prop $t "id" ""
            $tier = Get-Prop $t "tier" $null
            $feat = Get-Prop $t "feature" $null
            $mode = Get-Prop $t "mode" ""
            if ([string]::IsNullOrWhiteSpace([string]$tid)) {
                throw "Manifest $($mf.Name) contains entry missing 'id'"
            }
            if (-not $seenIds.Add([string]$tid)) {
                throw "Duplicate test id '$tid' detected in $($mf.Name)"
            }
            $isIntTier = ($null -ne $tier) -and -not ($tier -is [bool]) -and (($tier -is [int]) -or ($tier -is [long]))
            if (-not $isIntTier -or ([int]$tier -notin @(1, 2, 3, 4))) {
                throw "Test '$tid' in $($mf.Name) has invalid 'tier': $tier"
            }
            $featList = To-StringArray $feat
            if ($featList.Count -eq 0) {
                throw "Test '$tid' in $($mf.Name) missing 'feature'"
            }
            if ([string]$mode -notin $validModes) {
                throw "Test '$tid' in $($mf.Name) has invalid 'mode': $mode"
            }
            $allTests.Add($t)
        }
    }
    return ,($allTests.ToArray())
}

function Should-RunTest {
    param($TestObj, [System.Collections.Generic.List[string]]$TierF, [System.Collections.Generic.List[string]]$FeatF, [System.Collections.Generic.List[string]]$IdF)
    if ($TierF.Count -gt 0 -and -not $TierF.Contains("all")) {
        if (([string](Get-Prop $TestObj "tier" "")) -notin $TierF) {
            return $false
        }
    }
    if ($FeatF.Count -gt 0) {
        $tFeats = @((To-StringArray (Get-Prop $TestObj "feature" $null)) | ForEach-Object { $_.ToUpperInvariant() })
        $matched = $false
        foreach ($ff in $FeatF) {
            if ($ff -in $tFeats) { $matched = $true; break }
        }
        if (-not $matched) { return $false }
    }
    if ($IdF.Count -gt 0) {
        $tid = [string](Get-Prop $TestObj "id" "")
        if ($tid -notin $IdF) { return $false }
    }
    return $true
}

function Stage-TestSource {
    param([string]$E2ERoot, [string]$RepoDir, [string]$RelSource, [string]$StageDir)
    if (-not (Test-Path $StageDir)) {
        New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
    }
    $candE2E = Join-Path $E2ERoot $RelSource
    $candRepo = Join-Path $RepoDir $RelSource
    $srcAbs = ""
    if (Test-Path $candE2E) {
        $srcAbs = (Resolve-Path $candE2E).Path
    } elseif (Test-Path $candRepo) {
        $srcAbs = (Resolve-Path $candRepo).Path
    } else {
        throw "Source file not found: $RelSource"
    }
    $fname = [System.IO.Path]::GetFileName($srcAbs)
    $stagedPath = Join-Path $StageDir $fname
    [System.IO.File]::Copy($srcAbs, $stagedPath, $true)
    return $stagedPath
}

function Add-OutputAssertions {
    param(
        [System.Collections.Generic.List[string]]$OutReasons,
        [string]$StdoutStr,
        [string]$StderrStr,
        $ExpectStdout,
        $ForbidStdout,
        $ForbidStderr,
        $ExpectCombined,
        $ExpectAnyCombined
    )
    $combined = $StdoutStr + "`n" + $StderrStr
    foreach ($s in (To-StringArray $ExpectStdout)) {
        if (-not $StdoutStr.Contains($s)) {
            $OutReasons.Add("Missing expected stdout substring: '$s'")
        }
    }
    foreach ($s in (To-StringArray $ForbidStdout)) {
        if ($StdoutStr.Contains($s)) {
            $OutReasons.Add("Found forbidden stdout substring: '$s'")
        }
    }
    foreach ($s in (To-StringArray $ForbidStderr)) {
        if ($StderrStr.Contains($s)) {
            $OutReasons.Add("Found forbidden stderr substring: '$s'")
        }
    }
    foreach ($s in (To-StringArray $ExpectCombined)) {
        if (-not $combined.Contains($s)) {
            $OutReasons.Add("Missing expected diagnostic substring: '$s'")
        }
    }
    $anyList = To-StringArray $ExpectAnyCombined
    if ($anyList.Count -gt 0) {
        $foundAny = $false
        $combLower = $combined.ToLowerInvariant()
        foreach ($s in $anyList) {
            if ($combLower.Contains($s.ToLowerInvariant())) {
                $foundAny = $true
                break
            }
        }
        if (-not $foundAny) {
            $OutReasons.Add("None of expected diagnostic markers matched: [$($anyList -join ', ')]")
        }
    }
}

Push-Location $RepoRoot
try {
    Write-Host "================================================================================"
    Write-Host "NinoLang E2E Test Harness (PowerShell)"
    Write-Host "Repository: $RepoRoot"
    Write-Host "================================================================================"

    $compResult = Invoke-E2EComplianceGate -RootDir $E2EDir -TmpDirPath $TmpRoot -Strict $StrictCompliance
    if ($compResult.Violations.Count -gt 0) {
        Write-Host "[e2e-compliance] FAIL ($($compResult.Violations.Count) violation(s) across $($compResult.FileCount) .nino files):"
        foreach ($v in $compResult.Violations) {
            Write-Host "  $v"
        }
        exit 1
    }
    Write-Host "[e2e-compliance] PASS ($($compResult.FileCount) .nino files checked)"

    $allManifestTests = Load-AndValidateManifests -ManifestFolder $ManifestDir
    $selectedTests = New-Object System.Collections.Generic.List[object]
    foreach ($t in $allManifestTests) {
        if (Should-RunTest -TestObj $t -TierF $TierFilters -FeatF $FeatureFilters -IdF $IdFilters) {
            $selectedTests.Add($t)
        }
    }

    if ($selectedTests.Count -eq 0) {
        Write-Host "No tests matched the specified filters."
        exit 1
    }

    $gccBin = Resolve-GccCompiler -IsWindowsHost $IsWin
    $ninocBin = Resolve-NinocCompiler -RepoDir $RepoRoot -TmpDirPath $TmpRoot -OverridePath $NinocOverride -AllowBootstrap $Bootstrap -GccPath $gccBin -IsWindowsHost $IsWin
    $exeExt = if ($IsWin) { ".exe" } else { "" }
    $linkLibs = if ($IsWin) {
        @("-lm", "-lgdi32", "-luser32", "-lbcrypt", "-lws2_32")
    } else {
        @("-lm", "-lpthread", "-ldl")
    }

    Write-Host "Compiler : $ninocBin"
    Write-Host "GCC      : $(if ($gccBin) { $gccBin } else { '(not found)' })"
    Write-Host "Selected : $($selectedTests.Count) test(s)"
    Write-Host "--------------------------------------------------------------------------------"

    $tierPass = @{ 1 = 0; 2 = 0; 3 = 0; 4 = 0 }
    $tierFail = @{ 1 = 0; 2 = 0; 3 = 0; 4 = 0 }
    $totalPass = 0
    $totalFail = 0

    foreach ($t in $selectedTests) {
        $tid = [string](Get-Prop $t "id")
        $tier = [int](Get-Prop $t "tier")
        $mode = [string](Get-Prop $t "mode")
        $srcRel = [string](Get-Prop $t "source" "")
        $flags = To-StringArray (Get-Prop $t "flags" $null)
        $runArgs = To-StringArray (Get-Prop $t "args" $null)
        $timeoutSec = [int](Get-Prop $t "timeout_sec" 30)
        $stdinText = Get-Prop $t "stdin" $null
        $safeId = $tid -replace '[^A-Za-z0-9_.-]', '_'
        $stageDir = Join-Path $TmpRoot $safeId

        if (Test-Path $stageDir) {
            Remove-Item -Path $stageDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

        $failReasons = New-Object System.Collections.Generic.List[string]
        $diagOutput = ""

        try {
            if ($mode -eq "build-run") {
                $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                $stem = [System.IO.Path]::GetFileNameWithoutExtension($staged)
                $binPath = Join-Path $stageDir ($stem + $exeExt)
                $buildArgs = @("build", $staged, "-o", $binPath) + $flags
                $bres = Invoke-ProcessBounded -FilePath $ninocBin -ArgList $buildArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                $diagOutput = "BUILD exit=$($bres.ExitCode)`n$($bres.Stdout)`n$($bres.Stderr)"
                if ($bres.TimedOut) {
                    $failReasons.Add("Build timed out after ${timeoutSec}s")
                } elseif ($bres.ExitCode -ne 0) {
                    $failReasons.Add("Build failed with exit $($bres.ExitCode)")
                } elseif (-not (Test-Path $binPath)) {
                    $failReasons.Add("Expected compiled binary not found: $binPath")
                } else {
                    foreach ($s in (To-StringArray (Get-Prop $t "expect_build_stdout" $null))) {
                        if (-not $bres.Stdout.Contains($s)) {
                            $failReasons.Add("Missing build stdout substring: '$s'")
                        }
                    }
                    $rres = Invoke-ProcessBounded -FilePath $binPath -ArgList $runArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec -StdinText $stdinText
                    $diagOutput += "`nRUN exit=$($rres.ExitCode)`n$($rres.Stdout)`n$($rres.Stderr)"
                    $expectNonzero = [bool](Get-Prop $t "expect_nonzero" $false)
                    $expExit = [int](Get-Prop $t "expect_exit" 0)
                    if ($rres.TimedOut) {
                        $failReasons.Add("Runtime execution timed out after ${timeoutSec}s")
                    } elseif ($expectNonzero) {
                        if ($rres.ExitCode -eq 0) { $failReasons.Add("Expected non-zero exit code, got 0") }
                    } elseif ($rres.ExitCode -ne $expExit) {
                        $failReasons.Add("Expected exit $expExit, got $($rres.ExitCode)")
                    }
                    Add-OutputAssertions -OutReasons $failReasons -StdoutStr $rres.Stdout -StderrStr $rres.Stderr `
                        -ExpectStdout (Get-Prop $t "expect_stdout" $null) `
                        -ForbidStdout (Get-Prop $t "forbid_stdout" $null) `
                        -ForbidStderr (Get-Prop $t "forbid_stderr" $null) `
                        -ExpectCombined $null -ExpectAnyCombined $null
                }
            }
            elseif ($mode -eq "run") {
                $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                $rArgs = @("run", $staged) + $flags
                $rres = Invoke-ProcessBounded -FilePath $ninocBin -ArgList $rArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec -StdinText $stdinText
                $diagOutput = "RUN exit=$($rres.ExitCode)`n$($rres.Stdout)`n$($rres.Stderr)"
                $expectNonzero = [bool](Get-Prop $t "expect_nonzero" $false)
                $expExit = [int](Get-Prop $t "expect_exit" 0)
                if ($rres.TimedOut) {
                    $failReasons.Add("Execution timed out after ${timeoutSec}s")
                } elseif ($expectNonzero) {
                    if ($rres.ExitCode -eq 0) { $failReasons.Add("Expected non-zero exit code, got 0") }
                } elseif ($rres.ExitCode -ne $expExit) {
                    $failReasons.Add("Expected exit $expExit, got $($rres.ExitCode)")
                }
                Add-OutputAssertions -OutReasons $failReasons -StdoutStr $rres.Stdout -StderrStr $rres.Stderr `
                    -ExpectStdout (Get-Prop $t "expect_stdout" $null) `
                    -ForbidStdout (Get-Prop $t "forbid_stdout" $null) `
                    -ForbidStderr (Get-Prop $t "forbid_stderr" $null) `
                    -ExpectCombined $null -ExpectAnyCombined $null
            }
            elseif ($mode -eq "compile-fail") {
                $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                $stem = [System.IO.Path]::GetFileNameWithoutExtension($staged)
                $binPath = Join-Path $stageDir ($stem + $exeExt)
                $buildArgs = @("build", $staged, "-o", $binPath) + $flags
                $bres = Invoke-ProcessBounded -FilePath $ninocBin -ArgList $buildArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                $diagOutput = "COMPILE-FAIL exit=$($bres.ExitCode)`n$($bres.Stdout)`n$($bres.Stderr)"
                if ($bres.TimedOut) {
                    $failReasons.Add("Compile timed out after ${timeoutSec}s")
                } elseif ($bres.ExitCode -eq 0) {
                    $failReasons.Add("Expected compilation failure (exit != 0), got exit 0")
                }
                $forbidBin = [bool](Get-Prop $t "forbid_binary" $true)
                if ($forbidBin -and (Test-Path $binPath)) {
                    $failReasons.Add("Expected no output binary on compile-fail, but found $binPath")
                }
                $forbidOutList = New-Object System.Collections.Generic.List[string]
                foreach ($fs in (To-StringArray (Get-Prop $t "forbid_stdout" $null))) {
                    if (-not $forbidOutList.Contains($fs)) { $forbidOutList.Add($fs) }
                }
                if ([bool](Get-Prop $t "require_frontend_reject" $false)) {
                    foreach ($marker in @("Semantic Check  : [", "Native Codegen", "BACKEND COMPILATION FAILED")) {
                        if (-not $forbidOutList.Contains($marker)) { $forbidOutList.Add($marker) }
                    }
                }
                Add-OutputAssertions -OutReasons $failReasons -StdoutStr $bres.Stdout -StderrStr $bres.Stderr `
                    -ExpectStdout (Get-Prop $t "expect_stdout" $null) `
                    -ForbidStdout $forbidOutList `
                    -ForbidStderr (Get-Prop $t "forbid_stderr" $null) `
                    -ExpectCombined (Get-Prop $t "expect_stderr_or_stdout" $null) `
                    -ExpectAnyCombined (Get-Prop $t "expect_any_stderr_or_stdout" $null)
            }
            elseif ($mode -eq "c11-audit") {
                $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                $stem = [System.IO.Path]::GetFileNameWithoutExtension($staged)
                $binPath = Join-Path $stageDir ($stem + $exeExt)
                $buildArgs = @("build", $staged, "-o", $binPath) + $flags
                $bres = Invoke-ProcessBounded -FilePath $ninocBin -ArgList $buildArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                $diagOutput = "BUILD exit=$($bres.ExitCode)`n$($bres.Stdout)`n$($bres.Stderr)"
                $emittedC = $staged + ".c"
                if ($bres.TimedOut) {
                    $failReasons.Add("Build timed out after ${timeoutSec}s")
                } elseif ($bres.ExitCode -ne 0) {
                    $failReasons.Add("Build failed with exit $($bres.ExitCode)")
                } elseif (-not (Test-Path $emittedC)) {
                    $failReasons.Add("Emitted C file not found: $emittedC")
                } else {
                    $cText = [System.IO.File]::ReadAllText($emittedC, [System.Text.Encoding]::UTF8)
                    $scanScope = [string](Get-Prop $t "c11_scan_scope" "generated")
                    $scanText = Get-CScanText -CSource $cText -Scope $scanScope

                    $forbidTokens = To-StringArray (Get-Prop $t "c11_forbid" $null)
                    if ($forbidTokens.Count -eq 0) {
                        $forbidTokens = To-StringArray (Get-Prop $t "forbid_c_tokens" $null)
                    }
                    if ($forbidTokens.Count -eq 0) {
                        $forbidTokens = @("__auto_type", "__typeof__", "({", "__asm__", "__uint128_t", "__sync_")
                    }
                    foreach ($tok in $forbidTokens) {
                        if (Test-C11TokenPresent -ScanText $scanText -Token $tok) {
                            $failReasons.Add("Forbidden GNU/non-C11 token '$tok' found in emitted C (scope=$scanScope)")
                        }
                    }

                    $doPedantic = [bool](Get-Prop $t "pedantic_c11_compile" (Get-Prop $t "expect_c11_compile" $true))
                    $execPath = $binPath
                    if ($doPedantic) {
                        if ([string]::IsNullOrWhiteSpace($gccBin)) {
                            $failReasons.Add("Pedantic C11 compile requested, but no GCC compiler found")
                        } else {
                            $pedBin = Join-Path $stageDir ($stem + "_pedantic" + $exeExt)
                            $pedArgs = @("-std=c11", "-pedantic-errors", "-Wall", "-Wextra")
                            if (($flags -contains "--strict-c11") -or ($flags -contains "-strict-c11")) {
                                $pedArgs += "-DNINO_STRICT_C11=1"
                            }
                            $pedArgs += @($emittedC, "-o", $pedBin) + $linkLibs
                            $pres = Invoke-ProcessBounded -FilePath $gccBin -ArgList $pedArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                            $diagOutput += "`nPEDANTIC-GCC exit=$($pres.ExitCode)`n$($pres.Stdout)`n$($pres.Stderr)"
                            if ($pres.TimedOut) {
                                $failReasons.Add("Pedantic GCC compile timed out after ${timeoutSec}s")
                            } elseif ($pres.ExitCode -ne 0 -or -not (Test-Path $pedBin)) {
                                $failReasons.Add("GCC -std=c11 -pedantic-errors failed (exit $($pres.ExitCode))")
                            } else {
                                $execPath = $pedBin
                            }
                        }
                    }

                    if ($failReasons.Count -eq 0 -and (Test-Path $execPath)) {
                        $rres = Invoke-ProcessBounded -FilePath $execPath -ArgList $runArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec -StdinText $stdinText
                        $diagOutput += "`nRUN exit=$($rres.ExitCode)`n$($rres.Stdout)`n$($rres.Stderr)"
                        $expExit = [int](Get-Prop $t "expect_exit" 0)
                        if ($rres.TimedOut) {
                            $failReasons.Add("Execution timed out after ${timeoutSec}s")
                        } elseif ($rres.ExitCode -ne $expExit) {
                            $failReasons.Add("Expected exit $expExit, got $($rres.ExitCode)")
                        }
                        Add-OutputAssertions -OutReasons $failReasons -StdoutStr $rres.Stdout -StderrStr $rres.Stderr `
                            -ExpectStdout (Get-Prop $t "expect_stdout" $null) `
                            -ForbidStdout (Get-Prop $t "forbid_stdout" $null) `
                            -ForbidStderr (Get-Prop $t "forbid_stderr" $null) `
                            -ExpectCombined $null -ExpectAnyCombined $null
                    }
                }
            }
            elseif ($mode -eq "verify-proof") {
                $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                $stem = [System.IO.Path]::GetFileNameWithoutExtension($staged)
                $binPath = Join-Path $stageDir ($stem + $exeExt)
                $buildArgs = @("build", $staged, "-o", $binPath) + $flags
                $bres = Invoke-ProcessBounded -FilePath $ninocBin -ArgList $buildArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                $diagOutput = "BUILD exit=$($bres.ExitCode)`n$($bres.Stdout)`n$($bres.Stderr)"
                if ($bres.TimedOut) {
                    $failReasons.Add("Build timed out after ${timeoutSec}s")
                } elseif ($bres.ExitCode -ne 0 -or -not (Test-Path $binPath)) {
                    $failReasons.Add("Proof build failed with exit $($bres.ExitCode)")
                } else {
                    foreach ($s in (To-StringArray (Get-Prop $t "expect_build_stdout" $null))) {
                        if (-not $bres.Stdout.Contains($s)) {
                            $failReasons.Add("Missing build stdout substring: '$s'")
                        }
                    }
                    foreach ($s in (To-StringArray (Get-Prop $t "forbid_stdout" $null))) {
                        if ($bres.Stdout.Contains($s)) {
                            $failReasons.Add("Found forbidden build stdout substring: '$s'")
                        }
                    }
                    $vres = Invoke-ProcessBounded -FilePath $binPath -ArgList @("--verify-proof") -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                    $diagOutput += "`nVERIFY-PROOF exit=$($vres.ExitCode)`n$($vres.Stdout)`n$($vres.Stderr)"
                    $expExit = [int](Get-Prop $t "expect_exit" 0)
                    if ($vres.TimedOut) {
                        $failReasons.Add("--verify-proof timed out after ${timeoutSec}s")
                    } elseif ($vres.ExitCode -ne $expExit) {
                        $failReasons.Add("--verify-proof expected exit $expExit, got $($vres.ExitCode)")
                    }
                    Add-OutputAssertions -OutReasons $failReasons -StdoutStr $vres.Stdout -StderrStr $vres.Stderr `
                        -ExpectStdout (Get-Prop $t "expect_stdout" $null) `
                        -ForbidStdout (Get-Prop $t "forbid_stdout" $null) `
                        -ForbidStderr (Get-Prop $t "forbid_stderr" $null) `
                        -ExpectCombined $null -ExpectAnyCombined $null

                    $doTamper = [bool](Get-Prop $t "tamper_test" $false)
                    if ($doTamper) {
                        $emittedC = $staged + ".c"
                        if (-not (Test-Path $emittedC)) {
                            $failReasons.Add("Tamper test requires emitted C file $emittedC")
                        } elseif ([string]::IsNullOrWhiteSpace($gccBin)) {
                            $failReasons.Add("Tamper test requires GCC compiler")
                        } else {
                            $cText = [System.IO.File]::ReadAllText($emittedC, [System.Text.Encoding]::UTF8)
                            $tamperRe = [regex]'(?s)(_NINO_PCC_SMT_SPEC\s*\[\s*\]\s*=\s*\{\s*)(\d+)'
                            $m = $tamperRe.Match($cText)
                            if (-not $m.Success) {
                                $failReasons.Add("Could not locate _NINO_PCC_SMT_SPEC byte array in $emittedC")
                            } else {
                                $origByte = [int]$m.Groups[2].Value
                                $newByte = if ($origByte -eq 35) { 36 } else { 35 }
                                $tamperedC = $tamperRe.Replace($cText, ($m.Groups[1].Value + $newByte), 1)
                                $tamperCPath = $staged + ".tamper.c"
                                $tamperBin = Join-Path $stageDir ($stem + "_tamper" + $exeExt)
                                $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                                [System.IO.File]::WriteAllText($tamperCPath, $tamperedC, $utf8NoBom)
                                $tGccArgs = @("-std=c11", "-O2", "-w", $tamperCPath, "-o", $tamperBin) + $linkLibs
                                $tcc = Invoke-ProcessBounded -FilePath $gccBin -ArgList $tGccArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                                if ($tcc.TimedOut -or $tcc.ExitCode -ne 0 -or -not (Test-Path $tamperBin)) {
                                    $failReasons.Add("Compiling tampered C fixture failed (exit $($tcc.ExitCode))")
                                } else {
                                    $tvres = Invoke-ProcessBounded -FilePath $tamperBin -ArgList @("--verify-proof") -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                                    $diagOutput += "`nTAMPER-VERIFY exit=$($tvres.ExitCode)`n$($tvres.Stdout)`n$($tvres.Stderr)"
                                    if ($tvres.TimedOut) {
                                        $failReasons.Add("Tampered --verify-proof timed out")
                                    } elseif ($tvres.ExitCode -eq 0) {
                                        $failReasons.Add("Tampered binary --verify-proof unexpectedly exited 0")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            elseif ($mode -eq "binary-inspect") {
                $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                $stem = [System.IO.Path]::GetFileNameWithoutExtension($staged)
                $binPath = Join-Path $stageDir ($stem + $exeExt)
                $buildArgs = @("build", $staged, "-o", $binPath) + $flags
                $bres = Invoke-ProcessBounded -FilePath $ninocBin -ArgList $buildArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec
                $diagOutput = "BUILD exit=$($bres.ExitCode)`n$($bres.Stdout)`n$($bres.Stderr)"
                if ($bres.TimedOut) {
                    $failReasons.Add("Build timed out after ${timeoutSec}s")
                } elseif ($bres.ExitCode -ne 0 -or -not (Test-Path $binPath)) {
                    $failReasons.Add("Build failed with exit $($bres.ExitCode)")
                } else {
                    $binBytes = [System.IO.File]::ReadAllBytes($binPath)
                    foreach ($forbidStr in (To-StringArray (Get-Prop $t "rodata_forbid" $null))) {
                        $needle = [System.Text.Encoding]::UTF8.GetBytes($forbidStr)
                        if (Test-BytesContain -Haystack $binBytes -Needle $needle) {
                            $failReasons.Add("Forbidden plaintext bytes found in compiled binary: '$forbidStr'")
                        }
                    }
                    foreach ($reqStr in (To-StringArray (Get-Prop $t "rodata_require" $null))) {
                        $needle = [System.Text.Encoding]::UTF8.GetBytes($reqStr)
                        if (-not (Test-BytesContain -Haystack $binBytes -Needle $needle)) {
                            $failReasons.Add("Required bytes missing from compiled binary: '$reqStr'")
                        }
                    }
                    $expStdoutList = To-StringArray (Get-Prop $t "expect_stdout" $null)
                    $runBinary = [bool](Get-Prop $t "run_binary" ($expStdoutList.Count -gt 0))
                    if ($runBinary) {
                        $rres = Invoke-ProcessBounded -FilePath $binPath -ArgList $runArgs -WorkDir $RepoRoot -TimeoutSec $timeoutSec -StdinText $stdinText
                        $diagOutput += "`nRUN exit=$($rres.ExitCode)`n$($rres.Stdout)`n$($rres.Stderr)"
                        $expExit = [int](Get-Prop $t "expect_exit" 0)
                        if ($rres.TimedOut) {
                            $failReasons.Add("Binary execution timed out after ${timeoutSec}s")
                        } elseif ($rres.ExitCode -ne $expExit) {
                            $failReasons.Add("Expected exit $expExit, got $($rres.ExitCode)")
                        }
                        Add-OutputAssertions -OutReasons $failReasons -StdoutStr $rres.Stdout -StderrStr $rres.Stderr `
                            -ExpectStdout $expStdoutList `
                            -ForbidStdout (Get-Prop $t "forbid_stdout" $null) `
                            -ForbidStderr (Get-Prop $t "forbid_stderr" $null) `
                            -ExpectCombined $null -ExpectAnyCombined $null
                    }
                }
            }
            elseif ($mode -eq "command-check") {
                $staged = ""
                if (-not [string]::IsNullOrWhiteSpace($srcRel)) {
                    $candE2E = Join-Path $E2EDir $srcRel
                    $candRepo = Join-Path $RepoRoot $srcRel
                    if (Test-Path $candE2E) {
                        $staged = Stage-TestSource -E2ERoot $E2EDir -RepoDir $RepoRoot -RelSource $srcRel -StageDir $stageDir
                    } elseif (Test-Path $candRepo) {
                        $staged = (Resolve-Path $candRepo).Path
                    } else {
                        $staged = $srcRel
                    }
                }
                $cmdSteps = Get-Prop $t "commands" $null
                if ($null -eq $cmdSteps) {
                    $stepArgs = @()
                    if (-not [string]::IsNullOrWhiteSpace($staged)) {
                        $stepArgs += $staged
                    }
                    $stepArgs += $runArgs
                    $stepObj = [PSCustomObject]@{
                        cmd = "ninoc"
                        args = $stepArgs
                        stdin = $stdinText
                        expect_exit = Get-Prop $t "expect_exit" 0
                        expect_nonzero = Get-Prop $t "expect_nonzero" $false
                        expect_stdout = Get-Prop $t "expect_stdout" $null
                        forbid_stdout = Get-Prop $t "forbid_stdout" $null
                        forbid_stderr = Get-Prop $t "forbid_stderr" $null
                        expect_stderr_or_stdout = Get-Prop $t "expect_stderr_or_stdout" $null
                        expect_any_stderr_or_stdout = Get-Prop $t "expect_any_stderr_or_stdout" $null
                        timeout_sec = $timeoutSec
                    }
                    $cmdSteps = @($stepObj)
                }

                $stepIdx = 0
                foreach ($step in @($cmdSteps)) {
                    $stepIdx++
                    $cmdSpec = [string](Get-Prop $step "cmd" "ninoc")
                    $exeToRun = switch ($cmdSpec) {
                        "" { $ninocBin }
                        "ninoc" { $ninocBin }
                        "{ninoc}" { $ninocBin }
                        "{gcc}" { $gccBin }
                        default { $cmdSpec }
                    }
                    $rawStepArgs = To-StringArray (Get-Prop $step "args" $null)
                    $resolvedArgs = @()
                    foreach ($ra in $rawStepArgs) {
                        $sub = $ra.Replace("{ninoc}", $ninocBin).Replace("{gcc}", $gccBin).Replace("{staged}", $staged).Replace("{source}", $srcRel).Replace("{tmp_dir}", $stageDir).Replace("{repo_root}", $RepoRoot)
                        $resolvedArgs += $sub
                    }
                    $stepTimeout = [int](Get-Prop $step "timeout_sec" $timeoutSec)
                    $stepStdin = Get-Prop $step "stdin" $null
                    $cres = Invoke-ProcessBounded -FilePath $exeToRun -ArgList $resolvedArgs -WorkDir $RepoRoot -TimeoutSec $stepTimeout -StdinText $stepStdin
                    $diagOutput += "`nSTEP $stepIdx ($exeToRun $($resolvedArgs -join ' ')) exit=$($cres.ExitCode)`n$($cres.Stdout)`n$($cres.Stderr)"
                    $stepNonzero = [bool](Get-Prop $step "expect_nonzero" $false)
                    $stepExpExit = [int](Get-Prop $step "expect_exit" 0)
                    if ($cres.TimedOut) {
                        $failReasons.Add("Command step $stepIdx timed out after ${stepTimeout}s")
                    } elseif ($stepNonzero) {
                        if ($cres.ExitCode -eq 0) { $failReasons.Add("Command step $stepIdx expected non-zero exit, got 0") }
                    } elseif ($cres.ExitCode -ne $stepExpExit) {
                        $failReasons.Add("Command step $stepIdx expected exit $stepExpExit, got $($cres.ExitCode)")
                    }
                    Add-OutputAssertions -OutReasons $failReasons -StdoutStr $cres.Stdout -StderrStr $cres.Stderr `
                        -ExpectStdout (Get-Prop $step "expect_stdout" $null) `
                        -ForbidStdout (Get-Prop $step "forbid_stdout" $null) `
                        -ForbidStderr (Get-Prop $step "forbid_stderr" $null) `
                        -ExpectCombined (Get-Prop $step "expect_stderr_or_stdout" $null) `
                        -ExpectAnyCombined (Get-Prop $step "expect_any_stderr_or_stdout" $null)
                }
            }
        }
        catch {
            $failReasons.Add("Runner exception: $($_.Exception.Message)")
        }
        finally {
            if (Test-Path $stageDir) {
                Remove-Item -Path $stageDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        if ($failReasons.Count -eq 0) {
            $totalPass++
            $tierPass[$tier] = $tierPass[$tier] + 1
            Write-Host "[PASS] $tid (T$tier, $mode)"
            if ($VerboseMode -and $diagOutput.Length -gt 0) {
                Write-Host $diagOutput
            }
        } else {
            $totalFail++
            $tierFail[$tier] = $tierFail[$tier] + 1
            Write-Host "[FAIL] $tid (T$tier, $mode)"
            foreach ($fr in $failReasons) {
                Write-Host "       - $fr"
            }
            if ($VerboseMode -and $diagOutput.Length -gt 0) {
                Write-Host $diagOutput
            }
        }
    }

    Write-Host "--------------------------------------------------------------------------------"
    Write-Host ("Summary: PASS={0} FAIL={1} TOTAL={2}" -f $totalPass, $totalFail, ($totalPass + $totalFail))
    foreach ($tk in @(1, 2, 3, 4)) {
        $tp = $tierPass[$tk]
        $tf = $tierFail[$tk]
        if (($tp + $tf) -gt 0) {
            Write-Host ("  Tier {0}: PASS={1} FAIL={2}" -f $tk, $tp, $tf)
        }
    }
    Write-Host "================================================================================"

    if ($totalFail -gt 0) {
        exit 1
    }
    exit 0
}
finally {
    if (Test-Path $TmpRoot) {
        Remove-Item -Path $TmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Pop-Location
}

Set-StrictMode -Version Latest

function Get-RepoRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-WindowsDepsRoot {
    return (Join-Path (Get-RepoRoot) 'windows-deps')
}

function Get-WindowsRuntimeRoot {
    return (Join-Path $PSScriptRoot 'windows-runtime')
}

function Get-NamecoinDataDir {
    if ($env:NCP11_WINDOWS_NAMECOIN_DATA_DIR) {
        return $env:NCP11_WINDOWS_NAMECOIN_DATA_DIR
    }

    return (Join-Path $env:TEMP 'ncp11-namecoin-data')
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Reset-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }

    New-Item -ItemType Directory -Path $Path | Out-Null
}

function Write-AsciiFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        Ensure-Directory -Path $parent
    }

    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::ASCII)
}

function Quote-ProcessArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Argument
    )

    if ($Argument.Length -eq 0) {
        return '""'
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $escaped = $Argument -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'

    return '"' + $escaped + '"'
}

function ConvertTo-ProcessArgumentString {
    param(
        [string[]]$ArgumentList = @()
    )

    return (($ArgumentList | ForEach-Object { Quote-ProcessArgument -Argument $_ }) -join ' ')
}

function Start-NativeProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory = (Get-Location).Path,
        [string]$StdOutPath,
        [string]$StdErrPath
    )

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.WorkingDirectory = $WorkingDirectory
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true

    $redirectOutput = $PSBoundParameters.ContainsKey('StdOutPath') -or $PSBoundParameters.ContainsKey('StdErrPath')
    if ($redirectOutput) {
        $stdoutTarget = if ($PSBoundParameters.ContainsKey('StdOutPath')) { $StdOutPath } else { 'NUL' }
        $stderrTarget = if ($PSBoundParameters.ContainsKey('StdErrPath')) { $StdErrPath } else { 'NUL' }
        $commandString = Quote-ProcessArgument -Argument $FilePath
        $quotedArguments = ConvertTo-ProcessArgumentString -ArgumentList $ArgumentList
        if ($quotedArguments) {
            $commandString += ' ' + $quotedArguments
        }
        $commandString += ' 1>' + (Quote-ProcessArgument -Argument $stdoutTarget)
        $commandString += ' 2>' + (Quote-ProcessArgument -Argument $stderrTarget)

        $processInfo.FileName = $env:ComSpec
        $processInfo.Arguments = '/d /s /c "' + $commandString + '"'
    } else {
        $processInfo.FileName = $FilePath
        $processInfo.Arguments = ConvertTo-ProcessArgumentString -ArgumentList $ArgumentList
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    [void]$process.Start()

    return $process
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$AllowFailure,
        [string]$WorkingDirectory = (Get-Location).Path,
        [string]$InputText,
        [int]$TimeoutMilliseconds = 0
    )

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $FilePath
    $processInfo.Arguments = ConvertTo-ProcessArgumentString -ArgumentList $ArgumentList
    $processInfo.WorkingDirectory = $WorkingDirectory
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.RedirectStandardInput = $PSBoundParameters.ContainsKey('InputText')

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    [void]$process.Start()

    if ($PSBoundParameters.ContainsKey('InputText')) {
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = $false

    if ($TimeoutMilliseconds -gt 0 -and -not $process.WaitForExit($TimeoutMilliseconds)) {
        $timedOut = $true
        try {
            $process.Kill()
        } catch {
        }
    }

    $process.WaitForExit()
    [System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask))

    $stdout = $stdoutTask.Result.TrimEnd()
    $stderr = $stderrTask.Result.TrimEnd()
    $output = ($stdout + $stderr).TrimEnd()
    $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }

    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "Command failed ($exitCode): $FilePath $($ArgumentList -join ' ')`n$output"
    }

    return [pscustomobject]@{
        StdOut   = $stdout
        StdErr   = $stderr
        Output   = $output
        ExitCode = $exitCode
        TimedOut = $timedOut
    }
}

function Resolve-BinaryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string[]]$FallbackPaths = @(),
        [switch]$PreferFallbackPaths
    )

    if ($PreferFallbackPaths) {
        foreach ($fallbackPath in $FallbackPaths) {
            if ($fallbackPath -and (Test-Path -LiteralPath $fallbackPath)) {
                return $fallbackPath
            }
        }
    }

    $depsRoot = Get-WindowsDepsRoot
    if (Test-Path -LiteralPath $depsRoot) {
        $dependencyMatch = Get-ChildItem -Path $depsRoot -Recurse -File -Filter $Name -ErrorAction SilentlyContinue |
            Sort-Object -Property FullName |
            Select-Object -First 1
        if ($null -ne $dependencyMatch) {
            return $dependencyMatch.FullName
        }
    }

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        if ($command.Source) {
            return $command.Source
        }

        if ($command.Path) {
            return $command.Path
        }
    }

    foreach ($fallbackPath in $FallbackPaths) {
        if ($fallbackPath -and (Test-Path -LiteralPath $fallbackPath)) {
            return $fallbackPath
        }
    }

    throw "Unable to locate required executable '$Name'."
}

function Wait-ForTcpPort {
    param(
        [string]$HostName = '127.0.0.1',
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [int]$TimeoutSeconds = 60,
        [string]$Description = ''
    )

    if (-not $Description) {
        $Description = "$HostName`:$Port"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $asyncResult = $client.BeginConnect($HostName, $Port, $null, $null)
            if ($asyncResult.AsyncWaitHandle.WaitOne(1000)) {
                $client.EndConnect($asyncResult)
                return
            }
        } catch {
        } finally {
            $client.Dispose()
        }

        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for $Description"
}

function Stop-ProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $taskkill = Get-Command taskkill.exe -ErrorAction SilentlyContinue
    if ($null -ne $taskkill) {
        & $taskkill.Source /PID $ProcessId /T /F | Out-Null
    } else {
        Stop-Process -Id $ProcessId -Force
    }
}

function Stop-ProcessIfRunning {
    param(
        [AllowNull()]
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if (-not $Process.HasExited) {
            Stop-ProcessTree -ProcessId $Process.Id
            $Process.WaitForExit(10000) | Out-Null
        }
    } catch {
    } finally {
        $Process.Dispose()
    }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\windows-testlib.ps1"

$script:RepoRoot = Get-RepoRoot
Set-Location -LiteralPath $script:RepoRoot
$script:NamecoinCli = Resolve-BinaryPath -Name 'namecoin-cli.exe'
$script:OpenSslBinary = Resolve-BinaryPath -Name 'openssl.exe' -FallbackPaths @(
    'C:\ProgramData\chocolatey\bin\openssl.exe',
    "$env:ProgramFiles\OpenSSL\bin\openssl.exe",
    "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe",
    "${env:ProgramFiles(x86)}\OpenSSL\bin\openssl.exe",
    "${env:ProgramFiles(x86)}\OpenSSL-Win32\bin\openssl.exe",
    "$env:ProgramFiles\Git\usr\bin\openssl.exe",
    "$env:ProgramFiles\Git\mingw64\bin\openssl.exe"
)
$script:CurlBinary = Resolve-BinaryPath -Name 'curl.exe' -FallbackPaths @(
    "$env:SystemRoot\System32\curl.exe",
    "$env:ProgramFiles\Git\mingw64\bin\curl.exe",
    "${env:ProgramFiles(x86)}\Git\mingw64\bin\curl.exe"
) -PreferFallbackPaths
$script:FirefoxBinary = Resolve-BinaryPath -Name 'firefox.exe' -FallbackPaths @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
)
$script:Ncp11Dll = Resolve-BinaryPath -Name 'ncp11.dll'
$script:NamecoinDataDir = Get-NamecoinDataDir
$script:BitcoinCliArgs = @(
    "-datadir=$script:NamecoinDataDir",
    '-rpcuser=doggman',
    '-rpcpassword=donkey',
    '-rpcport=18554',
    '-regtest'
)
$script:AiaTestIp = '127.127.127.127'
$script:AiaTestUrl = "http://$script:AiaTestIp"
$script:TestTempDir = Join-Path $env:TEMP ('ncp11-functional-' + [Guid]::NewGuid().ToString('N'))
$script:Children = @()
$script:Services = @()
$script:LogDir = Join-Path (Get-WindowsRuntimeRoot) 'service-logs'
$script:HttpsServerProcess = $null
$script:HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$script:HostsMarkerBegin = '# BEGIN ncp11 functional tests'
$script:HostsMarkerEnd = '# END ncp11 functional tests'
$script:TestFailed = $false

function Invoke-NamecoinCliText {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    return (Invoke-NativeCommand -FilePath $script:NamecoinCli -ArgumentList ($script:BitcoinCliArgs + $Arguments)).Output.Trim()
}

function Invoke-NamecoinCliJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    return (Invoke-NamecoinCliText -Arguments $Arguments | ConvertFrom-Json)
}

function Invoke-Curl {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $baseArguments = @('--silent', '--show-error', '--fail', '--connect-timeout', '5', '--max-time', '20', '--noproxy', '*')
    return (Invoke-NativeCommand -FilePath $script:CurlBinary -ArgumentList ($baseArguments + $Arguments) -AllowFailure:$AllowFailure)
}

function Invoke-OpenSsl {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$InputText
    )

    if ($PSBoundParameters.ContainsKey('InputText')) {
        return (Invoke-NativeCommand -FilePath $script:OpenSslBinary -ArgumentList $Arguments -InputText $InputText)
    }

    return (Invoke-NativeCommand -FilePath $script:OpenSslBinary -ArgumentList $Arguments)
}

function ConvertTo-Base64File {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
}

function ConvertTo-Base64UrlFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (ConvertTo-Base64File -Path $Path).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-Blocks {
    param([Parameter(Mandatory = $true)][int]$Count)
    $address = Invoke-NamecoinCliText -Arguments @('getnewaddress')
    Invoke-NamecoinCliText -Arguments @('generatetoaddress', $Count.ToString(), $address) | Out-Null
}

function Wait-ForNamecoinWalletBalance {
    $deadline = (Get-Date).AddSeconds(120)
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    while ((Get-Date) -lt $deadline) {
        try {
            $balanceText = Invoke-NamecoinCliText -Arguments @('getbalance')
            if ($balanceText -and ([decimal]::Parse($balanceText, $culture) -ge 1)) {
                return
            }
        } catch {
        }

        Start-Sleep -Seconds 1
    }

    throw 'Timed out waiting for Namecoin wallet balance'
}

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)][string]$Haystack,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$ErrorMessage
    )

    if ($Haystack -notlike "*$Needle*") {
        Write-Host $Haystack
        throw $ErrorMessage
    }
}

function Register-NamecoinName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Write-Host "Pre-register $Name"
    $nameNew = Invoke-NamecoinCliJson -Arguments @('name_new', $Name)
    Write-Host "Wait for $Name pre-registration to mature"
    New-Blocks -Count 12
    Write-Host "Register $Name"
    Invoke-NamecoinCliText -Arguments @('name_firstupdate', $Name, $nameNew[1], $nameNew[0]) | Out-Null
    Write-Host "Wait for $Name registration to confirm"
    New-Blocks -Count 1
    Write-Host "Update $Name"
    Invoke-NamecoinCliText -Arguments @('name_update', $Name, $Value) | Out-Null
    Write-Host "Wait for $Name update to confirm"
    New-Blocks -Count 1
}

function New-LeafCert {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$ParentCaPath,
        [Parameter(Mandatory = $true)][string]$ParentKeyPath,
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$CsrPath,
        [Parameter(Mandatory = $true)][string]$CertPath,
        [Parameter(Mandatory = $true)][string]$ExtPath,
        [Parameter(Mandatory = $true)][string]$SerialPath
    )

    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $KeyPath) | Out-Null
    Invoke-OpenSsl -Arguments @('req', '-new', '-key', $KeyPath, '-subj', "/CN=$Domain", '-out', $CsrPath) | Out-Null

    $leafExt = @"
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$Domain
"@
    Write-AsciiFile -Path $ExtPath -Content $leafExt

    Invoke-OpenSsl -Arguments @('x509', '-req', '-in', $CsrPath, '-CA', $ParentCaPath, '-CAkey', $ParentKeyPath, '-CAcreateserial', '-CAserial', $SerialPath, '-out', $CertPath, '-days', '3650', '-sha256', '-extfile', $ExtPath, '-extensions', 'ext') | Out-Null
}

function New-SelfSignedLeafCert {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$CertPath
    )

    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $KeyPath) | Out-Null
    $config = @"
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no

[dn]
CN=$Domain

[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$Domain
"@
    Invoke-OpenSsl -Arguments @('req', '-new', '-x509', '-key', $KeyPath, '-subj', "/CN=$Domain", '-out', $CertPath, '-days', '3650', '-sha256', '-extensions', 'ext', '-config', '-') -InputText $config | Out-Null
}

function Start-HttpsServer {
    param(
        [Parameter(Mandatory = $true)][string]$CertPath,
        [Parameter(Mandatory = $true)][string]$KeyPath
    )

    Stop-ProcessIfRunning -Process $script:HttpsServerProcess
    $docRoot = Join-Path $script:TestTempDir 'https-docroot'
    $stdoutLog = Join-Path $script:TestTempDir 'https-server.stdout.log'
    $stderrLog = Join-Path $script:TestTempDir 'https-server.stderr.log'
    Ensure-Directory -Path $docRoot
    Write-AsciiFile -Path (Join-Path $docRoot 'index.html') -Content '<!DOCTYPE html><html><body>Namecoin ncp11 local TLS test</body></html>'

    $script:HttpsServerProcess = Start-NativeProcess -FilePath $script:OpenSslBinary -ArgumentList @('s_server', '-accept', '4443', '-cert', $CertPath, '-key', $KeyPath, '-WWW') -WorkingDirectory $docRoot -StdOutPath $stdoutLog -StdErrPath $stderrLog
    Start-Sleep -Seconds 2
    if ($script:HttpsServerProcess.HasExited) {
        Get-Content -LiteralPath $stdoutLog -ErrorAction SilentlyContinue
        Get-Content -LiteralPath $stderrLog -ErrorAction SilentlyContinue
        throw "Local HTTPS server failed to start with $CertPath"
    }
}

function Get-Ncp11LogPaths {
    $paths = @(
        (Join-Path $env:APPDATA 'ncp11.log'),
        (Join-Path $script:RepoRoot 'ncp11.log'),
        (Join-Path $env:APPDATA 'pkcs11mod.log'),
        (Join-Path $script:RepoRoot 'pkcs11mod.log')
    )
    if ($env:LOCALAPPDATA) {
        $paths += (Join-Path $env:LOCALAPPDATA 'ncp11.log')
    }
    return $paths
}

function Clear-Ncp11Logs {
    foreach ($path in Get-Ncp11LogPaths) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Assert-Ncp11Log {
    param([Parameter(Mandatory = $true)][ValidateSet('present', 'missing')][string]$Desired)

    $present = $false
    foreach ($path in Get-Ncp11LogPaths) {
        if (Test-Path -LiteralPath $path) {
            $present = $true
        }
    }
    Clear-Ncp11Logs

    if (($Desired -eq 'present') -ne $present) {
        throw "Log test failed; wanted $Desired"
    }
}

function Remove-TestHosts {
    if (-not (Test-Path -LiteralPath $script:HostsPath)) {
        return
    }

    $content = Get-Content -LiteralPath $script:HostsPath -Raw
    $pattern = "(?ms)\r?\n?$([regex]::Escape($script:HostsMarkerBegin)).*?$([regex]::Escape($script:HostsMarkerEnd))\r?\n?"
    $cleaned = [regex]::Replace($content, $pattern, "`r`n")
    [System.IO.File]::WriteAllText($script:HostsPath, $cleaned)
}

function Add-TestHosts {
    param([Parameter(Mandatory = $true)][string[]]$Domains)

    Remove-TestHosts
    $content = Get-Content -LiteralPath $script:HostsPath -Raw
    $block = @($script:HostsMarkerBegin, "127.0.0.1 $($Domains -join ' ')", $script:HostsMarkerEnd) -join "`r`n"
    [System.IO.File]::WriteAllText($script:HostsPath, ($content.TrimEnd() + "`r`n" + $block + "`r`n"))
}

function Set-FirefoxNcp11Policy {
    $firefoxRoot = Split-Path -Parent $script:FirefoxBinary
    $distributionDir = Join-Path $firefoxRoot 'distribution'
    Ensure-Directory -Path $distributionDir
    $escapedPath = $script:Ncp11Dll.Replace('\', '\\')
    $policy = '{"policies":{"SecurityDevices":{"Namecoin Certificate Trust":"' + $escapedPath + '"}}}'
    Write-AsciiFile -Path (Join-Path $distributionDir 'policies.json') -Content $policy
}

function Clear-FirefoxNcp11Policy {
    $firefoxRoot = Split-Path -Parent $script:FirefoxBinary
    $policyPath = Join-Path (Join-Path $firefoxRoot 'distribution') 'policies.json'
    if (Test-Path -LiteralPath $policyPath) {
        Remove-Item -LiteralPath $policyPath -Force
    }
}

function Invoke-Firefox {
    param([Parameter(Mandatory = $true)][string]$HostPort)

    $profileDir = Join-Path $script:TestTempDir ('firefox-profile-' + [Guid]::NewGuid().ToString('N'))
    $screenshotPath = Join-Path $script:TestTempDir ('firefox-' + [Guid]::NewGuid().ToString('N') + '.png')
    Ensure-Directory -Path $profileDir
    $result = Invoke-NativeCommand -FilePath $script:FirefoxBinary -ArgumentList @('-profile', $profileDir, '--headless', '--screenshot', $screenshotPath, "https://$HostPort/") -AllowFailure -TimeoutMilliseconds 60000
    $success = ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $screenshotPath))
    Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $screenshotPath -Force -ErrorAction SilentlyContinue

    return [pscustomobject]@{
        Success = $success
        Output  = $result.Output
    }
}

function Assert-FirefoxConnect {
    param(
        [Parameter(Mandatory = $true)][string]$HostPort,
        [Parameter(Mandatory = $true)][bool]$ShouldSucceed
    )

    $result = Invoke-Firefox -HostPort $HostPort
    if ($result.Success -ne $ShouldSucceed) {
        Write-Host $result.Output
        throw "Firefox TLS test failed for $HostPort"
    }
}

function Start-ChildProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    Ensure-Directory -Path $script:LogDir
    $stdoutLog = Join-Path $script:LogDir "$Name.stdout.log"
    $stderrLog = Join-Path $script:LogDir "$Name.stderr.log"
    $process = Start-NativeProcess -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $script:RepoRoot -StdOutPath $stdoutLog -StdErrPath $stderrLog
    $script:Children += [pscustomobject]@{ Name = $Name; Proc = $process; StdOut = $stdoutLog; StdErr = $stderrLog }
    return $process
}

function Start-ChildService {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )

    $scBinary = Resolve-BinaryPath -Name 'sc.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\sc.exe')) -PreferFallbackPaths
    $binPath = ConvertTo-ProcessArgumentString -ArgumentList @($BinaryPath)
    if ($ArgumentList.Count -gt 0) {
        $binPath += ' ' + (ConvertTo-ProcessArgumentString -ArgumentList $ArgumentList)
    }

    foreach ($cleanupArgs in @(@('stop', $Name), @('delete', $Name))) {
        Invoke-NativeCommand -FilePath $scBinary -ArgumentList $cleanupArgs -AllowFailure | Out-Null
    }

    Start-Sleep -Seconds 1
    Invoke-NativeCommand -FilePath $scBinary -ArgumentList @('create', $Name, 'binPath=', $binPath, 'start=', 'demand') | Out-Null
    Invoke-NativeCommand -FilePath $scBinary -ArgumentList @('start', $Name) | Out-Null
    $script:Services += [pscustomobject]@{ Name = $Name; ScBinary = $scBinary }
}

function Stop-Children {
    for ($index = $script:Services.Count - 1; $index -ge 0; $index--) {
        $entry = $script:Services[$index]
        Invoke-NativeCommand -FilePath $entry.ScBinary -ArgumentList @('stop', $entry.Name) -AllowFailure | Out-Null
        Start-Sleep -Seconds 1
        Invoke-NativeCommand -FilePath $entry.ScBinary -ArgumentList @('delete', $entry.Name) -AllowFailure | Out-Null
    }

    for ($index = $script:Children.Count - 1; $index -ge 0; $index--) {
        Stop-ProcessIfRunning -Process $script:Children[$index].Proc
    }
}

function Dump-ServiceLogs {
    foreach ($entry in $script:Children) {
        foreach ($path in @($entry.StdOut, $entry.StdErr)) {
            if (Test-Path -LiteralPath $path) {
                $content = Get-Content -LiteralPath $path -Raw
                if ($content) {
                    Write-Host "===== $($entry.Name): $path ====="
                    Write-Host $content.TrimEnd()
                }
            }
        }
    }

    Get-ChildItem -Path $script:LogDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*.service.log' } |
        ForEach-Object {
            $content = Get-Content -LiteralPath $_.FullName -Raw
            if ($content) {
                Write-Host "===== $($_.Name) ====="
                Write-Host $content.TrimEnd()
            }
        }
}

function Start-TestServices {
    Reset-Directory -Path $script:LogDir
    Reset-Directory -Path (Join-Path (Get-WindowsRuntimeRoot) 'encaya')
    $powershellBinary = Resolve-BinaryPath -Name 'powershell.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')) -PreferFallbackPaths
    $unboundBinary = Resolve-BinaryPath -Name 'unbound.exe' -FallbackPaths @('C:\Program Files\Unbound\unbound.exe') -PreferFallbackPaths
    $ncdnsBinary = Resolve-BinaryPath -Name 'ncdns.exe'
    $encayagenBinary = Resolve-BinaryPath -Name 'encayagen.exe'
    $encayaBinary = Resolve-BinaryPath -Name 'encaya.exe'

    Start-ChildProcess -Name 'bitcoind' -FilePath $powershellBinary -ArgumentList @('-NoLogo', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'run_bitcoind.ps1')) | Out-Null
    Wait-ForTcpPort -Port 18554 -TimeoutSeconds 120 -Description 'Namecoin Core RPC'

    foreach ($service in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*unbound*' -or $_.DisplayName -like '*unbound*' })) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($process in @(Get-Process -Name 'unbound' -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }

    Start-ChildProcess -Name 'unbound' -FilePath $unboundBinary -ArgumentList @('-d', '-c', (Join-Path $PSScriptRoot 'unbound.windows.conf')) | Out-Null
    Wait-ForTcpPort -Port 53 -TimeoutSeconds 120 -Description 'Unbound recursive DNS'

    $ncdnsLog = Join-Path $script:LogDir 'ncdns.service.log'
    Start-ChildService -Name 'ncdns' -BinaryPath $ncdnsBinary -ArgumentList @('-conf', (Join-Path $PSScriptRoot 'ncdns.windows.conf'), '-xlog.file', $ncdnsLog)
    Wait-ForTcpPort -Port 5391 -TimeoutSeconds 120 -Description 'ncdns authoritative DNS'

    $encayaConfigPath = Join-Path $PSScriptRoot 'encaya.windows.conf'
    Invoke-NativeCommand -FilePath $encayagenBinary -ArgumentList @('-conf', $encayaConfigPath) | Out-Null
    $encayaLog = Join-Path $script:LogDir 'encaya.service.log'
    Start-ChildService -Name 'encaya' -BinaryPath $encayaBinary -ArgumentList @('-conf', $encayaConfigPath, '-encaya.namecoinrpcaddress', '127.0.0.1:18554', '-encaya.namecoinrpcusername', 'doggman', '-encaya.namecoinrpcpassword', 'donkey', '-xlog.file', $encayaLog)
    Wait-ForTcpPort -HostName $script:AiaTestIp -Port 80 -TimeoutSeconds 120 -Description 'Encaya HTTP'
}

function Run-FunctionalTests {
    Ensure-Directory -Path $script:TestTempDir
    Write-Host 'Expire any existing names from previous functional test runs'
    New-Blocks -Count 35
    Write-Host 'Fetch Root CA via curl'
    Assert-Contains -Haystack (Invoke-Curl -Arguments @("$script:AiaTestUrl/lookup?domain=Namecoin%20Root%20CA")).Output -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'Root CA lookup failed'

    $fullLabel = 'ncp11full' + ((Get-Date).Ticks.ToString('x'))
    $fullName = "d/$fullLabel"
    $fullDomain = "$fullLabel.bit"
    $stapledLabel = 'ncp11stapled' + ((Get-Date).Ticks.ToString('x'))
    $stapledName = "d/$stapledLabel"
    $stapledDomain = "$stapledLabel.bit"
    Add-TestHosts -Domains @($fullDomain, $stapledDomain)

    $fullCaKey = Join-Path $script:TestTempDir 'full-ca.key'
    $fullCaPubDer = Join-Path $script:TestTempDir 'full-ca-pub.der'
    $fullParentCa = Join-Path $script:TestTempDir 'full-parent-ca.pem'
    $fullLeafKey = Join-Path $script:TestTempDir 'full-leaf.key'
    $fullLeafCsr = Join-Path $script:TestTempDir 'full-leaf.csr'
    $fullLeafCert = Join-Path $script:TestTempDir 'full-leaf.pem'
    $fullLeafExt = Join-Path $script:TestTempDir 'full-leaf-ext.cnf'
    $fullLeafSerial = Join-Path $script:TestTempDir 'full-leaf.srl'
    $bogusLeafKey = Join-Path $script:TestTempDir 'bogus-leaf.key'
    $bogusLeafCert = Join-Path $script:TestTempDir 'bogus-leaf.pem'
    $stapledCaKey = Join-Path $script:TestTempDir 'stapled-ca.key'
    $stapledCaPubDer = Join-Path $script:TestTempDir 'stapled-ca-pub.der'
    $stapledParentCa = Join-Path $script:TestTempDir 'stapled-parent-ca.pem'
    $stapledLeafKey = Join-Path $script:TestTempDir 'stapled-leaf.key'
    $stapledLeafCsr = Join-Path $script:TestTempDir 'stapled-leaf.csr'
    $stapledLeafCert = Join-Path $script:TestTempDir 'stapled-leaf.pem'
    $stapledLeafExt = Join-Path $script:TestTempDir 'stapled-leaf-ext.cnf'
    $stapledLeafSerial = Join-Path $script:TestTempDir 'stapled-leaf.srl'

    Write-Host 'Generate full-TLSA local test certificate material'
    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $fullCaKey) | Out-Null
    Invoke-OpenSsl -Arguments @('pkey', '-in', $fullCaKey, '-pubout', '-outform', 'DER', '-out', $fullCaPubDer) | Out-Null
    $fullCaPubB64 = ConvertTo-Base64File -Path $fullCaPubDer
    $fullValue = '{"ip":"127.0.0.1","map":{"*":{"tls":[[2,1,0,"' + $fullCaPubB64 + '"]]}}}'
    Register-NamecoinName -Name $fullName -Value $fullValue

    Write-Host "Fetch full-TLSA $fullDomain parent CA from Encaya"
    Invoke-Curl -Arguments @('--get', '--data-urlencode', "domain=$fullDomain Domain AIA Parent CA", "$script:AiaTestUrl/lookup") | Select-Object -ExpandProperty Output | Set-Content -LiteralPath $fullParentCa -Encoding ascii
    Assert-Contains -Haystack (Get-Content -LiteralPath $fullParentCa -Raw) -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'Full-TLSA parent CA lookup failed'
    New-LeafCert -Domain $fullDomain -ParentCaPath $fullParentCa -ParentKeyPath $fullCaKey -KeyPath $fullLeafKey -CsrPath $fullLeafCsr -CertPath $fullLeafCert -ExtPath $fullLeafExt -SerialPath $fullLeafSerial
    New-SelfSignedLeafCert -Domain $fullDomain -KeyPath $bogusLeafKey -CertPath $bogusLeafCert

    Write-Host 'Generate stapled local test certificate material'
    Invoke-OpenSsl -Arguments @('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', $stapledCaKey) | Out-Null
    Invoke-OpenSsl -Arguments @('pkey', '-in', $stapledCaKey, '-pubout', '-outform', 'DER', '-out', $stapledCaPubDer) | Out-Null
    $stapledCaPubB64 = ConvertTo-Base64UrlFile -Path $stapledCaPubDer
    Register-NamecoinName -Name $stapledName -Value '{"ip":"127.0.0.1"}'

    $stapledBlockchainAddress = (Invoke-NamecoinCliJson -Arguments @('name_show', $stapledName)).address
    $stapledMessageJson = '{"address":"' + $stapledBlockchainAddress + '","domain":"' + $stapledDomain + '","x509pub":"' + $stapledCaPubB64 + '"}'
    $stapledMessage = "Namecoin X.509 Stapled Certification: $stapledMessageJson"
    $stapledSig = Invoke-NamecoinCliText -Arguments @('signmessage', $stapledBlockchainAddress, $stapledMessage)
    $stapledSigsJson = '[{"blockchainaddress":"' + $stapledBlockchainAddress + '","blockchainsig":"' + $stapledSig + '"}]'
    Invoke-Curl -Arguments @('--get', '--data-urlencode', "domain=$stapledDomain Domain AIA Parent CA", '--data-urlencode', "pubb64=$stapledCaPubB64", '--data-urlencode', "sigs=$stapledSigsJson", "$script:AiaTestUrl/lookup") | Select-Object -ExpandProperty Output | Set-Content -LiteralPath $stapledParentCa -Encoding ascii
    Assert-Contains -Haystack (Get-Content -LiteralPath $stapledParentCa -Raw) -Needle 'BEGIN CERTIFICATE' -ErrorMessage 'Stapled parent CA lookup failed'
    New-LeafCert -Domain $stapledDomain -ParentCaPath $stapledParentCa -ParentKeyPath $stapledCaKey -KeyPath $stapledLeafKey -CsrPath $stapledLeafCsr -CertPath $stapledLeafCert -ExtPath $stapledLeafExt -SerialPath $stapledLeafSerial

    Write-Host 'Fetch full-TLSA local test domain with stock Firefox'
    Clear-FirefoxNcp11Policy
    Start-HttpsServer -CertPath $fullLeafCert -KeyPath $fullLeafKey
    Clear-Ncp11Logs
    Assert-FirefoxConnect -HostPort "$fullDomain`:4443" -ShouldSucceed $false
    Assert-Ncp11Log -Desired 'missing'

    Write-Host 'Configure Firefox for ncp11'
    Set-FirefoxNcp11Policy

    Write-Host 'Fetch unrelated local test cert with ncp11 Firefox'
    Start-HttpsServer -CertPath $bogusLeafCert -KeyPath $bogusLeafKey
    Clear-Ncp11Logs
    Assert-FirefoxConnect -HostPort "$fullDomain`:4443" -ShouldSucceed $false
    Assert-Ncp11Log -Desired 'present'

    Write-Host 'Fetch full-TLSA local test domain with ncp11 Firefox'
    Start-HttpsServer -CertPath $fullLeafCert -KeyPath $fullLeafKey
    Clear-Ncp11Logs
    Assert-FirefoxConnect -HostPort "$fullDomain`:4443" -ShouldSucceed $true
    Assert-Ncp11Log -Desired 'present'

    Write-Host 'Fetch stapled local test domain with ncp11 Firefox'
    Start-HttpsServer -CertPath $stapledLeafCert -KeyPath $stapledLeafKey
    Clear-Ncp11Logs
    Assert-FirefoxConnect -HostPort "$stapledDomain`:4443" -ShouldSucceed $true
    Assert-Ncp11Log -Desired 'present'
    Write-Host 'Functional test suite passed'
}

try {
    Start-TestServices
    Wait-ForNamecoinWalletBalance
    Run-FunctionalTests
} catch {
    $script:TestFailed = $true
    throw
} finally {
    Stop-ProcessIfRunning -Process $script:HttpsServerProcess
    Stop-Children
    Remove-TestHosts
    Clear-FirefoxNcp11Policy
    if ($script:TestFailed) {
        Dump-ServiceLogs
    }
    if (Test-Path -LiteralPath $script:TestTempDir) {
        Remove-Item -LiteralPath $script:TestTempDir -Recurse -Force
    }
}

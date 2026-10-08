#requires -Version 5.1
<#
.SYNOPSIS
    Tworzy CyberArk Safe i dodaje lokalne konto Windows Server lub Red Hat.
.DESCRIPTION
    Nakladka na New-CyberArkSafeAccount.ps1. Zachowuje jego logowanie,
    walidacje grupy owner, tworzenie Safe, obsluge czlonkow i Reconcile.
    Zmienia tylko parametry konta: address, platformId i properties.
    Nie weryfikuje istnienia konta na docelowym serwerze.
    Uwaga: bazowy skrypt sprawdza duplikat konta w CyberArk.
.EXAMPLE
    .\New-CyberArkLocalAccount.ps1 -SafeName 'SAFE-WIN01' -OSType Windows -Address 'win01.corp.local' -AccountUserName 'Administrator' -AllowExistingSafe -SkipReconcile
.EXAMPLE
    .\New-CyberArkLocalAccount.ps1 -SafeName 'SAFE-RHEL01' -OSType RedHat -Address 'rhel01.corp.local' -AccountUserName 'root' -PlatformId 'UnixSSH' -AllowExistingSafe
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SafeName,
    [Parameter(Mandatory = $true)][ValidateSet('Windows','RedHat')][string]$OSType,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Address,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AccountUserName,
    [string]$PlatformId,
    [string]$WindowsPlatformId = 'WinServerLocal',
    [string]$RedHatPlatformId = 'UnixSSH',
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'CyberArk-SafeConfig.json'),
    [string]$BaseScriptPath = (Join-Path $PSScriptRoot 'New-CyberArkSafeAccount.ps1'),
    [string]$PVWAURL,
    [ValidateSet('CyberArk','LDAP','Radius')][string]$AuthType,
    [System.Management.Automation.PSCredential]$Credential,
    [System.Security.SecureString]$AccountSecret,
    [string]$ADServer,
    [hashtable]$PlatformAccountProperties,
    [switch]$AllowExistingSafe,
    [switch]$UpdateExistingMembers,
    [switch]$SkipReconcile,
    [switch]$AddToAccountGroup
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $BaseScriptPath -PathType Leaf)) {
    throw "Brak skryptu bazowego: $BaseScriptPath"
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Brak konfiguracji: $ConfigPath"
}
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($null -eq $config.account) { throw 'Konfiguracja nie zawiera sekcji account.' }

$selectedPlatform = if (-not [string]::IsNullOrWhiteSpace($PlatformId)) {
    $PlatformId
} elseif ($OSType -eq 'Windows') {
    $WindowsPlatformId
} else {
    $RedHatPlatformId
}
$config.account.address = $Address
$config.account.platformId = $selectedPlatform
$config.account.secretType = 'password'

# Nie przenosimy LogonDomain z szablonu kont domenowych.
# Pozostale platformAccountProperties sa przekazywane tylko po jawnym podaniu.
$newProperties = [ordered]@{}
# RedHat: nie dodawaj domyslnie Port. Platformy UnixSSH/RHEL moga nie miec takiej wlasciwosci.
# Wlasciwosci platformy podaje sie jawnie przez -PlatformAccountProperties.
if ($null -ne $PlatformAccountProperties) {
    foreach ($key in $PlatformAccountProperties.Keys) {
        $newProperties[[string]$key] = [string]$PlatformAccountProperties[$key]
    }
}
if ($OSType -eq 'Windows') {
    # PVWA field "Logon To" maps to platform property "LogonDomain".
    # The value must equal account.address for local Windows accounts.
    # Remove the invalid legacy key even if supplied by the caller.
    if ($newProperties.Contains('LogonTo')) {
        $newProperties.Remove('LogonTo')
    }
    $newProperties['LogonDomain'] = $Address
}
$config.account.platformAccountProperties = [pscustomobject]$newProperties

$tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ("CyberArk-LocalAccount-{0}.json" -f [guid]::NewGuid().ToString('N'))
try {
    $json = $config | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($tempPath, $json, [System.Text.UTF8Encoding]::new($false))

    $arguments = @{
        SafeName = $SafeName
        AccountUserName = $AccountUserName
        ConfigPath = $tempPath
    }
    if ($PSBoundParameters.ContainsKey('PVWAURL')) { $arguments.PVWAURL = $PVWAURL }
    if ($PSBoundParameters.ContainsKey('AuthType')) { $arguments.AuthType = $AuthType }
    if ($PSBoundParameters.ContainsKey('Credential')) { $arguments.Credential = $Credential }
    if ($PSBoundParameters.ContainsKey('AccountSecret')) { $arguments.AccountSecret = $AccountSecret }
    if ($PSBoundParameters.ContainsKey('ADServer')) { $arguments.ADServer = $ADServer }
    if ($AllowExistingSafe) { $arguments.AllowExistingSafe = $true }
    if ($UpdateExistingMembers) { $arguments.UpdateExistingMembers = $true }
    if ($SkipReconcile) { $arguments.SkipReconcile = $true }
    if ($AddToAccountGroup) { $arguments.AddToAccountGroup = $true }

    Write-Host ("System: {0}; serwer: {1}; login: {2}; platformId: {3}" -f $OSType,$Address,$AccountUserName,$selectedPlatform)
    # Przekazujemy WhatIf/Confirm explicite; wrapper sam nie ingeruje w API.
    if ($WhatIfPreference) { $arguments.WhatIf = $true }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = [bool]$PSBoundParameters['Confirm'] }
    & $BaseScriptPath @arguments
}
finally {
    if (Test-Path -LiteralPath $tempPath) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

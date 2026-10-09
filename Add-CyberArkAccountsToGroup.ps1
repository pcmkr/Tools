#requires -Version 5.1
<#
.SYNOPSIS
  Adds existing CyberArk accounts to an Account Group without creating accounts.
.DESCRIPTION
  Uses the accountGroup section of CyberArk-SafeConfig.json, CyberArk REST API,
  and the selected authentication type (CyberArk, LDAP, Radius).
  Only accounts stored in the specified Safe may be added.
  Does not create Safe members, modify passwords or run Reconcile.
.EXAMPLE
  .\Add-CyberArkAccountsToGroup.ps1 -SafeName APP-PRD -AccountIds '21_101','21_102'
.EXAMPLE
  .\Add-CyberArkAccountsToGroup.ps1 -SafeName APP-PRD -AccountIds (Get-Content .\account-ids.txt) -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SafeName,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$AccountIds,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'CyberArk-SafeConfig.json'),
    [string]$PVWAURL,
    [ValidateSet('CyberArk','LDAP','Radius')][string]$AuthType,
    [pscredential]$Credential,
    [string]$GroupName,
    [string]$GroupPlatformId,
    [string[]]$AllowedPlatformIds,
    [switch]$CreateGroupIfMissing
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-Property {
    param($Item,[string]$Name)
    if ($null -eq $Item) { return $null }
    $property = $Item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Invoke-Api {
    param([string]$Method,[string]$Path,$Body=$null)
    $params = @{
        Uri = "$PVWAURL$Path"
        Method = $Method
        ContentType = 'application/json'
        Headers = @{Authorization=$script:token}
        ErrorAction = 'Stop'
        TimeoutSec = 180
    }
    if ($null -ne $Body) { $params.Body = ConvertTo-Json -InputObject $Body -Depth 15 }
    try { return Invoke-RestMethod @params }
    catch {
        $details = [string]$_.ErrorDetails.Message
        if (-not $details) { $details = $_.Exception.Message }
        throw "CyberArk $Method $Path failed: $details"
    }
}
function Expand-ApiCollection {
    param($Result)
    if ($null -eq $Result) { return @() }
    if ($Result -is [array]) { return @($Result) }
    $items = Get-Property $Result 'value'
    if ($null -eq $items) { $items = Get-Property $Result 'accounts' }
    if ($null -eq $items) { $items = Get-Property $Result 'groups' }
    if ($null -eq $items) { $items = Get-Property $Result 'members' }
    if ($null -eq $items) { return @($Result) }
    return @($items)
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Config not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
$defaults = Get-Property $config 'defaults'
$groupConfig = Get-Property $config 'accountGroup'
if (-not $PVWAURL) { $PVWAURL = [string](Get-Property $defaults 'pvwaUrl') }
if (-not $AuthType) { $AuthType = [string](Get-Property $defaults 'authType') }
if (-not $AuthType) { $AuthType = 'CyberArk' }
if ($AuthType -notin @('CyberArk','LDAP','Radius')) { throw "Unsupported AuthType: $AuthType" }
if (-not $GroupName) { $GroupName = [string](Get-Property $groupConfig 'name') }
if (-not $GroupPlatformId) { $GroupPlatformId = [string](Get-Property $groupConfig 'groupPlatformId') }
if (-not $CreateGroupIfMissing -and ((Get-Property $groupConfig 'createIfMissing') -eq $true)) {
    $CreateGroupIfMissing = $true
}
if (-not $PVWAURL -or -not $GroupName -or -not $GroupPlatformId) {
    throw 'PVWAURL, GroupName and GroupPlatformId must be set (parameters or JSON).'
}
$PVWAURL = $PVWAURL.TrimEnd('/')
$GroupName = $GroupName.Replace('{SafeName}',$SafeName)
$uniqueIds = @($AccountIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
if ($uniqueIds.Count -eq 0) { throw 'No account IDs.' }
if ($null -eq $Credential) { $Credential = Get-Credential -Message 'CyberArk PVWA login' }

$script:token = $null
try {
    # Login request must not include an authorization header.
    $logonBody = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
        concurrentSession = $true
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -Method Post -Body $logonBody -ContentType 'application/json' -ErrorAction Stop
    $script:token = if ($response -is [string]) { $response.Trim() } else {
        [string](Get-Property $response 'CyberArkLogonResult')
    }
    if (-not $script:token) { throw 'CyberArk authentication returned no token.' }

    $encodedSafe = [uri]::EscapeDataString($SafeName)
    $groupResult = Invoke-Api Get "/api/AccountGroups?Safe=$encodedSafe"
    $groups = @(Expand-ApiCollection $groupResult)
    $group = $groups | Where-Object {
        [string]::Equals([string](Get-Property $_ 'groupName'),$GroupName,[StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1

    if ($null -eq $group) {
        if (-not $CreateGroupIfMissing) { throw "Account Group '$GroupName' not found; creation is disabled." }
        if (-not $PSCmdlet.ShouldProcess($GroupName,'Create Account Group')) {
            Write-Host 'WhatIf: group creation skipped.'; return
        }
        $group = Invoke-Api Post '/api/AccountGroups/' @{
            GroupName=$GroupName
            GroupPlatformID=$GroupPlatformId
            Safe=$SafeName
        }
    }
    # Fail closed if a pre-existing group has the wrong group platform.
    $actualGroupPlatform = [string](Get-Property $group 'groupPlatformId')
    if (-not $actualGroupPlatform) { $actualGroupPlatform = [string](Get-Property $group 'GroupPlatform') }
    if ($actualGroupPlatform -and -not [string]::Equals($actualGroupPlatform,$GroupPlatformId,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Group '$GroupName' uses groupPlatformId '$actualGroupPlatform' instead of '$GroupPlatformId'."
    }
    $groupId = [string](Get-Property $group 'groupID')
    if (-not $groupId) { $groupId = [string](Get-Property $group 'id') }
    if (-not $groupId) { throw "CyberArk did not return GroupID for '$GroupName'." }
    $escapedGroup = [uri]::EscapeDataString($groupId)
    $memberResult = Invoke-Api Get "/api/AccountGroups/$escapedGroup/Members"
    $existingIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pageNumber = 0
    while ($true) {
        $pageNumber++
        if ($pageNumber -gt 100) { throw 'Account Group pagination exceeded safety limit.' }
        foreach ($member in @(Expand-ApiCollection $memberResult)) {
            $id = [string](Get-Property $member 'accountID')
            if (-not $id) { $id = [string](Get-Property $member 'id') }
            if ($id) { [void]$existingIds.Add($id) }
        }
        $nextLink = [string](Get-Property $memberResult 'nextLink')
        if (-not $nextLink) { break }
        if ([uri]::IsWellFormedUriString($nextLink,[UriKind]::Absolute)) {
            $nextUri = $nextLink
        } else {
            $nextUri = ([uri]::new(([uri]$PVWAURL),$nextLink)).AbsoluteUri
        }
        # Invoke-Api expects a path; reject cross-origin URLs.
        if (-not $nextUri.StartsWith($PVWAURL,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Pagination nextLink points outside PVWA.'
        }
        $memberResult = Invoke-Api Get $nextUri.Substring($PVWAURL.Length)
    }

    $stats = [ordered]@{ Added=0; AlreadyMember=0; Failed=0; Planned=0 }
    foreach ($id in $uniqueIds) {
        if ($existingIds.Contains($id)) {
            Write-Host "Already a member: $id"
            $stats.AlreadyMember++
            continue
        }
        try {
            $account = Invoke-Api Get "/api/Accounts/$([uri]::EscapeDataString($id))"
            $accountSafe = [string](Get-Property $account 'safeName')
            if (-not [string]::Equals($accountSafe,$SafeName,[StringComparison]::OrdinalIgnoreCase)) {
                throw "Account belongs to Safe '$accountSafe', expected '$SafeName'."
            }
            if ($AllowedPlatformIds -and $AllowedPlatformIds.Count -gt 0) {
                $actualPlatform = [string](Get-Property $account 'platformId')
                if ($actualPlatform -notin $AllowedPlatformIds) {
                    throw "Account $id has target platform '$actualPlatform', allowed: $($AllowedPlatformIds -join ', ')."
                }
            }
            if ($PSCmdlet.ShouldProcess($id,"Add to Account Group '$GroupName'")) {
                Invoke-Api Post "/api/AccountGroups/$escapedGroup/Members" @{ accountID=$id } | Out-Null
                Write-Host "Added: $id" -ForegroundColor Green
                [void]$existingIds.Add($id)
                $stats.Added++
            }
            else { $stats.Planned++ }
        }
        catch {
            Write-Warning "Account $id failed: $($_.Exception.Message)"
            $stats.Failed++
        }
    }
    Write-Host ("Group: {0} | Added: {1}, already present: {2}, planned: {3}, failed: {4}" -f $GroupName,$stats.Added,$stats.AlreadyMember,$stats.Planned,$stats.Failed)
    if ($stats.Failed -gt 0) { throw "$($stats.Failed) account(s) could not be assigned." }
}
finally {
    if ($script:token) {
        try { Invoke-Api Post '/api/Auth/Logoff' @{} | Out-Null }
        catch { Write-Warning "Logoff failed: $($_.Exception.Message)" }
    }
}

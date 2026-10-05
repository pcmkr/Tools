#requires -Version 5.1
#requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Eksportuje grupy Active Directory i ich członków do CSV.

.DESCRIPTION
    Tworzy Groups.csv, Memberships.csv i opcjonalnie Errors.csv.
    Obsługuje członkostwo bezpośrednie i zagnieżdżone, pełną ścieżkę członkostwa,
    UPN, mail, stan Enabled, DN/OU, scope/category grup i wykrywanie cykli.

    Dla użytkowników dodaje:
      - dokładny LastLogon (maksymalny lastLogon ze wszystkich dostępnych DC),
      - dokładny LastBadPasswordAttempt (maksymalny badPasswordTime ze wszystkich dostępnych DC),
      - extensionAttribute2,
      - extensionAttribute13,
      - employeeID,
      - employeeType.

    SID-y nie są eksportowane.

.PARAMETER OutputDirectory
    Katalog wynikowy. Domyślnie AD-Group-Export-<timestamp>.

.PARAMETER SearchBase
    Opcjonalny Distinguished Name OU/kontenera ograniczający wyszukiwanie grup.

.PARAMETER Domain
    Domena DNS lub konkretny kontroler domeny używany do odnalezienia domeny.
    Alias: -Server, -DomainController.

.PARAMETER GroupFilter
    Filtr przekazywany bezpośrednio do Get-ADGroup -Filter. Domyślnie "*".

.PARAMETER ExpandNested
    Rekurencyjnie rozwija grupy zagnieżdżone i zapisuje MembershipDepth/Path.

.PARAMETER IncludeEmptyGroups
    Dodaje do Memberships.csv także grupy bez członków.

.PARAMETER Encoding
    Kodowanie plików CSV. Domyślnie utf8BOM. W Windows PowerShell 5.1
    wartość utf8BOM jest mapowana na UTF8, które zapisuje BOM.

.PARAMETER Delimiter
    Separator CSV. Domyślnie średnik, co jest wygodne dla polskiego Excela.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -Domain corp.example.com -ExpandNested -IncludeEmptyGroups

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -Domain dc01.corp.example.com -SearchBase "OU=Groups,DC=corp,DC=example,DC=com"

.NOTES
    Wymaga modułu ActiveDirectory (RSAT).
    Dokładny LastLogon i LastBadPasswordAttempt wymagają odczytu wszystkich dostępnych DC.
    badPasswordTime oznacza ostatnią próbę z błędnym hasłem; nie jest uniwersalnym znacznikiem
    każdego możliwego nieudanego logowania.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PWD ("AD-Group-Export-" + (Get-Date -Format "yyyyMMdd-HHmmss"))),
    [string]$SearchBase,
    [Alias("Server","DomainController")]
    [string]$Domain,
    [string]$GroupFilter = "*",
    [switch]$ExpandNested,
    [switch]$IncludeEmptyGroups,
    [ValidateSet("utf8", "utf8BOM", "unicode", "ascii")]
    [string]$Encoding = "utf8BOM",
    [char]$Delimiter = ";"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

$adServerParams = @{}
if ($Domain) { $adServerParams.Server = $Domain }

function Get-ParentOU {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    if ($DistinguishedName -match '^[^,]+,(.+)$') { return $Matches[1] }
    return $null
}

function Convert-FileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $v = [Int64]$Value
        if ($v -le 0 -or $v -eq [Int64]::MaxValue) { return $null }
        return [DateTime]::FromFileTimeUtc($v).ToLocalTime()
    }
    catch { return $null }
}

function Get-CompatibleCsvEncoding {
    param([Parameter(Mandatory)][string]$RequestedEncoding)
    if ($PSVersionTable.PSVersion.Major -lt 6 -and $RequestedEncoding -eq "utf8BOM") {
        return "UTF8"
    }
    return $RequestedEncoding
}

function Export-ReadableCsv {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )
    begin { $buffer = [System.Collections.Generic.List[object]]::new() }
    process { $buffer.Add($InputObject) }
    end {
        $csvEncoding = Get-CompatibleCsvEncoding -RequestedEncoding $Encoding
        $buffer | Export-Csv -LiteralPath $Path -NoTypeInformation -Delimiter $Delimiter -Encoding $csvEncoding
    }
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$groupsCsv = Join-Path $OutputDirectory "Groups.csv"
$membershipsCsv = Join-Path $OutputDirectory "Memberships.csv"
$errorsCsv = Join-Path $OutputDirectory "Errors.csv"

$errors = [System.Collections.Generic.List[object]]::new()
$membershipRows = [System.Collections.Generic.List[object]]::new()
$objectCache = @{}
$logonIndex = @{}

Write-Host "Odnajdywanie kontrolerów domeny..." -ForegroundColor Cyan
try {
    $dcs = @(Get-ADDomainController -Filter * @adServerParams | Sort-Object HostName)
}
catch {
    throw "Nie udało się pobrać listy kontrolerów domeny: $($_.Exception.Message)"
}
if ($dcs.Count -eq 0) { throw "Nie znaleziono kontrolerów domeny." }

Write-Host ("Kontrolery domeny: {0}" -f (($dcs.HostName) -join ", ")) -ForegroundColor Cyan
Write-Host "Budowanie indeksu dokładnych czasów logowania..." -ForegroundColor Cyan

foreach ($dc in $dcs) {
    try {
        Write-Host ("  Odczyt: {0}" -f $dc.HostName) -ForegroundColor DarkCyan
        $dcUsers = Get-ADUser -Filter * -Server $dc.HostName -Properties lastLogon,badPasswordTime,ObjectGUID -ErrorAction Stop
        foreach ($u in $dcUsers) {
            $key = $u.ObjectGUID.Guid
            if (-not $logonIndex.ContainsKey($key)) {
                $logonIndex[$key] = [PSCustomObject]@{
                    LastLogonRaw = [Int64]0
                    LastLogonSourceDC = $null
                    LastBadRaw = [Int64]0
                    LastBadSourceDC = $null
                }
            }

            $entry = $logonIndex[$key]
            if ($null -ne $u.lastLogon) {
                $v = [Int64]$u.lastLogon
                if ($v -gt $entry.LastLogonRaw) {
                    $entry.LastLogonRaw = $v
                    $entry.LastLogonSourceDC = $dc.HostName
                }
            }
            if ($null -ne $u.badPasswordTime) {
                $v = [Int64]$u.badPasswordTime
                if ($v -gt $entry.LastBadRaw) {
                    $entry.LastBadRaw = $v
                    $entry.LastBadSourceDC = $dc.HostName
                }
            }
        }
    }
    catch {
        $errors.Add([PSCustomObject]@{
            Timestamp = Get-Date
            Operation = "BuildLogonIndex"
            ObjectName = $null
            DistinguishedName = $null
            Error = ("DC {0}: {1}" -f $dc.HostName, $_.Exception.Message)
        })
        Write-Warning ("Nie udało się odczytać użytkowników z DC {0}: {1}" -f $dc.HostName, $_.Exception.Message)
    }
}

$groupParams = @{
    Filter = $GroupFilter
    Properties = @("Description","GroupCategory","GroupScope","mail","ManagedBy","whenCreated","whenChanged")
}
if ($SearchBase) { $groupParams.SearchBase = $SearchBase }

if ($Domain) { Write-Host ("Domena / serwer AD: {0}" -f $Domain) -ForegroundColor Cyan }
Write-Host "Pobieranie grup AD..." -ForegroundColor Cyan
$groups = @(Get-ADGroup @groupParams @adServerParams | Sort-Object Name)
Write-Host ("Znaleziono grup: {0}" -f $groups.Count) -ForegroundColor Cyan

function Get-ADObjectDetails {
    param([Parameter(Mandatory)]$Member)

    $cacheKey = [string]$Member.DistinguishedName
    if ($objectCache.ContainsKey($cacheKey)) { return $objectCache[$cacheKey] }

    try {
        switch ($Member.ObjectClass) {
            "user" {
                $obj = Get-ADUser -Identity $Member.DistinguishedName -Properties @(
                    "DisplayName","UserPrincipalName","mail","Enabled","DistinguishedName","SamAccountName",
                    "ObjectGUID","extensionAttribute2","extensionAttribute13","employeeID","employeeType"
                ) @adServerParams

                $timeEntry = $null
                $guidKey = $obj.ObjectGUID.Guid
                if ($logonIndex.ContainsKey($guidKey)) { $timeEntry = $logonIndex[$guidKey] }

                $details = [PSCustomObject]@{
                    Name = $obj.Name
                    DisplayName = $obj.DisplayName
                    SamAccountName = $obj.SamAccountName
                    UserPrincipalName = $obj.UserPrincipalName
                    Mail = $obj.mail
                    Enabled = $obj.Enabled
                    DNSHostName = $null
                    DistinguishedName = $obj.DistinguishedName
                    OU = Get-ParentOU -DistinguishedName $obj.DistinguishedName
                    GroupCategory = $null
                    GroupScope = $null
                    LastLogon = if ($timeEntry) { Convert-FileTime $timeEntry.LastLogonRaw } else { $null }
                    LastLogonSourceDC = if ($timeEntry) { $timeEntry.LastLogonSourceDC } else { $null }
                    LastBadPasswordAttempt = if ($timeEntry) { Convert-FileTime $timeEntry.LastBadRaw } else { $null }
                    LastBadPasswordSourceDC = if ($timeEntry) { $timeEntry.LastBadSourceDC } else { $null }
                    ExtensionAttribute2 = $obj.extensionAttribute2
                    ExtensionAttribute13 = $obj.extensionAttribute13
                    EmployeeID = $obj.employeeID
                    EmployeeType = $obj.employeeType
                }
            }
            "computer" {
                $obj = Get-ADComputer -Identity $Member.DistinguishedName -Properties DNSHostName,Enabled,DistinguishedName,SamAccountName @adServerParams
                $details = [PSCustomObject]@{
                    Name=$obj.Name; DisplayName=$null; SamAccountName=$obj.SamAccountName; UserPrincipalName=$null;
                    Mail=$null; Enabled=$obj.Enabled; DNSHostName=$obj.DNSHostName; DistinguishedName=$obj.DistinguishedName;
                    OU=(Get-ParentOU $obj.DistinguishedName); GroupCategory=$null; GroupScope=$null;
                    LastLogon=$null; LastLogonSourceDC=$null; LastBadPasswordAttempt=$null; LastBadPasswordSourceDC=$null;
                    ExtensionAttribute2=$null; ExtensionAttribute13=$null; EmployeeID=$null; EmployeeType=$null
                }
            }
            "group" {
                $obj = Get-ADGroup -Identity $Member.DistinguishedName -Properties mail,GroupCategory,GroupScope,DistinguishedName,SamAccountName @adServerParams
                $details = [PSCustomObject]@{
                    Name=$obj.Name; DisplayName=$null; SamAccountName=$obj.SamAccountName; UserPrincipalName=$null;
                    Mail=$obj.mail; Enabled=$null; DNSHostName=$null; DistinguishedName=$obj.DistinguishedName;
                    OU=(Get-ParentOU $obj.DistinguishedName); GroupCategory=$obj.GroupCategory; GroupScope=$obj.GroupScope;
                    LastLogon=$null; LastLogonSourceDC=$null; LastBadPasswordAttempt=$null; LastBadPasswordSourceDC=$null;
                    ExtensionAttribute2=$null; ExtensionAttribute13=$null; EmployeeID=$null; EmployeeType=$null
                }
            }
            default {
                $obj = Get-ADObject -Identity $Member.DistinguishedName -Properties mail,DistinguishedName @adServerParams
                $details = [PSCustomObject]@{
                    Name=$obj.Name; DisplayName=$null; SamAccountName=$null; UserPrincipalName=$null;
                    Mail=$obj.mail; Enabled=$null; DNSHostName=$null; DistinguishedName=$obj.DistinguishedName;
                    OU=(Get-ParentOU $obj.DistinguishedName); GroupCategory=$null; GroupScope=$null;
                    LastLogon=$null; LastLogonSourceDC=$null; LastBadPasswordAttempt=$null; LastBadPasswordSourceDC=$null;
                    ExtensionAttribute2=$null; ExtensionAttribute13=$null; EmployeeID=$null; EmployeeType=$null
                }
            }
        }

        $objectCache[$cacheKey] = $details
        return $details
    }
    catch {
        $errors.Add([PSCustomObject]@{
            Timestamp = Get-Date
            Operation = "Get-ADObjectDetails"
            ObjectName = $Member.Name
            DistinguishedName = $Member.DistinguishedName
            Error = $_.Exception.Message
        })

        return [PSCustomObject]@{
            Name=$Member.Name; DisplayName=$null; SamAccountName=$Member.SamAccountName; UserPrincipalName=$null;
            Mail=$null; Enabled=$null; DNSHostName=$null; DistinguishedName=$Member.DistinguishedName;
            OU=(Get-ParentOU $Member.DistinguishedName); GroupCategory=$null; GroupScope=$null;
            LastLogon=$null; LastLogonSourceDC=$null; LastBadPasswordAttempt=$null; LastBadPasswordSourceDC=$null;
            ExtensionAttribute2=$null; ExtensionAttribute13=$null; EmployeeID=$null; EmployeeType=$null
        }
    }
}

function Add-MembershipRow {
    param(
        [Parameter(Mandatory)]$RootGroup,
        $Member,
        [Parameter(Mandatory)][ValidateSet("Direct","Nested","Empty")][string]$MembershipType,
        [Parameter(Mandatory)][int]$Depth,
        [Parameter(Mandatory)][string]$MembershipPath
    )

    if ($MembershipType -eq "Empty") {
        $membershipRows.Add([PSCustomObject]@{
            GroupName=$RootGroup.Name; GroupSamAccountName=$RootGroup.SamAccountName; GroupCategory=$RootGroup.GroupCategory;
            GroupScope=$RootGroup.GroupScope; GroupMail=$RootGroup.mail; GroupDN=$RootGroup.DistinguishedName;
            GroupOU=(Get-ParentOU $RootGroup.DistinguishedName); MembershipType="Empty"; MembershipDepth=0;
            MembershipPath=$MembershipPath; MemberObjectClass=$null; MemberName=$null; MemberDisplayName=$null;
            MemberSamAccountName=$null; MemberUPN=$null; MemberMail=$null; MemberEnabled=$null; MemberDNSHostName=$null;
            MemberDN=$null; MemberOU=$null; MemberGroupCategory=$null; MemberGroupScope=$null; MemberLastLogon=$null;
            MemberLastLogonSourceDC=$null; MemberLastBadPasswordAttempt=$null; MemberLastBadPasswordSourceDC=$null;
            MemberExtensionAttribute2=$null; MemberExtensionAttribute13=$null; MemberEmployeeID=$null; MemberEmployeeType=$null
        })
        return
    }

    $details = Get-ADObjectDetails -Member $Member

    $membershipRows.Add([PSCustomObject]@{
        GroupName=$RootGroup.Name
        GroupSamAccountName=$RootGroup.SamAccountName
        GroupCategory=$RootGroup.GroupCategory
        GroupScope=$RootGroup.GroupScope
        GroupMail=$RootGroup.mail
        GroupDN=$RootGroup.DistinguishedName
        GroupOU=Get-ParentOU $RootGroup.DistinguishedName
        MembershipType=$MembershipType
        MembershipDepth=$Depth
        MembershipPath=$MembershipPath
        MemberObjectClass=$Member.ObjectClass
        MemberName=$details.Name
        MemberDisplayName=$details.DisplayName
        MemberSamAccountName=$details.SamAccountName
        MemberUPN=$details.UserPrincipalName
        MemberMail=$details.Mail
        MemberEnabled=$details.Enabled
        MemberDNSHostName=$details.DNSHostName
        MemberDN=$details.DistinguishedName
        MemberOU=$details.OU
        MemberGroupCategory=$details.GroupCategory
        MemberGroupScope=$details.GroupScope
        MemberLastLogon=$details.LastLogon
        MemberLastLogonSourceDC=$details.LastLogonSourceDC
        MemberLastBadPasswordAttempt=$details.LastBadPasswordAttempt
        MemberLastBadPasswordSourceDC=$details.LastBadPasswordSourceDC
        MemberExtensionAttribute2=$details.ExtensionAttribute2
        MemberExtensionAttribute13=$details.ExtensionAttribute13
        MemberEmployeeID=$details.EmployeeID
        MemberEmployeeType=$details.EmployeeType
    })
}

function Expand-GroupMembership {
    param(
        [Parameter(Mandatory)]$RootGroup,
        [Parameter(Mandatory)][string]$CurrentGroupDN,
        [Parameter(Mandatory)][int]$Depth,
        [Parameter(Mandatory)][string[]]$PathParts,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$GroupsInCurrentPath
    )

    try {
        $members = @(Get-ADGroupMember -Identity $CurrentGroupDN -ErrorAction Stop @adServerParams)
    }
    catch {
        $errors.Add([PSCustomObject]@{
            Timestamp=Get-Date; Operation="Get-ADGroupMember"; ObjectName=$RootGroup.Name;
            DistinguishedName=$CurrentGroupDN; Error=$_.Exception.Message
        })
        return
    }

    foreach ($member in $members) {
        $memberPathParts = @($PathParts + $member.Name)
        $memberPath = $memberPathParts -join " > "
        $type = if ($Depth -eq 1) { "Direct" } else { "Nested" }

        Add-MembershipRow -RootGroup $RootGroup -Member $member -MembershipType $type -Depth $Depth -MembershipPath $memberPath

        if ($ExpandNested -and $member.ObjectClass -eq "group") {
            $nestedGroupDN = [string]$member.DistinguishedName
            if ($GroupsInCurrentPath.Contains($nestedGroupDN)) {
                $errors.Add([PSCustomObject]@{
                    Timestamp=Get-Date; Operation="NestedGroupCycle"; ObjectName=$member.Name;
                    DistinguishedName=$nestedGroupDN;
                    Error="Wykryto cykliczne zagnieżdżenie grup. Rekurencja dla tej ścieżki została zatrzymana."
                })
                continue
            }

            $nextPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($dn in $GroupsInCurrentPath) { [void]$nextPath.Add($dn) }
            [void]$nextPath.Add($nestedGroupDN)

            Expand-GroupMembership -RootGroup $RootGroup -CurrentGroupDN $nestedGroupDN -Depth ($Depth + 1) -PathParts $memberPathParts -GroupsInCurrentPath $nextPath
        }
    }
}

$groupRows = foreach ($group in $groups) {
    [PSCustomObject]@{
        Name=$group.Name
        SamAccountName=$group.SamAccountName
        GroupCategory=$group.GroupCategory
        GroupScope=$group.GroupScope
        Description=$group.Description
        Mail=$group.mail
        ManagedBy=$group.ManagedBy
        DistinguishedName=$group.DistinguishedName
        OU=Get-ParentOU $group.DistinguishedName
        WhenCreated=$group.whenCreated
        WhenChanged=$group.whenChanged
    }
}

$counter = 0
foreach ($group in $groups) {
    $counter++
    Write-Progress -Activity "Eksport członkostwa grup AD" -Status ("{0}/{1}: {2}" -f $counter,$groups.Count,$group.Name) -PercentComplete (($counter / [math]::Max($groups.Count,1))*100)

    try {
        $directMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop @adServerParams)
        if ($directMembers.Count -eq 0) {
            if ($IncludeEmptyGroups) {
                Add-MembershipRow -RootGroup $group -Member $null -MembershipType "Empty" -Depth 0 -MembershipPath $group.Name
            }
            continue
        }

        $pathSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$pathSet.Add([string]$group.DistinguishedName)
        Expand-GroupMembership -RootGroup $group -CurrentGroupDN $group.DistinguishedName -Depth 1 -PathParts @($group.Name) -GroupsInCurrentPath $pathSet
    }
    catch {
        $errors.Add([PSCustomObject]@{
            Timestamp=Get-Date; Operation="ProcessGroup"; ObjectName=$group.Name;
            DistinguishedName=$group.DistinguishedName; Error=$_.Exception.Message
        })
    }
}
Write-Progress -Activity "Eksport członkostwa grup AD" -Completed

$groupRows | Export-ReadableCsv -Path $groupsCsv
$membershipRows | Export-ReadableCsv -Path $membershipsCsv
if ($errors.Count -gt 0) { $errors | Export-ReadableCsv -Path $errorsCsv }

Write-Host ""
Write-Host "Eksport zakończony." -ForegroundColor Green
Write-Host ("Grupy:        {0}" -f $groups.Count)
Write-Host ("Relacje:      {0}" -f $membershipRows.Count)
Write-Host ("Błędy/uwagi:  {0}" -f $errors.Count)
Write-Host ("Katalog:      {0}" -f $OutputDirectory)
Write-Host ("Groups.csv:   {0}" -f $groupsCsv)
Write-Host ("Memberships:  {0}" -f $membershipsCsv)
if ($errors.Count -gt 0) { Write-Host ("Errors.csv:   {0}" -f $errorsCsv) -ForegroundColor Yellow }

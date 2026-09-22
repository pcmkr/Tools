<#
.SYNOPSIS
    Eksportuje grupy Active Directory i ich członków do CSV.

.DESCRIPTION
    Tworzy Groups.csv, Memberships.csv i opcjonalnie Errors.csv.
    Obsługuje członkostwo bezpośrednie i zagnieżdżone, pełną ścieżkę członkostwa,
    UPN, mail, stan Enabled, SID, DN/OU, scope/category grup i wykrywanie cykli.

.PARAMETER OutputDirectory
    Katalog wynikowy. Domyślnie tworzony jest katalog AD-Group-Export-<timestamp>.

.PARAMETER SearchBase
    Opcjonalny Distinguished Name OU/kontenera ograniczający wyszukiwanie grup.

.PARAMETER Domain
    Domena DNS lub konkretny kontroler domeny używany przez polecenia Get-AD*.
    Alias: -Server, -DomainController.

.PARAMETER GroupFilter
    Filtr przekazywany bezpośrednio do Get-ADGroup -Filter. Domyślnie "*".

.PARAMETER ExpandNested
    Rekurencyjnie rozwija grupy zagnieżdżone i zapisuje MembershipDepth/Path.

.PARAMETER IncludeEmptyGroups
    Dodaje do Memberships.csv także grupy bez członków.

.PARAMETER Encoding
    Kodowanie plików CSV. Domyślnie utf8BOM.

.PARAMETER Delimiter
    Separator CSV. Domyślnie średnik.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -Domain corp.example.com -ExpandNested -IncludeEmptyGroups
    Pełny eksport grup i członkostwa dla domeny.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -Domain dc01.corp.example.com -SearchBase "OU=Groups,DC=corp,DC=example,DC=com"
    Eksport grup z konkretnego OU przez wskazany kontroler domeny.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -Domain corp.example.com -GroupFilter 'Name -like "GRP-*"' -OutputDirectory C:\Temp\ADGroups
    Eksport tylko grup pasujących do wzorca.

.NOTES
    Wymaga modułu ActiveDirectory (RSAT). Przy -ExpandNested liczba zapytań do AD może znacząco wzrosnąć.
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
if ($Domain) {
    $adServerParams.Server = $Domain
}

function Get-ParentOU {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    if ($DistinguishedName -match '^[^,]+,(.+)$') { return $Matches[1] }
    return $null
}

function Convert-SidToString {
    param($Sid)
    if ($null -eq $Sid) { return $null }
    try { return $Sid.Value } catch { return [string]$Sid }
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$groupsCsv = Join-Path $OutputDirectory "Groups.csv"
$membershipsCsv = Join-Path $OutputDirectory "Memberships.csv"
$errorsCsv = Join-Path $OutputDirectory "Errors.csv"

$groupParams = @{
    Filter = $GroupFilter
    Properties = @("Description","GroupCategory","GroupScope","mail","ManagedBy","SID","whenCreated","whenChanged")
}
if ($SearchBase) { $groupParams.SearchBase = $SearchBase }

if ($Domain) {
    Write-Host ("Domena / serwer AD: {0}" -f $Domain) -ForegroundColor Cyan
}
Write-Host "Pobieranie grup AD..." -ForegroundColor Cyan
$groups = @(Get-ADGroup @groupParams @adServerParams | Sort-Object Name)
Write-Host ("Znaleziono grup: {0}" -f $groups.Count) -ForegroundColor Cyan

$objectCache = @{}
$errors = [System.Collections.Generic.List[object]]::new()
$membershipRows = [System.Collections.Generic.List[object]]::new()

function Get-ADObjectDetails {
    param([Parameter(Mandatory)]$Member)

    $cacheKey = [string]$Member.DistinguishedName
    if ($objectCache.ContainsKey($cacheKey)) { return $objectCache[$cacheKey] }

    try {
        switch ($Member.ObjectClass) {
            "user" {
                $obj = Get-ADUser -Identity $Member.DistinguishedName -Properties DisplayName,UserPrincipalName,mail,Enabled,SID,DistinguishedName,SamAccountName @adServerParams
            }
            "computer" {
                $obj = Get-ADComputer -Identity $Member.DistinguishedName -Properties DNSHostName,Enabled,SID,DistinguishedName,SamAccountName @adServerParams
            }
            "group" {
                $obj = Get-ADGroup -Identity $Member.DistinguishedName -Properties mail,GroupCategory,GroupScope,SID,DistinguishedName,SamAccountName @adServerParams
            }
            default {
                $obj = Get-ADObject -Identity $Member.DistinguishedName -Properties mail,SID,DistinguishedName @adServerParams
            }
        }

        $details = [PSCustomObject]@{
            Name              = $obj.Name
            DisplayName       = if ($obj.PSObject.Properties.Name -contains "DisplayName") { $obj.DisplayName } else { $null }
            SamAccountName    = if ($obj.PSObject.Properties.Name -contains "SamAccountName") { $obj.SamAccountName } else { $null }
            UserPrincipalName = if ($obj.PSObject.Properties.Name -contains "UserPrincipalName") { $obj.UserPrincipalName } else { $null }
            Mail              = if ($obj.PSObject.Properties.Name -contains "mail") { $obj.mail } else { $null }
            Enabled           = if ($obj.PSObject.Properties.Name -contains "Enabled") { $obj.Enabled } else { $null }
            DNSHostName       = if ($obj.PSObject.Properties.Name -contains "DNSHostName") { $obj.DNSHostName } else { $null }
            SID               = if ($obj.PSObject.Properties.Name -contains "SID") { Convert-SidToString $obj.SID } else { $null }
            DistinguishedName = $obj.DistinguishedName
            OU                = Get-ParentOU -DistinguishedName $obj.DistinguishedName
            GroupCategory     = if ($obj.PSObject.Properties.Name -contains "GroupCategory") { $obj.GroupCategory } else { $null }
            GroupScope        = if ($obj.PSObject.Properties.Name -contains "GroupScope") { $obj.GroupScope } else { $null }
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
            Name = $Member.Name
            DisplayName = $null
            SamAccountName = $Member.SamAccountName
            UserPrincipalName = $null
            Mail = $null
            Enabled = $null
            DNSHostName = $null
            SID = $null
            DistinguishedName = $Member.DistinguishedName
            OU = Get-ParentOU -DistinguishedName $Member.DistinguishedName
            GroupCategory = $null
            GroupScope = $null
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
            GroupName = $RootGroup.Name
            GroupSamAccountName = $RootGroup.SamAccountName
            GroupCategory = $RootGroup.GroupCategory
            GroupScope = $RootGroup.GroupScope
            GroupMail = $RootGroup.mail
            GroupSID = Convert-SidToString $RootGroup.SID
            GroupDN = $RootGroup.DistinguishedName
            GroupOU = Get-ParentOU $RootGroup.DistinguishedName
            MembershipType = "Empty"
            MembershipDepth = 0
            MembershipPath = $MembershipPath
            MemberObjectClass = $null
            MemberName = $null
            MemberDisplayName = $null
            MemberSamAccountName = $null
            MemberUPN = $null
            MemberMail = $null
            MemberEnabled = $null
            MemberDNSHostName = $null
            MemberSID = $null
            MemberDN = $null
            MemberOU = $null
            MemberGroupCategory = $null
            MemberGroupScope = $null
        })
        return
    }

    $details = Get-ADObjectDetails -Member $Member

    $membershipRows.Add([PSCustomObject]@{
        GroupName = $RootGroup.Name
        GroupSamAccountName = $RootGroup.SamAccountName
        GroupCategory = $RootGroup.GroupCategory
        GroupScope = $RootGroup.GroupScope
        GroupMail = $RootGroup.mail
        GroupSID = Convert-SidToString $RootGroup.SID
        GroupDN = $RootGroup.DistinguishedName
        GroupOU = Get-ParentOU $RootGroup.DistinguishedName
        MembershipType = $MembershipType
        MembershipDepth = $Depth
        MembershipPath = $MembershipPath
        MemberObjectClass = $Member.ObjectClass
        MemberName = $details.Name
        MemberDisplayName = $details.DisplayName
        MemberSamAccountName = $details.SamAccountName
        MemberUPN = $details.UserPrincipalName
        MemberMail = $details.Mail
        MemberEnabled = $details.Enabled
        MemberDNSHostName = $details.DNSHostName
        MemberSID = $details.SID
        MemberDN = $details.DistinguishedName
        MemberOU = $details.OU
        MemberGroupCategory = $details.GroupCategory
        MemberGroupScope = $details.GroupScope
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
            Timestamp = Get-Date
            Operation = "Get-ADGroupMember"
            ObjectName = $RootGroup.Name
            DistinguishedName = $CurrentGroupDN
            Error = $_.Exception.Message
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
                    Timestamp = Get-Date
                    Operation = "NestedGroupCycle"
                    ObjectName = $member.Name
                    DistinguishedName = $nestedGroupDN
                    Error = "Wykryto cykliczne zagnieżdżenie grup. Rekurencja dla tej ścieżki została zatrzymana."
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
        Name = $group.Name
        SamAccountName = $group.SamAccountName
        GroupCategory = $group.GroupCategory
        GroupScope = $group.GroupScope
        Description = $group.Description
        Mail = $group.mail
        ManagedBy = $group.ManagedBy
        SID = Convert-SidToString $group.SID
        DistinguishedName = $group.DistinguishedName
        OU = Get-ParentOU $group.DistinguishedName
        WhenCreated = $group.whenCreated
        WhenChanged = $group.whenChanged
    }
}

$counter = 0
foreach ($group in $groups) {
    $counter++

    Write-Progress -Activity "Eksport członkostwa grup AD" -Status ("{0}/{1}: {2}" -f $counter, $groups.Count, $group.Name) -PercentComplete (($counter / [math]::Max($groups.Count, 1)) * 100)

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
            Timestamp = Get-Date
            Operation = "ProcessGroup"
            ObjectName = $group.Name
            DistinguishedName = $group.DistinguishedName
            Error = $_.Exception.Message
        })
    }
}

Write-Progress -Activity "Eksport członkostwa grup AD" -Completed

$groupRows | Export-Csv -LiteralPath $groupsCsv -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
$membershipRows | Export-Csv -LiteralPath $membershipsCsv -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding

if ($errors.Count -gt 0) {
    $errors | Export-Csv -LiteralPath $errorsCsv -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
}

Write-Host ""
Write-Host "Eksport zakończony." -ForegroundColor Green
Write-Host ("Grupy:        {0}" -f $groups.Count)
Write-Host ("Relacje:      {0}" -f $membershipRows.Count)
Write-Host ("Błędy/uwagi:  {0}" -f $errors.Count)
Write-Host ("Katalog:      {0}" -f $OutputDirectory)
Write-Host ("Groups.csv:   {0}" -f $groupsCsv)
Write-Host ("Memberships:  {0}" -f $membershipsCsv)
if ($errors.Count -gt 0) { Write-Host ("Errors.csv:   {0}" -f $errorsCsv) -ForegroundColor Yellow }

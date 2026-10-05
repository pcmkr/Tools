#requires -Version 5.1
#requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Eksportuje wszystkich użytkowników Active Directory wraz ze wszystkimi dostępnymi atrybutami.

.DESCRIPTION
    Pobiera Get-ADUser -Properties * dla wszystkich użytkowników w domenie lub podanym SearchBase.
    Wynikowy CSV zawiera:
      - czytelne kolumny dla Excela,
      - UTF-8 z BOM (domyślnie) i separator średnik,
      - wszystkie właściwości zwrócone przez Get-ADUser -Properties *,
      - wielowartościowe atrybuty spłaszczone do jednej komórki,
      - dokładny LastLogonExact jako maksimum atrybutu lastLogon ze wszystkich dostępnych DC,
      - dokładny LastBadPasswordAttemptExact jako maksimum badPasswordTime ze wszystkich dostępnych DC,
      - nazwę DC, z którego pochodzi każda z tych wartości.

    Dla wydajności skrypt nie odpytuje każdego DC osobno dla każdego użytkownika.
    Zamiast tego wykonuje jeden lekki odczyt użytkowników na każdy DC i buduje indeks po ObjectGUID.

.PARAMETER Domain
    Domena DNS albo kontroler domeny, np. corp.example.com lub dc01.corp.example.com.
    Jeśli pominięty, używana jest bieżąca domena komputera/użytkownika.
    Alias: -Server, -DomainController.

.PARAMETER SearchBase
    Opcjonalny DN OU/kontenera ograniczający eksport użytkowników.

.PARAMETER OutputPath
    Ścieżka wynikowego CSV.

.PARAMETER Delimiter
    Separator CSV. Domyślnie średnik, odpowiedni dla typowej polskiej konfiguracji Excela.

.PARAMETER Encoding
    Kodowanie CSV. Domyślnie utf8BOM.
    W Windows PowerShell 5.1 utf8BOM jest mapowane na UTF8, które zapisuje BOM.

.PARAMETER MultiValueSeparator
    Separator używany wewnątrz jednej komórki dla atrybutów wielowartościowych.
    Domyślnie " | ".

.EXAMPLE
    .\Export-AllADUsers.ps1 -Domain corp.example.com

.EXAMPLE
    .\Export-AllADUsers.ps1 -Domain corp.example.com -SearchBase "OU=Users,DC=corp,DC=example,DC=com" -OutputPath C:\Temp\AD-AllUsers.csv

.NOTES
    Wymaga modułu ActiveDirectory (RSAT).

    LastLogonExact:
      atrybut lastLogon nie jest replikowany, dlatego poprawna wartość wymaga maksimum ze wszystkich DC.

    LastBadPasswordAttemptExact:
      bazuje na badPasswordTime, który również nie jest replikowany.
      Oznacza ostatnią próbę z błędnym hasłem, a nie każdy możliwy typ nieudanego logowania.

    Jeśli któryś DC jest niedostępny, skrypt zapisze ostrzeżenie, a wartości "Exact" będą maksimum
    wyłącznie z DC, które udało się odczytać.
#>

[CmdletBinding()]
param(
    [Alias("Server","DomainController")]
    [string]$Domain,

    [string]$SearchBase,

    [string]$OutputPath = (Join-Path $PWD ("AD-AllUsers-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")),

    [char]$Delimiter = ";",

    [ValidateSet("utf8", "utf8BOM", "unicode", "ascii")]
    [string]$Encoding = "utf8BOM",

    [string]$MultiValueSeparator = " | "
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

$adServerParams = @{}
if ($Domain) { $adServerParams.Server = $Domain }

function Convert-FileTime {
    param($Value)

    if ($null -eq $Value) { return $null }
    try {
        $v = [Int64]$Value
        if ($v -le 0 -or $v -eq [Int64]::MaxValue) { return $null }
        return [DateTime]::FromFileTimeUtc($v).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-CompatibleCsvEncoding {
    param([Parameter(Mandatory)][string]$RequestedEncoding)

    if ($PSVersionTable.PSVersion.Major -lt 6 -and $RequestedEncoding -eq "utf8BOM") {
        return "UTF8"
    }
    return $RequestedEncoding
}

function Convert-ToExcelValue {
    param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [DateTime]) {
        return $Value.ToString("yyyy-MM-dd HH:mm:ss")
    }

    if ($Value -is [DateTimeOffset]) {
        return $Value.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    }

    if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
        return $Value.Value
    }

    if ($Value -is [Guid]) {
        return $Value.Guid
    }

    if ($Value -is [byte[]]) {
        return "base64:" + [Convert]::ToBase64String($Value)
    }

    if ($Value -is [bool]) {
        return $Value.ToString()
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $pairs = foreach ($key in $Value.Keys) {
            "{0}={1}" -f $key, (Convert-ToExcelValue $Value[$key])
        }
        return ($pairs -join $MultiValueSeparator)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = foreach ($item in $Value) {
            Convert-ToExcelValue $item
        }
        return ($items -join $MultiValueSeparator)
    }

    try {
        return [string]$Value
    }
    catch {
        return $Value.ToString()
    }
}

Write-Host "Odnajdywanie kontrolerów domeny..." -ForegroundColor Cyan
$dcs = @(Get-ADDomainController -Filter * @adServerParams | Sort-Object HostName)
if ($dcs.Count -eq 0) {
    throw "Nie znaleziono kontrolerów domeny."
}

Write-Host ("Kontrolery domeny: {0}" -f (($dcs.HostName) -join ", ")) -ForegroundColor Cyan

# Dokładne lastLogon i badPasswordTime są agregowane po ObjectGUID.
$logonIndex = @{}
$successfulDcReads = 0

foreach ($dc in $dcs) {
    Write-Host ("Odczyt lastLogon/badPasswordTime z {0}..." -f $dc.HostName) -ForegroundColor DarkCyan

    try {
        $dcUserParams = @{
            Filter = "*"
            Server = $dc.HostName
            Properties = @("lastLogon","badPasswordTime","ObjectGUID")
            ErrorAction = "Stop"
        }
        if ($SearchBase) { $dcUserParams.SearchBase = $SearchBase }

        $dcUsers = Get-ADUser @dcUserParams
        $successfulDcReads++

        foreach ($user in $dcUsers) {
            $key = $user.ObjectGUID.ToString()

            if (-not $logonIndex.ContainsKey($key)) {
                $logonIndex[$key] = [PSCustomObject]@{
                    LastLogonRaw = [Int64]0
                    LastLogonSourceDC = $null
                    LastBadRaw = [Int64]0
                    LastBadSourceDC = $null
                }
            }

            $entry = $logonIndex[$key]

            if ($null -ne $user.lastLogon) {
                $v = [Int64]$user.lastLogon
                if ($v -gt $entry.LastLogonRaw) {
                    $entry.LastLogonRaw = $v
                    $entry.LastLogonSourceDC = $dc.HostName
                }
            }

            if ($null -ne $user.badPasswordTime) {
                $v = [Int64]$user.badPasswordTime
                if ($v -gt $entry.LastBadRaw) {
                    $entry.LastBadRaw = $v
                    $entry.LastBadSourceDC = $dc.HostName
                }
            }
        }
    }
    catch {
        Write-Warning ("Nie udało się odczytać DC {0}: {1}" -f $dc.HostName, $_.Exception.Message)
    }
}

if ($successfulDcReads -eq 0) {
    throw "Nie udało się odczytać danych logowania z żadnego kontrolera domeny."
}

Write-Host "Pobieranie wszystkich użytkowników i wszystkich właściwości..." -ForegroundColor Cyan

$userParams = @{
    Filter = "*"
    Properties = "*"
}
if ($SearchBase) { $userParams.SearchBase = $SearchBase }

$users = @(Get-ADUser @userParams @adServerParams)
Write-Host ("Znaleziono użytkowników: {0}" -f $users.Count) -ForegroundColor Cyan

if ($users.Count -eq 0) {
    throw "Nie znaleziono użytkowników spełniających kryteria."
}

# Zbuduj sumę wszystkich nazw właściwości występujących w zwróconych obiektach.
# Dzięki temu atrybut ustawiony tylko u części użytkowników nadal dostaje własną kolumnę.
$propertySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($user in $users) {
    foreach ($property in $user.PSObject.Properties) {
        [void]$propertySet.Add($property.Name)
    }
}

# Najważniejsze kolumny na początku, reszta alfabetycznie.
$preferredColumns = @(
    "SamAccountName",
    "UserPrincipalName",
    "DisplayName",
    "Name",
    "Enabled",
    "DistinguishedName",
    "ObjectGUID",
    "LastLogonExact",
    "LastLogonSourceDC",
    "LastBadPasswordAttemptExact",
    "LastBadPasswordSourceDC",
    "LastLogonDate",
    "lastLogon",
    "lastLogonTimestamp",
    "badPasswordTime",
    "mail",
    "employeeID",
    "employeeType",
    "extensionAttribute2",
    "extensionAttribute13",
    "whenCreated",
    "whenChanged"
)

$allPropertyNames = @($propertySet | Sort-Object)
$remainingColumns = @(
    $allPropertyNames | Where-Object {
        $name = $_
        -not ($preferredColumns -contains $name) -and
        $name -notin @("LastLogonExact","LastLogonSourceDC","LastBadPasswordAttemptExact","LastBadPasswordSourceDC")
    }
)

$columns = [System.Collections.Generic.List[string]]::new()

foreach ($column in $preferredColumns) {
    if (
        $column -in @("LastLogonExact","LastLogonSourceDC","LastBadPasswordAttemptExact","LastBadPasswordSourceDC") -or
        $propertySet.Contains($column)
    ) {
        if (-not $columns.Contains($column)) { $columns.Add($column) }
    }
}

foreach ($column in $remainingColumns) {
    if (-not $columns.Contains($column)) { $columns.Add($column) }
}

Write-Host ("Kolumn w CSV: {0}" -f $columns.Count) -ForegroundColor Cyan
Write-Host "Przygotowywanie danych do CSV..." -ForegroundColor Cyan

$rows = [System.Collections.Generic.List[object]]::new()
$counter = 0

foreach ($user in $users) {
    $counter++

    Write-Progress -Activity "Przygotowywanie eksportu użytkowników AD" -Status ("{0}/{1}: {2}" -f $counter,$users.Count,$user.SamAccountName) -PercentComplete (($counter / [math]::Max($users.Count,1))*100)

    $guidKey = $user.ObjectGUID.ToString()
    $timeEntry = $null
    if ($logonIndex.ContainsKey($guidKey)) {
        $timeEntry = $logonIndex[$guidKey]
    }

    $ordered = [ordered]@{}

    foreach ($column in $columns) {
        switch ($column) {
            "LastLogonExact" {
                $ordered[$column] = if ($timeEntry) { Convert-ToExcelValue (Convert-FileTime $timeEntry.LastLogonRaw) } else { $null }
            }
            "LastLogonSourceDC" {
                $ordered[$column] = if ($timeEntry) { $timeEntry.LastLogonSourceDC } else { $null }
            }
            "LastBadPasswordAttemptExact" {
                $ordered[$column] = if ($timeEntry) { Convert-ToExcelValue (Convert-FileTime $timeEntry.LastBadRaw) } else { $null }
            }
            "LastBadPasswordSourceDC" {
                $ordered[$column] = if ($timeEntry) { $timeEntry.LastBadSourceDC } else { $null }
            }
            default {
                $property = $user.PSObject.Properties[$column]
                if ($null -ne $property) {
                    $ordered[$column] = Convert-ToExcelValue $property.Value
                }
                else {
                    $ordered[$column] = $null
                }
            }
        }
    }

    $rows.Add([PSCustomObject]$ordered)
}

Write-Progress -Activity "Przygotowywanie eksportu użytkowników AD" -Completed

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$csvEncoding = Get-CompatibleCsvEncoding -RequestedEncoding $Encoding
$rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Delimiter $Delimiter -Encoding $csvEncoding

Write-Host ""
Write-Host "Eksport zakończony." -ForegroundColor Green
Write-Host ("Użytkownicy:           {0}" -f $users.Count)
Write-Host ("Kolumny:               {0}" -f $columns.Count)
Write-Host ("DC odczytane:          {0}/{1}" -f $successfulDcReads,$dcs.Count)
Write-Host ("Plik:                  {0}" -f $OutputPath)

if ($successfulDcReads -lt $dcs.Count) {
    Write-Warning "Nie wszystkie DC były dostępne. Kolumny Exact są maksimum z dostępnych kontrolerów domeny."
}

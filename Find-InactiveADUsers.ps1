#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Znajduje konta użytkowników AD, które nie logowały się przez wskazaną liczbę dni.

.DESCRIPTION
    Pobiera użytkowników z domeny i filtruje konta, których LastLogonDate jest starsze niż
    wskazany próg albo jest puste (konto nigdy się nie logowało). Domyślnie raport obejmuje
    tylko konta włączone.

    LastLogonDate bazuje na replikowanym lastLogonTimestamp. Jest odpowiedni do raportów
    nieaktywności, ale nie do ustalania dokładnego czasu ostatniego logowania.

.PARAMETER Days
    Liczba dni nieaktywności, np. 90.

.PARAMETER Domain
    Domena DNS albo serwer AD przekazywany do Get-ADUser -Server.

.PARAMETER OutputPath
    Ścieżka wynikowego CSV. Domyślnie .\Inactive-AD-Users.csv.

.PARAMETER IncludeDisabled
    Uwzględnia również konta wyłączone.

.EXAMPLE
    .\Find-InactiveADUsers.ps1 -Days 90 -Domain corp.example.com
    Zwraca włączone konta nieaktywne od co najmniej 90 dni.

.EXAMPLE
    .\Find-InactiveADUsers.ps1 -Days 180 -Domain corp.example.com -IncludeDisabled -OutputPath C:\Temp\InactiveUsers.csv
    Uwzględnia również konta wyłączone i zapisuje raport do wskazanego pliku.

.NOTES
    Wymaga modułu ActiveDirectory (RSAT). Konta bez LastLogonDate są oznaczane NeverLoggedOn=True.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateRange(1,36500)]
    [int]$Days,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [string]$OutputPath = ".\Inactive-AD-Users.csv",

    [switch]$IncludeDisabled
)

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff = (Get-Date).AddDays(-$Days)

$users = Get-ADUser `
    -Filter * `
    -Server $Domain `
    -Properties LastLogonDate, Enabled, PasswordLastSet, WhenCreated, UserPrincipalName

$result = $users | Where-Object {
    $enabledCondition = $IncludeDisabled -or $_.Enabled
    $inactiveCondition = ($null -eq $_.LastLogonDate) -or ($_.LastLogonDate -lt $cutoff)
    $enabledCondition -and $inactiveCondition
} | Select-Object `
    SamAccountName,
    UserPrincipalName,
    Enabled,
    LastLogonDate,
    PasswordLastSet,
    WhenCreated,
    @{
        Name = "DaysSinceLastLogon"
        Expression = {
            if ($null -eq $_.LastLogonDate) {
                $null
            }
            else {
                [math]::Floor(((Get-Date) - $_.LastLogonDate).TotalDays)
            }
        }
    },
    @{
        Name = "NeverLoggedOn"
        Expression = {
            $null -eq $_.LastLogonDate
        }
    },
    DistinguishedName

$result |
    Sort-Object LastLogonDate |
    Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -Encoding UTF8 `
        -Delimiter ";"

Write-Host "Próg nieaktywności: $Days dni"
Write-Host "Data graniczna:     $cutoff"
Write-Host "Znaleziono kont:    $($result.Count)"
Write-Host "CSV:                $OutputPath"

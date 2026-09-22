#requires -Modules ActiveDirectory

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

#requires -Version 5.1
#requires -Modules ActiveDirectory
<#
.SYNOPSIS
  Eksportuje stan wskazanych kont AD na podstawie listy sAMAccountName.

.DESCRIPTION
  Wejście: plik tekstowy z jednym sAMAccountName w linii + domena DNS.
  Dla dokładnego LastLogon i BadPasswordTime skrypt odpytuje wszystkie DC w domenie,
  ponieważ lastLogon i badPasswordTime nie są replikowane.

  DisabledDateApprox jest wyliczane z metadanych replikacji userAccountControl.
  To NIE jest gwarantowana data wyłączenia konta: userAccountControl może zmieniać się
  także z innych powodów. Dokładną datę wyłączenia należy brać z Security Event ID 4725.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$InputFile,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Domain,
  [string]$OutputPath = (Join-Path $PWD ("AD-User-State-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")),
  [char]$Delimiter = ";",
  [ValidateSet("utf8","utf8BOM","unicode","ascii")][string]$Encoding = "utf8BOM"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

function Convert-FileTime {
  param($Value)
  if ($null -eq $Value) { return $null }
  try {
    $v = [Int64]$Value
    if ($v -le 0 -or $v -eq [Int64]::MaxValue) { return $null }
    return [DateTime]::FromFileTimeUtc($v).ToLocalTime()
  } catch { return $null }
}

function Get-MaxNonReplicatedTime {
  param(
    [Parameter(Mandatory)][string]$DistinguishedName,
    [Parameter(Mandatory)][string]$AttributeName,
    [Parameter(Mandatory)][object[]]$DomainControllers
  )

  $max = [Int64]0
  $sourceDC = $null
  foreach ($dc in $DomainControllers) {
    try {
      $u = Get-ADUser -Identity $DistinguishedName -Server $dc.HostName -Properties $AttributeName -ErrorAction Stop
      $raw = $u.$AttributeName
      if ($null -ne $raw) {
        $v = [Int64]$raw
        if ($v -gt $max) { $max = $v; $sourceDC = $dc.HostName }
      }
    } catch {
      Write-Warning ("Nie udało się odczytać {0} dla {1} z DC {2}: {3}" -f $AttributeName,$DistinguishedName,$dc.HostName,$_.Exception.Message)
    }
  }

  [PSCustomObject]@{
    RawValue = $max
    Date = if ($max -gt 0) { Convert-FileTime $max } else { $null }
    SourceDC = $sourceDC
  }
}

function Get-UacChangeApproximation {
  param([string]$DistinguishedName,[string]$Server)
  try {
    $m = Get-ADReplicationAttributeMetadata -Object $DistinguishedName -Server $Server -Properties userAccountControl -ErrorAction Stop |
      Where-Object AttributeName -eq "userAccountControl" | Select-Object -First 1
    if ($m) { return $m.LastOriginatingChangeTime }
  } catch {
    Write-Warning ("Nie udało się pobrać metadanych userAccountControl dla {0}: {1}" -f $DistinguishedName,$_.Exception.Message)
  }
  return $null
}

$domainInfo = Get-ADDomain -Identity $Domain -Server $Domain
$dcs = @(Get-ADDomainController -Filter * -Server $Domain | Sort-Object HostName)
if ($dcs.Count -eq 0) { throw "Nie znaleziono kontrolerów domeny dla $Domain" }
$referenceDC = $dcs[0].HostName

$samAccounts = @(Get-Content -LiteralPath $InputFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") } | Sort-Object -Unique)
if ($samAccounts.Count -eq 0) { throw "Lista wejściowa jest pusta." }

$rows = foreach ($sam in $samAccounts) {
  try {
    $escaped = $sam.Replace("'","''")
    $user = Get-ADUser -Filter "SamAccountName -eq '$escaped'" -Server $Domain -Properties @(
      "Enabled","LockedOut","lockoutTime","PasswordExpired","PasswordNeverExpires","PasswordLastSet",
      "msDS-UserPasswordExpiryTimeComputed","AccountExpirationDate","whenChanged","DistinguishedName",
      "UserPrincipalName","DisplayName","userAccountControl"
    ) | Select-Object -First 1

    if ($null -eq $user) {
      [PSCustomObject]@{
        SamAccountName=$sam; Found=$false; Domain=$Domain; DisplayName=$null; UserPrincipalName=$null;
        Enabled=$null; DisabledDateApprox=$null; DisabledDateSource="NotFound";
        LastLogon=$null; LastLogonSourceDC=$null; LastBadPassword=$null; LastBadPasswordSourceDC=$null;
        PasswordLastSet=$null; PasswordNeverExpires=$null; PasswordExpired=$null; PasswordExpiryDate=$null;
        LockedOut=$null; LockoutTime=$null; AccountExpirationDate=$null; DistinguishedName=$null; Error="User not found"
      }
      continue
    }

    $lastLogon = Get-MaxNonReplicatedTime -DistinguishedName $user.DistinguishedName -AttributeName "lastLogon" -DomainControllers $dcs
    $lastBad   = Get-MaxNonReplicatedTime -DistinguishedName $user.DistinguishedName -AttributeName "badPasswordTime" -DomainControllers $dcs

    $expiry = $null
    if (-not $user.PasswordNeverExpires) {
      $expiry = Convert-FileTime $user."msDS-UserPasswordExpiryTimeComputed"
    }

    $disabledApprox = $null
    $disabledSource = $null
    if (-not $user.Enabled) {
      $disabledApprox = Get-UacChangeApproximation -DistinguishedName $user.DistinguishedName -Server $referenceDC
      $disabledSource = "userAccountControl replication metadata; approximate only"
    }

    [PSCustomObject]@{
      SamAccountName=$user.SamAccountName
      Found=$true
      Domain=$Domain
      DisplayName=$user.DisplayName
      UserPrincipalName=$user.UserPrincipalName
      Enabled=$user.Enabled
      DisabledDateApprox=$disabledApprox
      DisabledDateSource=$disabledSource
      LastLogon=$lastLogon.Date
      LastLogonSourceDC=$lastLogon.SourceDC
      LastBadPassword=$lastBad.Date
      LastBadPasswordSourceDC=$lastBad.SourceDC
      PasswordLastSet=$user.PasswordLastSet
      PasswordNeverExpires=$user.PasswordNeverExpires
      PasswordExpired=$user.PasswordExpired
      PasswordExpiryDate=$expiry
      LockedOut=$user.LockedOut
      LockoutTime=(Convert-FileTime $user.lockoutTime)
      AccountExpirationDate=$user.AccountExpirationDate
      DistinguishedName=$user.DistinguishedName
      Error=$null
    }
  } catch {
    [PSCustomObject]@{
      SamAccountName=$sam; Found=$false; Domain=$Domain; DisplayName=$null; UserPrincipalName=$null;
      Enabled=$null; DisabledDateApprox=$null; DisabledDateSource=$null;
      LastLogon=$null; LastLogonSourceDC=$null; LastBadPassword=$null; LastBadPasswordSourceDC=$null;
      PasswordLastSet=$null; PasswordNeverExpires=$null; PasswordExpired=$null; PasswordExpiryDate=$null;
      LockedOut=$null; LockoutTime=$null; AccountExpirationDate=$null; DistinguishedName=$null; Error=$_.Exception.Message
    }
  }
}

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
Write-Host ("Wyeksportowano {0} rekordów do {1}" -f $rows.Count,$OutputPath) -ForegroundColor Green
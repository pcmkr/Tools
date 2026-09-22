#requires -Version 5.1
<#
.SYNOPSIS
    Eksportuje użytkowników CyberArk PAM i ich role/autoryzacje do CSV.

.DESCRIPTION
    Korzysta wyłącznie z endpointu /api/Users. Nie pobiera Safe, kont ani członkostwa w Safe.
    Raport obejmuje m.in. UserType, Source, stan konta i VaultAuthorization.

.PARAMETER PVWAURL
    Bazowy URL PVWA, np. https://pvwa.example.com/PasswordVault.

.PARAMETER AuthType
    Metoda logowania: CyberArk, LDAP albo Radius.

.PARAMETER Credential
    Opcjonalny PSCredential. Jeśli brak, skrypt wywoła Get-Credential.

.PARAMETER OutputPath
    Ścieżka wynikowego CSV.

.PARAMETER PageSize
    Liczba użytkowników pobieranych na stronę API.

.PARAMETER Encoding
    Kodowanie CSV. Domyślnie utf8BOM.

.PARAMETER Delimiter
    Separator CSV. Domyślnie średnik.

.EXAMPLE
    .\Export-CyberArkUsers.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AuthType LDAP
    Loguje się przez LDAP i eksportuje użytkowników PAM.

.EXAMPLE
    .\Export-CyberArkUsers.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AuthType CyberArk -OutputPath C:\Temp\CyberArk-Users.csv
    Eksportuje użytkowników do wskazanego pliku.

.NOTES
    Konto używane do raportu musi mieć uprawnienie pozwalające odczytać /api/Users.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$PVWAURL,
  [ValidateSet("CyberArk","LDAP","Radius")][string]$AuthType = "CyberArk",
  [System.Management.Automation.PSCredential]$Credential,
  [string]$OutputPath = (Join-Path $PWD ("CyberArk-PAM-Users-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")),
  [ValidateRange(1,1000)][int]$PageSize = 1000,
  [ValidateSet("utf8","utf8BOM","unicode","ascii")][string]$Encoding = "utf8BOM",
  [char]$Delimiter = ";"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PVWAURL = $PVWAURL.TrimEnd("/")

function Get-Prop {
  param($Object,[string[]]$Names)
  if ($null -eq $Object) { return $null }
  foreach ($n in $Names) {
    $p = $Object.PSObject.Properties[$n]
    if ($null -ne $p) { return $p.Value }
  }
  return $null
}

function Join-Values {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    return (($Value | ForEach-Object { [string]$_ }) -join "|")
  }
  return [string]$Value
}

function Resolve-NextLink {
  param([string]$NextLink)
  if ([string]::IsNullOrWhiteSpace($NextLink)) { return $null }
  if ($NextLink -match "^https?://") { return $NextLink }
  if ($NextLink.StartsWith("/")) {
    $u = [uri]$PVWAURL
    return ($u.Scheme + "://" + $u.Authority + $NextLink)
  }
  return ($PVWAURL + "/" + $NextLink.TrimStart("/"))
}

if ($null -eq $Credential) {
  $Credential = Get-Credential -Message "Dane logowania do CyberArk PAM"
}

$token = $null
$headers = $null

try {
  Write-Host "Logowanie do CyberArk PAM..." -ForegroundColor Cyan

  $body = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
    concurrentSession = $true
  } | ConvertTo-Json

  $token = Invoke-RestMethod -Method Post -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -ContentType "application/json" -Body $body -TimeoutSec 120

  if ($token -isnot [string]) {
    $token = Get-Prop $token @("CyberArkLogonResult","token","Token")
  }

  if ([string]::IsNullOrWhiteSpace([string]$token)) {
    throw "CyberArk zwrócił pusty token logowania."
  }

  $headers = @{ Authorization = [string]$token }

  Write-Host "Pobieranie użytkowników..." -ForegroundColor Cyan

  $users = [System.Collections.Generic.List[object]]::new()
  $next = "$PVWAURL/api/Users?limit=$PageSize"

  while ($next) {
    $response = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ContentType "application/json" -TimeoutSec 300

    $items = $null
    foreach ($name in @("Users","users","value")) {
      $p = $response.PSObject.Properties[$name]
      if ($null -ne $p) {
        $items = @($p.Value)
        break
      }
    }

    if ($null -eq $items) { $items = @($response) }

    foreach ($u in $items) {
      if ($null -ne $u) { $users.Add($u) }
    }

    $next = Resolve-NextLink (Get-Prop $response @("nextLink","NextLink"))
  }

  $rows = foreach ($u in $users) {
    [PSCustomObject]@{
      UserName = Get-Prop $u @("username","userName","UserName")
      UserType = Get-Prop $u @("userType","UserType")
      Source = Get-Prop $u @("source","Source")
      DistinguishedName = Get-Prop $u @("distinguishedName","DistinguishedName")
      ComponentUser = Get-Prop $u @("componentUser","ComponentUser")
      IsEnabled = Get-Prop $u @("enableUser","isEnabled","Enabled")
      IsSuspended = Get-Prop $u @("suspended","isSuspended","Suspended")
      VaultAuthorization = Join-Values (Get-Prop $u @("vaultAuthorization","VaultAuthorization"))
      Location = Get-Prop $u @("location","Location")
      Description = Get-Prop $u @("description","Description")
      BusinessAddress = Get-Prop $u @("businessAddress","BusinessAddress")
      Internet = Get-Prop $u @("internet","Internet")
      Phones = Join-Values (Get-Prop $u @("phones","Phones"))
      Email = Get-Prop $u @("email","Email")
      LastSuccessfulLoginDate = Get-Prop $u @("lastSuccessfulLoginDate","LastSuccessfulLoginDate")
    }
  }

  $outputDir = Split-Path -Parent $OutputPath
  if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
  }

  $rows | Sort-Object UserName | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding

  Write-Host ""
  Write-Host "Eksport zakończony." -ForegroundColor Green
  Write-Host ("Użytkownicy: {0}" -f $users.Count)
  Write-Host ("Plik:       {0}" -f $OutputPath)
}
finally {
  if ($headers -and $token) {
    try {
      Invoke-RestMethod -Method Post -Uri "$PVWAURL/api/Auth/Logoff" -Headers $headers -ContentType "application/json" -TimeoutSec 60 | Out-Null
    } catch {
      Write-Warning ("Nie udało się wylogować sesji CyberArk: " + $_.Exception.Message)
    }
  }
}
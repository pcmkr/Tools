#requires -Version 5.1
<#
.SYNOPSIS
    Eksportuje użytkowników, Safe, członków Safe, konta i macierz dostępu z CyberArk PAM.

.DESCRIPTION
    Korzysta z CyberArk PVWA REST API. Tworzy raporty PAM-Users.csv, PAM-Safes.csv,
    PAM-SafeMembers.csv, PAM-Accounts.csv, PAM-AccountAccess.csv, PAM-EffectiveAccess.csv
    oraz Errors.csv, jeśli wystąpią problemy.

.PARAMETER PVWAURL
    Bazowy URL PVWA, np. https://pvwa.example.com/PasswordVault.

.PARAMETER AuthType
    Metoda logowania: CyberArk, LDAP albo Radius.

.PARAMETER Credential
    Opcjonalny PSCredential. Jeśli brak, skrypt wywoła Get-Credential.

.PARAMETER OutputDirectory
    Katalog wynikowy raportu.

.PARAMETER ExpandADGroups
    Rozwija grupy AD będące członkami Safe do konkretnych użytkowników.

.PARAMETER ADDomain
    Domena AD używana do rozwijania grup, np. corp.example.com.

.PARAMETER ADServer
    Opcjonalny konkretny kontroler domeny.

.PARAMETER SkipUsers
    Pomija endpoint /api/Users, gdy konto raportujące nie ma prawa do listy użytkowników PAM.

.PARAMETER PageSize
    Liczba obiektów pobieranych na stronę API.

.PARAMETER Encoding
    Kodowanie plików CSV.

.PARAMETER Delimiter
    Separator CSV.

.EXAMPLE
    .\Export-CyberArkAccess.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AuthType LDAP
    Eksportuje użytkowników, Safe, konta i bezpośrednie relacje dostępu.

.EXAMPLE
    .\Export-CyberArkAccess.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AuthType LDAP -ExpandADGroups -ADDomain "corp.example.com"
    Dodatkowo rozwija grupy AD do efektywnych użytkowników.

.EXAMPLE
    .\Export-CyberArkAccess.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AuthType CyberArk -SkipUsers -OutputDirectory C:\Temp\PAMAudit
    Pomija listę użytkowników PAM i zapisuje pozostałe raporty we wskazanym katalogu.

.NOTES
    Pełność wyniku zależy od uprawnień konta raportującego w CyberArk.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PVWAURL,
  [ValidateSet("CyberArk","LDAP","Radius")][string]$AuthType = "CyberArk",
  [System.Management.Automation.PSCredential]$Credential,
  [string]$OutputDirectory = (Join-Path $PWD ("CyberArk-Access-Export-" + (Get-Date -Format "yyyyMMdd-HHmmss"))),
  [switch]$ExpandADGroups,
  [string]$ADDomain,
  [string]$ADServer,
  [switch]$SkipUsers,
  [ValidateRange(1,1000)][int]$PageSize = 1000,
  [ValidateSet("utf8","utf8BOM","unicode","ascii")][string]$Encoding = "utf8BOM",
  [char]$Delimiter = ";"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PVWAURL = $PVWAURL.TrimEnd("/")
if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

$errors = [System.Collections.Generic.List[object]]::new()
$token = $null
$headers = $null

function Add-ReportError {
  param([string]$Operation,[string]$Object,[string]$Message)
  $errors.Add([PSCustomObject]@{ Timestamp=Get-Date; Operation=$Operation; Object=$Object; Error=$Message })
}

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
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) { return (($Value | ForEach-Object { [string]$_ }) -join "|") }
  return [string]$Value
}

function Resolve-NextLink {
  param([string]$NextLink)
  if ([string]::IsNullOrWhiteSpace($NextLink)) { return $null }
  if ($NextLink -match "^https?://") { return $NextLink }
  if ($NextLink.StartsWith("/")) {
    $u=[uri]$PVWAURL
    return ($u.Scheme + "://" + $u.Authority + $NextLink)
  }
  return ($PVWAURL + "/" + $NextLink.TrimStart("/"))
}

function Get-Paged {
  param([string]$Uri,[string[]]$CollectionProperties,[string]$Operation)
  $result=[System.Collections.Generic.List[object]]::new()
  $next=$Uri
  while ($next) {
    try {
      $r=Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ContentType "application/json" -TimeoutSec 300
    } catch {
      Add-ReportError $Operation $next $_.Exception.Message
      throw
    }
    $items=$null
    foreach ($p in $CollectionProperties) {
      $prop=$r.PSObject.Properties[$p]
      if ($null -ne $prop) { $items=@($prop.Value); break }
    }
    if ($null -eq $items) { $items=@($r) }
    foreach ($i in $items) { if ($null -ne $i) { $result.Add($i) } }
    $next=Resolve-NextLink (Get-Prop $r @("nextLink","NextLink"))
  }
  return @($result)
}

function Get-Permission { param($Permissions,[string]$Name); return (Get-Prop $Permissions @($Name,($Name.Substring(0,1).ToUpper()+$Name.Substring(1)))) }

function Convert-SafeMember {
  param($Safe,$Member)
  $p=Get-Prop $Member @("permissions","Permissions")
  [PSCustomObject]@{
    SafeName=Get-Prop $Safe @("safeName","SafeName")
    SafeUrlId=Get-Prop $Safe @("safeUrlId","SafeUrlId")
    MemberName=Get-Prop $Member @("memberName","MemberName")
    MemberType=Get-Prop $Member @("memberType","MemberType")
    MemberLocation=Get-Prop $Member @("memberLocation","MemberLocation")
    MembershipExpirationDate=Get-Prop $Member @("membershipExpirationDate","MembershipExpirationDate")
    UseAccounts=Get-Permission $p "useAccounts"
    RetrieveAccounts=Get-Permission $p "retrieveAccounts"
    ListAccounts=Get-Permission $p "listAccounts"
    AddAccounts=Get-Permission $p "addAccounts"
    UpdateAccountContent=Get-Permission $p "updateAccountContent"
    UpdateAccountProperties=Get-Permission $p "updateAccountProperties"
    InitiateCPMAccountManagementOperations=Get-Permission $p "initiateCPMAccountManagementOperations"
    SpecifyNextAccountContent=Get-Permission $p "specifyNextAccountContent"
    RenameAccounts=Get-Permission $p "renameAccounts"
    DeleteAccounts=Get-Permission $p "deleteAccounts"
    UnlockAccounts=Get-Permission $p "unlockAccounts"
    ManageSafe=Get-Permission $p "manageSafe"
    ManageSafeMembers=Get-Permission $p "manageSafeMembers"
    BackupSafe=Get-Permission $p "backupSafe"
    ViewAuditLog=Get-Permission $p "viewAuditLog"
    ViewSafeMembers=Get-Permission $p "viewSafeMembers"
    AccessWithoutConfirmation=Get-Permission $p "accessWithoutConfirmation"
    RequestsAuthorizationLevel=Get-Permission $p "requestsAuthorizationLevel"
    RequestsAuthorizationLevel1=Get-Permission $p "requestsAuthorizationLevel1"
    RequestsAuthorizationLevel2=Get-Permission $p "requestsAuthorizationLevel2"
    CreateFolders=Get-Permission $p "createFolders"
    DeleteFolders=Get-Permission $p "deleteFolders"
    MoveAccountsAndFolders=Get-Permission $p "moveAccountsAndFolders"
  }
}

function Get-SafeMembers {
  param($Safe)
  $name=[string](Get-Prop $Safe @("safeName","SafeName"))
  $id=[string](Get-Prop $Safe @("safeUrlId","SafeUrlId"))
  if ([string]::IsNullOrWhiteSpace($id)) { $id=$name }
  $id=[uri]::EscapeDataString($id)
  try {
    return Get-Paged "$PVWAURL/api/Safes/$id/Members?limit=$PageSize" @("value","Members","members") ("Get Safe Members: "+$name)
  } catch {
    Write-Warning ("Nie udało się pobrać członków Safe: "+$name)
    return @()
  }
}

function Build-PAMUserIndex {
  param([object[]]$Users)
  $idx=@{}
  foreach ($u in $Users) {
    foreach ($k in @([string](Get-Prop $u @("username","userName","UserName")),[string](Get-Prop $u @("distinguishedName","DistinguishedName")))) {
      if (-not [string]::IsNullOrWhiteSpace($k)) { $idx[$k.ToLowerInvariant()]=$u }
    }
  }
  return $idx
}

function Find-PAMUser {
  param([hashtable]$Index,[string[]]$Keys)
  foreach ($k in $Keys) {
    if (-not [string]::IsNullOrWhiteSpace($k) -and $Index.ContainsKey($k.ToLowerInvariant())) { return $Index[$k.ToLowerInvariant()] }
  }
  return $null
}

function Resolve-ADGroupUsers {
  param([string]$GroupName)
  $sp=@{}
  if ($ADServer) { $sp.Server=$ADServer } elseif ($ADDomain) { $sp.Server=$ADDomain }
  try {
    $escaped=$GroupName.Replace("'","''")
    $g=Get-ADGroup -Filter "Name -eq '$escaped' -or SamAccountName -eq '$escaped'" @sp | Select-Object -First 1
    if ($null -eq $g) { Add-ReportError "Resolve AD group" $GroupName "Nie znaleziono grupy AD"; return @() }
    $out=foreach ($m in @(Get-ADGroupMember -Identity $g.DistinguishedName -Recursive @sp | Where-Object ObjectClass -eq "user")) {
      try { Get-ADUser -Identity $m.DistinguishedName -Properties UserPrincipalName,DisplayName,mail,Enabled @sp }
      catch { Add-ReportError "Resolve AD user" $m.DistinguishedName $_.Exception.Message }
    }
    return @($out)
  } catch {
    Add-ReportError "Resolve AD group" $GroupName $_.Exception.Message
    return @()
  }
}

function New-AccessRow {
  param($Account,$M,[string]$EffectiveUserName,[string]$EffectiveUserUPN,[string]$EffectiveUserDisplayName,[string]$EffectiveUserMail,$EffectiveUserEnabled,[string]$AccessVia,[string]$AccessViaType,$PAMUser)
  [PSCustomObject]@{
    EffectiveUserName=$EffectiveUserName; EffectiveUserUPN=$EffectiveUserUPN; EffectiveUserDisplayName=$EffectiveUserDisplayName; EffectiveUserMail=$EffectiveUserMail; EffectiveUserEnabled=$EffectiveUserEnabled
    PAMUserType=Get-Prop $PAMUser @("userType","UserType"); PAMUserSource=Get-Prop $PAMUser @("source","Source"); PAMUserEnabled=Get-Prop $PAMUser @("enableUser","isEnabled","Enabled"); PAMUserSuspended=Get-Prop $PAMUser @("suspended","isSuspended","Suspended"); PAMVaultAuthorization=Join-Values (Get-Prop $PAMUser @("vaultAuthorization","VaultAuthorization"))
    AccessVia=$AccessVia; AccessViaType=$AccessViaType; PermissionScope="Safe"; SafeName=$M.SafeName
    AccountId=Get-Prop $Account @("id","Id"); AccountName=Get-Prop $Account @("name","Name"); AccountUserName=Get-Prop $Account @("userName","UserName"); AccountAddress=Get-Prop $Account @("address","Address"); PlatformId=Get-Prop $Account @("platformId","PlatformId"); SecretType=Get-Prop $Account @("secretType","SecretType")
    UseAccounts=$M.UseAccounts; RetrieveAccounts=$M.RetrieveAccounts; ListAccounts=$M.ListAccounts; AddAccounts=$M.AddAccounts; UpdateAccountContent=$M.UpdateAccountContent; UpdateAccountProperties=$M.UpdateAccountProperties
    InitiateCPMAccountManagementOperations=$M.InitiateCPMAccountManagementOperations; SpecifyNextAccountContent=$M.SpecifyNextAccountContent; RenameAccounts=$M.RenameAccounts; DeleteAccounts=$M.DeleteAccounts; UnlockAccounts=$M.UnlockAccounts
    ManageSafe=$M.ManageSafe; ManageSafeMembers=$M.ManageSafeMembers; BackupSafe=$M.BackupSafe; ViewAuditLog=$M.ViewAuditLog; ViewSafeMembers=$M.ViewSafeMembers; AccessWithoutConfirmation=$M.AccessWithoutConfirmation
    RequestsAuthorizationLevel=$M.RequestsAuthorizationLevel; RequestsAuthorizationLevel1=$M.RequestsAuthorizationLevel1; RequestsAuthorizationLevel2=$M.RequestsAuthorizationLevel2; CreateFolders=$M.CreateFolders; DeleteFolders=$M.DeleteFolders; MoveAccountsAndFolders=$M.MoveAccountsAndFolders
  }
}

try {
  if ($ExpandADGroups) { Import-Module ActiveDirectory -ErrorAction Stop }
  if ($null -eq $Credential) { $Credential=Get-Credential -Message "Dane logowania do CyberArk PAM" }

  $body=@{ username=$Credential.UserName; password=$Credential.GetNetworkCredential().Password; concurrentSession=$true } | ConvertTo-Json
  Write-Host "Logowanie do CyberArk..." -ForegroundColor Cyan
  $token=Invoke-RestMethod -Method Post -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -ContentType "application/json" -Body $body -TimeoutSec 120
  if ($token -isnot [string]) { $token=Get-Prop $token @("CyberArkLogonResult","token","Token") }
  if ([string]::IsNullOrWhiteSpace([string]$token)) { throw "CyberArk zwrócił pusty token." }
  $headers=@{ Authorization=[string]$token }

  $users=@()
  if (-not $SkipUsers) {
    Write-Host "Pobieranie użytkowników PAM..." -ForegroundColor Cyan
    try { $users=@(Get-Paged "$PVWAURL/api/Users?limit=$PageSize" @("Users","users","value") "Get Users") }
    catch { Write-Warning "Brak dostępu do /api/Users. Raport będzie bez pełnych danych o rolach PAM." }
  }

  Write-Host "Pobieranie Safe..." -ForegroundColor Cyan
  $safes=@(Get-Paged "$PVWAURL/api/Safes?limit=$PageSize" @("value","Safes","safes") "Get Safes")
  Write-Host "Pobieranie kont..." -ForegroundColor Cyan
  $accounts=@(Get-Paged "$PVWAURL/api/Accounts?limit=$PageSize" @("value","Accounts","accounts") "Get Accounts")

  $memberRows=[System.Collections.Generic.List[object]]::new()
  $n=0
  foreach ($s in $safes) {
    $n++; $sn=[string](Get-Prop $s @("safeName","SafeName"))
    Write-Progress -Activity "CyberArk Safe Members" -Status "$n/$($safes.Count): $sn" -PercentComplete (($n/[math]::Max($safes.Count,1))*100)
    foreach ($m in @(Get-SafeMembers $s)) { $memberRows.Add((Convert-SafeMember $s $m)) }
  }
  Write-Progress -Activity "CyberArk Safe Members" -Completed

  $userRows=foreach ($u in $users) { [PSCustomObject]@{ UserName=Get-Prop $u @("username","userName","UserName"); UserType=Get-Prop $u @("userType","UserType"); Source=Get-Prop $u @("source","Source"); DistinguishedName=Get-Prop $u @("distinguishedName","DistinguishedName"); ComponentUser=Get-Prop $u @("componentUser","ComponentUser"); IsEnabled=Get-Prop $u @("enableUser","isEnabled","Enabled"); IsSuspended=Get-Prop $u @("suspended","isSuspended","Suspended"); VaultAuthorization=Join-Values (Get-Prop $u @("vaultAuthorization","VaultAuthorization")); Location=Get-Prop $u @("location","Location"); Description=Get-Prop $u @("description","Description") } }

  $safeRows=foreach ($s in $safes) { [PSCustomObject]@{ SafeName=Get-Prop $s @("safeName","SafeName"); SafeUrlId=Get-Prop $s @("safeUrlId","SafeUrlId"); Description=Get-Prop $s @("description","Description"); Location=Get-Prop $s @("location","Location"); ManagingCPM=Get-Prop $s @("managingCPM","ManagingCPM"); NumberOfDaysRetention=Get-Prop $s @("numberOfDaysRetention","NumberOfDaysRetention"); NumberOfVersionsRetention=Get-Prop $s @("numberOfVersionsRetention","NumberOfVersionsRetention"); OLACEnabled=Get-Prop $s @("olacEnabled","OLACEnabled") } }

  $accountRows=foreach ($a in $accounts) { [PSCustomObject]@{ AccountId=Get-Prop $a @("id","Id"); AccountName=Get-Prop $a @("name","Name"); UserName=Get-Prop $a @("userName","UserName"); Address=Get-Prop $a @("address","Address"); SafeName=Get-Prop $a @("safeName","SafeName"); PlatformId=Get-Prop $a @("platformId","PlatformId"); SecretType=Get-Prop $a @("secretType","SecretType"); CreatedTime=Get-Prop $a @("createdTime","CreatedTime") } }

  $accountsBySafe=@{}
  foreach ($a in $accounts) { $sn=[string](Get-Prop $a @("safeName","SafeName")); if (-not $accountsBySafe.ContainsKey($sn)) { $accountsBySafe[$sn]=[System.Collections.Generic.List[object]]::new() }; $accountsBySafe[$sn].Add($a) }
  $pamIndex=Build-PAMUserIndex $users
  $access=[System.Collections.Generic.List[object]]::new()
  $effective=[System.Collections.Generic.List[object]]::new()

  foreach ($m in $memberRows) {
    if (-not $accountsBySafe.ContainsKey([string]$m.SafeName)) { continue }
    $pam=Find-PAMUser $pamIndex @([string]$m.MemberName)
    foreach ($a in $accountsBySafe[[string]$m.SafeName]) {
      $access.Add((New-AccessRow $a $m ([string]$m.MemberName) $null $null $null $null ([string]$m.MemberName) ([string]$m.MemberType) $pam))
      if ($ExpandADGroups -and ([string]$m.MemberType -match "group")) {
        foreach ($adu in @(Resolve-ADGroupUsers ([string]$m.MemberName))) {
          $pu=Find-PAMUser $pamIndex @([string]$adu.SamAccountName,[string]$adu.UserPrincipalName,[string]$adu.DistinguishedName)
          $effective.Add((New-AccessRow $a $m ([string]$adu.SamAccountName) ([string]$adu.UserPrincipalName) ([string]$adu.DisplayName) ([string]$adu.mail) $adu.Enabled ([string]$m.MemberName) "ADGroup" $pu))
        }
      } else {
        $effective.Add((New-AccessRow $a $m ([string]$m.MemberName) $null $null $null $null ([string]$m.MemberName) ([string]$m.MemberType) $pam))
      }
    }
  }

  $userRows | Export-Csv (Join-Path $OutputDirectory "PAM-Users.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
  $safeRows | Export-Csv (Join-Path $OutputDirectory "PAM-Safes.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
  $memberRows | Export-Csv (Join-Path $OutputDirectory "PAM-SafeMembers.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
  $accountRows | Export-Csv (Join-Path $OutputDirectory "PAM-Accounts.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
  $access | Export-Csv (Join-Path $OutputDirectory "PAM-AccountAccess.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
  $effective | Export-Csv (Join-Path $OutputDirectory "PAM-EffectiveAccess.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
  if ($errors.Count -gt 0) { $errors | Export-Csv (Join-Path $OutputDirectory "Errors.csv") -NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding }

  Write-Host ""
  Write-Host "Eksport zakończony." -ForegroundColor Green
  Write-Host ("Użytkownicy PAM:   {0}" -f $users.Count)
  Write-Host ("Safe:              {0}" -f $safes.Count)
  Write-Host ("Członkowie Safe:   {0}" -f $memberRows.Count)
  Write-Host ("Konta:             {0}" -f $accounts.Count)
  Write-Host ("Relacje dostępu:   {0}" -f $access.Count)
  Write-Host ("Efektywne relacje: {0}" -f $effective.Count)
  Write-Host ("Błędy/ostrzeżenia: {0}" -f $errors.Count)
  Write-Host ("Katalog:           {0}" -f $OutputDirectory)
}
finally {
  if ($headers -and $token) {
    try { Invoke-RestMethod -Method Post -Uri "$PVWAURL/api/Auth/Logoff" -Headers $headers -ContentType "application/json" -TimeoutSec 60 | Out-Null }
    catch { Write-Warning ("Nie udało się wylogować sesji CyberArk: "+$_.Exception.Message) }
  }
}
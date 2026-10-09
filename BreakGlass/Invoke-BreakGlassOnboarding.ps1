#requires -Version 5.1
<#
.SYNOPSIS
  Onboarding Break-Glass per PRODUCT, combining Windows and RHEL in one CyberArk Account Group.
.DESCRIPTION
  CSV: product,safeName,groupName,groupPlatformId,os,address,platformId
  One initial SecureString password prompt PER PRODUCT, shared on both operating systems.
  Does not reset existing passwords, Reconcile, or automatically create group membership.
  Enable the latter explicitly with -AssignGroups.
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
 [Parameter(Mandatory)][string]$ManifestCsv,
 [Parameter(Mandatory)][string]$ConfigPath,
 [string]$PVWAURL,
 [ValidateSet('CyberArk','LDAP','Radius')][string]$AuthType,
 [pscredential]$Credential,
 [int]$ExpectedWindows=150,
 [int]$ExpectedRHEL=150,
 [string]$ADServer,
 [switch]$AssignGroups
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$localScript=Join-Path $root 'New-CyberArkLocalAccount.ps1'
$groupScript=Join-Path $root 'Add-CyberArkAccountsToGroup.ps1'
foreach($item in @($ManifestCsv,$ConfigPath,$localScript,$groupScript)){
 if(-not (Test-Path -LiteralPath $item -PathType Leaf)){throw "File missing: $item"}
}
$rows=@(Import-Csv -LiteralPath $ManifestCsv)
if(-not $rows.Count){throw 'Empty manifest.'}
$knownHosts=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$specs=[ordered]@{}
foreach($row in $rows){
 foreach($field in @('product','safeName','groupName','groupPlatformId','os','address','platformId')){
  if([string]::IsNullOrWhiteSpace([string]$row.$field)){throw "Empty field $field in CSV"}
 }
 if($row.os -notin @('Windows','RHEL')){throw "Unknown OS $($row.os)"}
 if(-not $knownHosts.Add($row.address.Trim())){throw "Duplicate server address $($row.address); one local bguser cannot use multiple product passwords."}
 $product=$row.product.Trim()
 if(-not $specs.Contains($product)){
  $specs[$product]=[pscustomobject]@{
   Product=$product; Safe=$row.safeName.Trim(); Group=$row.groupName.Trim(); GroupPlatform=$row.groupPlatformId.Trim()
  }
 }else{
  $spec=$specs[$product]
  if($spec.Safe -ne $row.safeName.Trim() -or $spec.Group -ne $row.groupName.Trim() -or $spec.GroupPlatform -ne $row.groupPlatformId.Trim()){
   throw "Product $product needs exactly one Safe, group and group platform."
  }
 }
}
$products=@($specs.Keys)
foreach($p in $products){
 foreach($q in $products){
  if($p -eq $q){continue}
  if($specs[$p].Safe -eq $specs[$q].Safe){throw "Safe reused across products: $p and $q"}
  if($specs[$p].Group -eq $specs[$q].Group){throw "Group name reused across products: $p and $q"}
 }
}
$windows=@($rows | Where-Object os -eq Windows).Count
$linux=@($rows | Where-Object os -eq RHEL).Count
if($windows -ne $ExpectedWindows -or $linux -ne $ExpectedRHEL){
 throw "Counts Windows=$windows (expected $ExpectedWindows), RHEL=$linux (expected $ExpectedRHEL)."
}
$config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if(-not $PVWAURL){$PVWAURL=[string]$config.defaults.pvwaUrl}
if(-not $AuthType){$AuthType=[string]$config.defaults.authType}
if(-not $PVWAURL -or $AuthType -notin @('CyberArk','LDAP','Radius')){throw 'Invalid PVWA URL / AuthType'}
$PVWAURL=$PVWAURL.TrimEnd('/')
if(-not $Credential){$Credential=Get-Credential -Message 'CyberArk onboarding'}
$secretByProduct=@{}
try{
 if(-not $WhatIfPreference){
  foreach($product in $products){
   $secretByProduct[$product]=Read-Host "Initial password for PRODUCT $product (Windows and RHEL)" -AsSecureString
  }
 }
 $failed=[System.Collections.Generic.List[string]]::new()
 $processed=0
 foreach($row in $rows){
  $params=@{
   SafeName=$row.safeName.Trim()
   OSType=$(if($row.os -eq 'Windows'){'Windows'}else{'RedHat'})
   Address=$row.address.Trim()
   AccountUserName='bguser'
   PlatformId=$row.platformId.Trim()
   ConfigPath=$ConfigPath
   PVWAURL=$PVWAURL
   AuthType=$AuthType
   Credential=$Credential
   AllowExistingSafe=$true
   SkipReconcile=$true
   Confirm=$false
  }
  if($ADServer){$params.ADServer=$ADServer}
  if($secretByProduct.ContainsKey($row.product.Trim())){$params.AccountSecret=$secretByProduct[$row.product.Trim()]}
  if($WhatIfPreference){$params.WhatIf=$true}
  try{& $localScript @params; $processed++}
  catch{$failed.Add("$($row.product) $($row.address): $($_.Exception.Message)")}
 }
 Write-Host "Processed: $processed/$($rows.Count) accounts across $($products.Count) products; failures=$($failed.Count)"
 if($failed.Count -gt 0){
  foreach($failure in $failed){Write-Warning $failure}
  throw 'Incomplete onboarding; no group assignments attempted.'
 }
 if($WhatIfPreference -or -not $AssignGroups){
  Write-Host 'Account Group assignment skipped. Opt-in with -AssignGroups.'
  return
 }
 $token=$null
 $idsPerProduct=@{}
 try{
  $logon=@{username=$Credential.UserName;password=$Credential.GetNetworkCredential().Password;concurrentSession=$true} | ConvertTo-Json
  $response=Invoke-RestMethod -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -Method Post -ContentType 'application/json' -Body $logon -ErrorAction Stop
  $token=if($response -is [string]){$response.Trim()}else{[string]$response.CyberArkLogonResult}
  if(-not $token){throw 'Missing CyberArk token'}
  foreach($product in $products){
   $spec=$specs[$product]
   $all=[System.Collections.Generic.List[object]]::new()
   $offset=0;$limit=100
   do{
    $filter=[uri]::EscapeDataString("safeName eq $($spec.Safe)")
    $response=Invoke-RestMethod -Uri "$PVWAURL/api/Accounts?filter=$filter&limit=$limit&offset=$offset" -Headers @{Authorization=$token} -ErrorAction Stop
    $page=@($response.value | Where-Object {$null -ne $_})
    foreach($account in $page){$all.Add($account)}
    $offset+=$page.Count
    if($offset -gt 10000){throw "Pagination safety limit exceeded for $product"}
   }while($page.Count -eq $limit)
   $ids=[System.Collections.Generic.List[string]]::new()
   foreach($row in @($rows | Where-Object {$_.product.Trim() -eq $product})){
    $matches=@($all | Where-Object {
     $_.safeName -eq $spec.Safe -and $_.address -eq $row.address.Trim() -and
     $_.userName -eq 'bguser' -and $_.platformId -eq $row.platformId.Trim()
    })
    if($matches.Count -ne 1 -or -not $matches[0].id){throw "Missing or duplicate account for $product / $($row.address)"}
    $ids.Add([string]$matches[0].id)
   }
   $idsPerProduct[$product]=@($ids.ToArray())
  }
 }finally{
  if($token){
   try{Invoke-RestMethod -Uri "$PVWAURL/api/Auth/Logoff" -Method Post -Headers @{Authorization=$token} -ErrorAction Stop | Out-Null}
   catch{Write-Warning 'CyberArk Logoff failed'}
  }
 }
 foreach($product in $products){
  $spec=$specs[$product]
  $ids=@($idsPerProduct[$product])
  $allowed=@($rows | Where-Object {$_.product.Trim() -eq $product} | ForEach-Object {$_.platformId.Trim()} | Select-Object -Unique)
  if($PSCmdlet.ShouldProcess($spec.Group,"Assign $($ids.Count) Windows/RHEL accounts for $product")){
   $groupParams=@{
    SafeName=$spec.Safe
    AccountIds=$ids
    ConfigPath=$ConfigPath
    PVWAURL=$PVWAURL
    AuthType=$AuthType
    Credential=$Credential
    GroupName=$spec.Group
    GroupPlatformId=$spec.GroupPlatform
    AllowedPlatformIds=$allowed
    CreateGroupIfMissing=$true
    Confirm=$false
   }
   & $groupScript @groupParams
  }
 }
 Write-Host 'Group assignments requested. Run audit and target-local password verification.'
}finally{$secretByProduct.Clear()}

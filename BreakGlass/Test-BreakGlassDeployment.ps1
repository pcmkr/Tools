#requires -Version 5.1
<#
.SYNOPSIS
  Read-only validation: one CyberArk Safe + Account Group PER PRODUCT,
  with both Windows and RHEL hosts allowed in the same group.
.DESCRIPTION
  Manifest columns: product,safeName,groupName,groupPlatformId,os,address,platformId.
  Never reads passwords or executes Change/Reconcile.
.EXAMPLE
  .\Test-BreakGlassDeployment.ps1 -ManifestCsv .\manifest.csv -PVWAURL https://pvwa.example.invalid/PasswordVault -ExpectedWindows 2 -ExpectedRHEL 2 -ReportCsv C:\Temp\bg-report.csv
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ManifestCsv,
 [Parameter(Mandatory)][string]$PVWAURL,
 [ValidateSet('CyberArk','LDAP','Radius')][string]$AuthType='Radius',
 [pscredential]$Credential,
 [int]$ExpectedWindows=150,
 [int]$ExpectedRHEL=150,
 [string]$ReportCsv
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PVWAURL=$PVWAURL.TrimEnd('/')
$rows=@(Import-Csv -LiteralPath $ManifestCsv)
$win=@($rows | Where-Object os -eq 'Windows').Count
$rhel=@($rows | Where-Object os -eq 'RHEL').Count
if($win -ne $ExpectedWindows -or $rhel -ne $ExpectedRHEL){throw "Inventory Windows=$win/$ExpectedWindows; RHEL=$rhel/$ExpectedRHEL"}
if(-not $Credential){$Credential=Get-Credential -Message 'CyberArk read-only audit'}
function Api-Get([string]$Path) {
 Invoke-RestMethod -Uri "$PVWAURL$Path" -Method Get -Headers @{Authorization=$script:token} -ErrorAction Stop
}
function Result-Items($Result){
 if($Result -is [array]){return @($Result)}
 foreach($field in @('value','accounts','groups','members')){
  if($Result -and $Result.PSObject.Properties[$field]){return @($Result.PSObject.Properties[$field].Value)}
 }
 throw 'Unexpected API response shape'
}
function Account-Pages([string]$SafeName) {
 $list=[System.Collections.Generic.List[object]]::new();$offset=0;$limit=100
 $filter=[uri]::EscapeDataString("safeName eq $SafeName")
 do{
  $response=Api-Get "/api/Accounts?filter=$filter&limit=$limit&offset=$offset"
  $page=@(Result-Items $response | Where-Object {$null -ne $_})
  foreach($a in $page){$list.Add($a)}
  $offset+=$page.Count
  if($offset -gt 10000){throw "Pagination exceeds safety limit: $SafeName"}
 }while($page.Count -eq $limit)
 return @($list.ToArray())
}
function Member-Pages([string]$GroupId){
 $list=[System.Collections.Generic.List[object]]::new()
 $id=[uri]::EscapeDataString($GroupId)
 $path="/api/AccountGroups/$id/Members"
 $steps=0
 while($true){
  $steps++
  if($steps -gt 100){throw 'Group membership nextLink loop'}
  $result=Api-Get $path
  foreach($member in @(Result-Items $result)){if($null -ne $member){$list.Add($member)}}
  $next=[string]$result.nextLink
  if(-not $next){break}
  if([uri]::IsWellFormedUriString($next,[UriKind]::Absolute)){
   if(-not $next.StartsWith($PVWAURL,[StringComparison]::OrdinalIgnoreCase)){throw 'Group nextLink points outside PVWA'}
   $path=$next.Substring($PVWAURL.Length)
  }else{$path=$next}
 }
 return @($list.ToArray())
}
$script:token=$null
try{
 $logon=@{username=$Credential.UserName;password=$Credential.GetNetworkCredential().Password;concurrentSession=$true} | ConvertTo-Json
 $response=Invoke-RestMethod -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -Method Post -ContentType 'application/json' -Body $logon -ErrorAction Stop
 $script:token=if($response -is [string]){$response.Trim()}else{[string]$response.CyberArkLogonResult}
 if(-not $script:token){throw 'Missing CyberArk session token'}
 $report=[System.Collections.Generic.List[object]]::new()
 $products=@($rows | Select-Object -ExpandProperty product -Unique)
 $seen=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($product in $products){
  $subset=@($rows | Where-Object product -eq $product)
  $safes=@($subset | Select-Object -ExpandProperty safeName -Unique)
  $names=@($subset | Select-Object -ExpandProperty groupName -Unique)
  $platforms=@($subset | Select-Object -ExpandProperty groupPlatformId -Unique)
  if($safes.Count -ne 1 -or $names.Count -ne 1 -or $platforms.Count -ne 1){throw "Inconsistent product mapping $product"}
  $safe=$safes[0];$groupName=$names[0];$groupPlatform=$platforms[0]
  $all=@(Account-Pages $safe)
  $groups=@(Result-Items (Api-Get "/api/AccountGroups?Safe=$([uri]::EscapeDataString($safe))"))
  $matchedGroups=@($groups | Where-Object groupName -eq $groupName)
  if($matchedGroups.Count -ne 1){throw "Product $product: group $groupName not unique"}
  $g=$matchedGroups[0]
  $id=if($g.groupID){[string]$g.groupID}else{[string]$g.id}
  if(-not $id){throw "Missing group ID: $groupName"}
  $foundPlatform=[string]$g.groupPlatformId
  if(-not $foundPlatform){$foundPlatform=[string]$g.GroupPlatform}
  if($foundPlatform -and $foundPlatform -ne $groupPlatform){throw "Group $groupName has wrong group platform: $foundPlatform"}
  $members=@(Member-Pages $id)
  if($members.Count -ne $subset.Count){throw "$product group count $($members.Count) != manifest $($subset.Count)"}
  $memberIds=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($m in $members){
   $mid=if($m.accountID){[string]$m.accountID}else{[string]$m.id}
   if(-not $mid -or -not $memberIds.Add($mid)){throw "Malformed or duplicate group membership: $product"}
  }
  foreach($row in $subset){
   if($row.os -notin @('Windows','RHEL')){throw "Unexpected OS $($row.os)"}
   if(-not $seen.Add($row.address.Trim())){throw "Server $($row.address) belongs to multiple products"}
   $accounts=@($all | Where-Object{
    $_.safeName -eq $safe -and $_.address -eq $row.address.Trim() -and
    $_.userName -eq 'bguser' -and $_.platformId -eq $row.platformId.Trim()
   })
   if($accounts.Count -ne 1){throw "$product / $($row.address): missing or duplicate CyberArk account"}
   $a=$accounts[0]
   if(-not $memberIds.Contains([string]$a.id)){throw "Missing Account Group membership for $product / $($row.address)"}
   if($a.secretManagement -and $a.secretManagement.automaticManagementEnabled -eq $false){
    throw "$product / $($row.address): CPM management disabled"
   }
   $report.Add([pscustomobject]@{
    Product=$product;OS=$row.os;Address=$row.address;Safe=$safe;AccountGroup=$groupName;
    AccountId=$a.id;TargetPlatform=$a.platformId
   })
  }
  Write-Host "PASS product=$product safe=$safe group=$groupName members=$($members.Count)"
 }
 if($ReportCsv){$report | Export-Csv -LiteralPath $ReportCsv -NoTypeInformation -Encoding UTF8}
 Write-Host "PASS $($report.Count) accounts across $($products.Count) products: $win Windows + $rhel RHEL."
 Write-Host 'This audit does NOT confirm local login, shared password, or CPM change success.'
}finally{
 if($script:token){
  try{Invoke-RestMethod -Uri "$PVWAURL/api/Auth/Logoff" -Method Post -Headers @{Authorization=$script:token} -ErrorAction Stop | Out-Null}
  catch{Write-Warning 'CyberArk Logoff failed'}
 }
}

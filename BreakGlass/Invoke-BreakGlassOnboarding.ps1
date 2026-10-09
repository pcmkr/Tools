#requires -Version 5.1
<#
.SYNOPSIS
  Onboard Windows/RHEL bguser accounts via existing Tools scripts, optionally adding groups.
.NOTES
  Repeatable; does not run Reconcile, rotate, or alter passwords of existing accounts.
  WARNING: Each existing wrapper invocation uses a separate PVWA session.
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
  [Parameter(Mandatory)][string]$ManifestCsv,
  [Parameter(Mandatory)][string]$SafeName,
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$PVWAURL,
  [ValidateSet('CyberArk','LDAP','Radius')][string]$AuthType,
  [pscredential]$Credential,
  [SecureString]$WindowsSecret,
  [SecureString]$RhelSecret,
  [int]$ExpectedWindows=150,
  [int]$ExpectedRHEL=150,
  [switch]$AssignGroups,
  [string]$WindowsGroupName,
  [string]$RhelGroupName,
  [string]$WindowsGroupPlatformId,
  [string]$RhelGroupPlatformId,
  [string]$ADServer
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$localScript=Join-Path $root 'New-CyberArkLocalAccount.ps1'
$groupScript=Join-Path $root 'Add-CyberArkAccountsToGroup.ps1'
foreach($file in @($ManifestCsv,$ConfigPath,$localScript,$groupScript)){
  if(-not (Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing file: $file"}
}
$rows=@(Import-Csv -LiteralPath $ManifestCsv)
if($rows.Count -eq 0){throw 'Empty manifest.'}
$seen=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($row in $rows){
  if($row.os -notin @('Windows','RHEL')){throw "Unsupported OS: $($row.os)"}
  foreach($field in @('address','platformId')){
    if([string]::IsNullOrWhiteSpace([string]$row.$field)){throw "Missing $field"}
  }
  if(-not $seen.Add($row.address.Trim())){throw "Duplicate address: $($row.address)"}
}
$win=@($rows | Where-Object os -eq Windows)
$rhel=@($rows | Where-Object os -eq RHEL)
if($win.Count -ne $ExpectedWindows -or $rhel.Count -ne $ExpectedRHEL){
  throw "Count mismatch Windows=$($win.Count)/$ExpectedWindows RHEL=$($rhel.Count)/$ExpectedRHEL"
}
if($AssignGroups){
  foreach($v in @($WindowsGroupName,$RhelGroupName,$WindowsGroupPlatformId,$RhelGroupPlatformId)){
    if(-not $v){throw 'Group name and group platform ID for each OS required.'}
  }
  if($WindowsGroupName -eq $RhelGroupName){throw 'Different OS secrets require separate Account Groups.'}
}
$config=Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
if(-not $PVWAURL){$PVWAURL=[string]$config.defaults.pvwaUrl}
if(-not $AuthType){$AuthType=[string]$config.defaults.authType}
if(-not $PVWAURL -or $AuthType -notin @('CyberArk','LDAP','Radius')){throw 'PVWAURL / AuthType invalid.'}
$PVWAURL=$PVWAURL.TrimEnd('/')
if(-not $Credential){$Credential=Get-Credential -Message 'CyberArk onboarding'}
if(-not $WhatIfPreference){
  if($win.Count -gt 0 -and -not $WindowsSecret){$WindowsSecret=Read-Host 'Initial Windows shared password' -AsSecureString}
  if($rhel.Count -gt 0 -and -not $RhelSecret){$RhelSecret=Read-Host 'Initial RHEL shared password' -AsSecureString}
}
$failed=[System.Collections.Generic.List[string]]::new()
$done=0
foreach($row in $rows){
  $args=@{
    SafeName=$SafeName
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
  if($ADServer){$args.ADServer=$ADServer}
  if($row.os -eq 'Windows' -and $WindowsSecret){$args.AccountSecret=$WindowsSecret}
  if($row.os -eq 'RHEL' -and $RhelSecret){$args.AccountSecret=$RhelSecret}
  if($WhatIfPreference){$args.WhatIf=$true}
  try{& $localScript @args; $done++}
  catch{$failed.Add("$($row.os) $($row.address): $($_.Exception.Message)")}
}
Write-Host "Accounts processed: $done/$($rows.Count). Failures: $($failed.Count)."
if($failed.Count -gt 0){
  foreach($item in $failed){Write-Warning $item}
  throw 'Incomplete onboarding. Group assignment blocked.'
}
if($WhatIfPreference -or -not $AssignGroups){
  Write-Host 'Group assignment omitted (use -AssignGroups after validating all accounts).'
  return
}
$token=$null
try{
  $logon=@{
    username=$Credential.UserName
    password=$Credential.GetNetworkCredential().Password
    concurrentSession=$true
  } | ConvertTo-Json
  $r=Invoke-RestMethod -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -Method Post -Body $logon -ContentType 'application/json' -ErrorAction Stop
  $token=if($r -is [string]){$r.Trim()}else{[string]$r.CyberArkLogonResult}
  if(-not $token){throw 'Missing CyberArk session token.'}
  $headers=@{Authorization=$token}
  $all=[System.Collections.Generic.List[object]]::new()
  $offset=0
  $limit=100
  do{
    $filter=[uri]::EscapeDataString("safeName eq $SafeName")
    $pageResult=Invoke-RestMethod -Uri "$PVWAURL/api/Accounts?filter=$filter&limit=$limit&offset=$offset" -Headers $headers -ErrorAction Stop
    $page=@($pageResult.value | Where-Object {$null -ne $_})
    foreach($a in $page){$all.Add($a)}
    $offset+=$page.Count
    if($offset -gt 10000){throw 'Account listing exceeded safety limit.'}
  }while($page.Count -eq $limit)
  $ids=@{Windows=@();RHEL=@()}
  foreach($row in $rows){
    $found=@($all | Where-Object {
      $_.safeName -eq $SafeName -and $_.address -eq $row.address.Trim() -and
      $_.userName -eq 'bguser' -and $_.platformId -eq $row.platformId.Trim()
    })
    if($found.Count -ne 1 -or -not $found[0].id){throw "Account not uniquely found: $($row.address)"}
    $ids[$row.os]+=[string]$found[0].id
  }
}finally{
  if($token){
    try{Invoke-RestMethod -Uri "$PVWAURL/api/Auth/Logoff" -Method Post -Headers @{Authorization=$token} -ErrorAction Stop | Out-Null}
    catch{Write-Warning 'PVWA logoff failed.'}
  }
}
foreach($spec in @(
  @{os='Windows';name=$WindowsGroupName;platform=$WindowsGroupPlatformId},
  @{os='RHEL';name=$RhelGroupName;platform=$RhelGroupPlatformId}
)){
  $accountIDs=@($ids[$spec.os])
  if($accountIDs.Count -eq 0){continue}
  $allowed=@($rows | Where-Object os -eq $spec.os | ForEach-Object {$_.platformId} | Select-Object -Unique)
  if($PSCmdlet.ShouldProcess($spec.name,"Assign $($accountIDs.Count) member accounts")){
    & $groupScript -SafeName $SafeName -AccountIds $accountIDs -ConfigPath $ConfigPath -PVWAURL $PVWAURL -AuthType $AuthType -Credential $Credential -GroupName $spec.name -GroupPlatformId $spec.platform -AllowedPlatformIds $allowed -CreateGroupIfMissing -Confirm:$false
  }
}
Write-Host 'Finished. Verify all group members, platform and CPM status in PVWA.'

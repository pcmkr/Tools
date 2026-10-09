#requires -Version 5.1
<#
.SYNOPSIS
  Read-only audit of Break-Glass account group membership. Does not read secrets.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SafeName,
  [Parameter(Mandatory)][string]$ManifestCsv,
  [Parameter(Mandatory)][string]$PVWAURL,
  [ValidateSet('CyberArk','LDAP','Radius')][string]$AuthType='Radius',
  [pscredential]$Credential,
  [Parameter(Mandatory)][string]$WindowsGroupName,
  [Parameter(Mandatory)][string]$RhelGroupName,
  [int]$ExpectedWindows=150,
  [int]$ExpectedRHEL=150,
  [string]$ReportCsv
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PVWAURL=$PVWAURL.TrimEnd('/')
$rows=@(Import-Csv -LiteralPath $ManifestCsv)
if(-not $Credential){$Credential=Get-Credential -Message 'Read-only CyberArk audit'}
function Invoke-Get([string]$Path) {
  Invoke-RestMethod -Uri "$PVWAURL$Path" -Method Get -Headers @{Authorization=$script:token} -ErrorAction Stop
}
function Get-Items($Response){
  if($Response -is [array]){return @($Response)}
  foreach($key in @('value','members','accounts','groups')){
    if($Response -and $Response.PSObject.Properties[$key]){
      return @($Response.PSObject.Properties[$key].Value)
    }
  }
  throw 'Unexpected API collection shape. Audit fails closed.'
}
function Get-Paged([string]$Path){
  $items=[System.Collections.Generic.List[object]]::new()
  $offset=0; $limit=100
  do{
    $separator=if($Path.Contains('?')){'&'}else{'?'}
    $url=$Path + $separator + "limit=$limit&offset=$offset"
    $response=Invoke-Get $url
    $page=@(Get-Items $response | Where-Object {$null -ne $_})
    foreach($item in $page){$items.Add($item)}
    $offset+=$page.Count
    if($offset -gt 10000){throw 'Exceeded pagination safety limit'}
  }while($page.Count -eq $limit)
  return @($items.ToArray())
}
$script:token=$null
try{
  $body=@{username=$Credential.UserName;password=$Credential.GetNetworkCredential().Password;concurrentSession=$true} | ConvertTo-Json
  $r=Invoke-RestMethod -Uri "$PVWAURL/api/Auth/$AuthType/Logon" -Method Post -ContentType 'application/json' -Body $body -ErrorAction Stop
  $script:token=if($r -is [string]){$r.Trim()}else{[string]$r.CyberArkLogonResult}
  if(-not $script:token){throw 'Missing CyberArk token'}
  $safeEncoded=[uri]::EscapeDataString($SafeName)
  $groups=@(Get-Items (Invoke-Get "/api/AccountGroups?Safe=$safeEncoded"))
  $filter=[uri]::EscapeDataString("safeName eq $SafeName")
  $accounts=@(Get-Paged "/api/Accounts?filter=$filter")
  $assignments=@{}
  $specs=@(
    @{os='Windows';name=$WindowsGroupName;expected=$ExpectedWindows},
    @{os='RHEL';name=$RhelGroupName;expected=$ExpectedRHEL}
  )
  foreach($spec in $specs){
    $found=@($groups | Where-Object {$_.groupName -eq $spec.name})
    if($found.Count -ne 1){throw "Expected one group $($spec.name), found $($found.Count)"}
    $id=if($found[0].groupID){[string]$found[0].groupID}else{[string]$found[0].id}
    if(-not $id){throw "Missing groupID for $($spec.name)"}
    $escapedId=[uri]::EscapeDataString($id)
    $members=@(Get-Paged "/api/AccountGroups/$escapedId/Members")
    if($members.Count -ne $spec.expected){throw "$($spec.name): $($members.Count) members, expected $($spec.expected)"}
    foreach($member in $members){
      $memberID=if($member.accountID){[string]$member.accountID}else{[string]$member.id}
      if(-not $memberID){throw 'Missing member accountID'}
      if($assignments.ContainsKey($memberID)){throw "Duplicate group assignment for account $memberID"}
      $assignments[$memberID]=$spec.os
    }
  }
  if($rows.Count -ne ($ExpectedWindows+$ExpectedRHEL)){throw 'Manifest count mismatch'}
  $report=[System.Collections.Generic.List[object]]::new()
  foreach($row in $rows){
    if($row.os -notin @('Windows','RHEL')){throw "Unsupported OS $($row.os)"}
    $found=@($accounts | Where-Object {
      $_.safeName -eq $SafeName -and $_.address -eq $row.address -and
      $_.userName -eq 'bguser' -and $_.platformId -eq $row.platformId
    })
    if($found.Count -ne 1){throw "Account missing/duplicate: $($row.address)"}
    $a=$found[0]
    if(-not $assignments.ContainsKey([string]$a.id) -or $assignments[[string]$a.id] -ne $row.os){
      throw "Wrong membership: $($row.address)"
    }
    if($a.secretManagement -and $a.secretManagement.automaticManagementEnabled -eq $false){
      throw "CPM account disabled: $($row.address)"
    }
    $report.Add([pscustomobject]@{
      OS=$row.os; Address=$row.address; AccountId=$a.id
      TargetPlatformId=$a.platformId; Group=if($row.os -eq 'Windows'){$WindowsGroupName}else{$RhelGroupName}
    })
  }
  if($assignments.Count -ne $rows.Count){throw 'Extra account group members outside manifest'}
  if($ReportCsv){$report | Export-Csv -LiteralPath $ReportCsv -NoTypeInformation -Encoding UTF8}
  Write-Host "PASS: $($rows.Count) accounts, $ExpectedWindows Windows, $ExpectedRHEL RHEL."
  Write-Host 'NOTE: This checks membership and metadata only; not actual passwords or server login.'
}finally{
  if($script:token){
    try{Invoke-RestMethod -Uri "$PVWAURL/api/Auth/Logoff" -Method Post -Headers @{Authorization=$script:token} -ErrorAction Stop | Out-Null}
    catch{Write-Warning 'Failed to log off CyberArk session'}
  }
}

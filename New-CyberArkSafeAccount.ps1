#requires -Version 5.1
<#
.SYNOPSIS
    Tworzy Safe w CyberArk PAM, przypisuje członków z rolami, dodaje konto
    i uruchamia Reconcile.

.DESCRIPTION
    Skrypt jest przeznaczony dla jednego, stałego typu konta opisanego w JSON.
    Nazwa Safe oraz login konta są przekazywane jako parametry.

    Dla każdego Safe automatycznie wyliczana jest grupa właścicieli:
        <SafeName><ownerGroupSuffix>

    Domyślnie daje to np.:
        APP-PRD-SQL01_owner

    Grupa jest dodawana do Safe z uprawnieniami roli Owner z pliku JSON.

    Pole CyberArk Account "name" (Object Name) nie jest wysyłane do API.
    CyberArk generuje nazwę obiektu konta zgodnie z własnym mechanizmem.

.PARAMETER PVWAURL
    Bazowy URL PVWA, np. https://pvwa.example.com/PasswordVault.

.PARAMETER SafeName
    Nazwa tworzonego Safe, np. APP-PRD-SQL01.

.PARAMETER AccountUserName
    Login konta dodawanego do Safe, np. svc_sql.

.PARAMETER ConfigPath
    Ścieżka do pliku JSON. Plik definiuje stałe właściwości Safe, typ konta,
    role, stałych członków oraz sposób tworzenia grupy Owner.

.PARAMETER AuthType
    Metoda logowania: CyberArk, LDAP albo Radius.

.PARAMETER Credential
    Opcjonalny PSCredential do logowania do PVWA.

.PARAMETER AccountSecret
    Początkowy sekret konta. Jeśli nie zostanie przekazany, skrypt poprosi
    o niego jako SecureString.

.PARAMETER AllowExistingSafe
    Pozwala użyć istniejącego Safe.

.PARAMETER UpdateExistingMembers
    Aktualizuje uprawnienia członków, którzy już istnieją w Safe.

.PARAMETER SkipReconcile
    Pomija operację Reconcile.

.EXAMPLE
    .\New-CyberArkSafeAccount.ps1 `
        -PVWAURL "https://pvwa.example.com/PasswordVault" `
        -AuthType LDAP `
        -SafeName "APP-PRD-SQL01" `
        -AccountUserName "svc_sql" `
        -ConfigPath .\CyberArk-SafeConfig.example.json

.EXAMPLE
    $secret = Read-Host "Początkowe hasło konta" -AsSecureString

    .\New-CyberArkSafeAccount.ps1 `
        -PVWAURL "https://pvwa.example.com/PasswordVault" `
        -AuthType CyberArk `
        -SafeName "APP-PRD-SQL01" `
        -AccountUserName "svc_sql" `
        -ConfigPath .\CyberArk-SafeConfig.example.json `
        -AccountSecret $secret

.EXAMPLE
    .\New-CyberArkSafeAccount.ps1 `
        -PVWAURL "https://pvwa.example.com/PasswordVault" `
        -SafeName "APP-PRD-SQL01" `
        -AccountUserName "svc_sql" `
        -ConfigPath .\CyberArk-SafeConfig.example.json `
        -WhatIf

.NOTES
    Konto wykonujące skrypt musi mieć uprawnienia potrzebne do:
      - tworzenia Safe,
      - zarządzania członkami Safe,
      - dodawania kont,
      - inicjowania operacji CPM (Reconcile).

    Hasło konta nie jest przechowywane w pliku konfiguracyjnym.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PVWAURL,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SafeName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$AccountUserName,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ConfigPath,

    [ValidateSet("CyberArk", "LDAP", "Radius")]
    [string]$AuthType = "CyberArk",

    [System.Management.Automation.PSCredential]$Credential,

    [System.Security.SecureString]$AccountSecret,

    [switch]$AllowExistingSafe,

    [switch]$UpdateExistingMembers,

    [switch]$SkipReconcile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PVWAURL = $PVWAURL.TrimEnd("/")

$permissionNames = @(
    "useAccounts",
    "retrieveAccounts",
    "listAccounts",
    "addAccounts",
    "updateAccountContent",
    "updateAccountProperties",
    "initiateCPMAccountManagementOperations",
    "specifyNextAccountContent",
    "renameAccounts",
    "deleteAccounts",
    "unlockAccounts",
    "manageSafe",
    "manageSafeMembers",
    "backupSafe",
    "viewAuditLog",
    "viewSafeMembers",
    "accessWithoutConfirmation",
    "createFolders",
    "deleteFolders",
    "moveAccountsAndFolders",
    "requestsAuthorizationLevel1",
    "requestsAuthorizationLevel2"
)

function Get-ObjectProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }

    return $property.Value
}

function Test-ObjectProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    return ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name])
}

function Expand-TemplateValue {
    param($Value)

    if ($Value -is [string]) {
        return $Value.Replace("{SafeName}", $SafeName).Replace("{AccountUserName}", $AccountUserName)
    }

    return $Value
}

function ConvertFrom-SecureStringPlainText {
    param(
        [Parameter(Mandatory)]
        [System.Security.SecureString]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-HttpStatusCode {
    param($Exception)

    if ($null -eq $Exception) { return $null }

    try {
        if ($null -ne $Exception.Response.StatusCode) {
            return [int]$Exception.Response.StatusCode
        }
    }
    catch {
    }

    try {
        if ($null -ne $Exception.Response.StatusCode.value__) {
            return [int]$Exception.Response.StatusCode.value__
        }
    }
    catch {
        return $null
    }

    return $null
}

function Invoke-CyberArkApi {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Get", "Post", "Put", "Patch", "Delete")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [hashtable]$Headers,

        $Body,

        [int]$TimeoutSec = 180
    )

    $parameters = @{
        Method      = $Method
        Uri         = $Uri
        ContentType = "application/json"
        TimeoutSec  = $TimeoutSec
    }

    if ($null -ne $Headers) {
        $parameters.Headers = $Headers
    }

    if ($null -ne $Body) {
        if ($Body -is [string]) {
            $parameters.Body = $Body
        }
        else {
            $parameters.Body = ($Body | ConvertTo-Json -Depth 20)
        }
    }

    return Invoke-RestMethod @parameters
}

function Get-SafeByName {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $safeId = [uri]::EscapeDataString($Name)

    try {
        return Invoke-CyberArkApi -Method Get -Uri "$PVWAURL/api/Safes/$safeId" -Headers $Headers
    }
    catch {
        if ((Get-HttpStatusCode $_.Exception) -eq 404) {
            return $null
        }
        throw
    }
}

function Get-SafeMember {
    param(
        [Parameter(Mandatory)][string]$SafeIdentifier,
        [Parameter(Mandatory)][string]$MemberName,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $safeId = [uri]::EscapeDataString($SafeIdentifier)
    $memberId = [uri]::EscapeDataString($MemberName)

    try {
        return Invoke-CyberArkApi -Method Get -Uri "$PVWAURL/api/Safes/$safeId/Members/$memberId" -Headers $Headers
    }
    catch {
        if ((Get-HttpStatusCode $_.Exception) -eq 404) {
            return $null
        }
        throw
    }
}

function ConvertTo-PermissionObject {
    param(
        [Parameter(Mandatory)]
        $RoleDefinition
    )

    $permissions = [ordered]@{}

    foreach ($permissionName in $permissionNames) {
        $permissions[$permissionName] = $false
    }

    foreach ($property in $RoleDefinition.PSObject.Properties) {
        if ($property.Name -notin $permissionNames) {
            throw "Nieznane uprawnienie '$($property.Name)' w definicji roli."
        }

        if ($property.Value -isnot [bool]) {
            throw "Uprawnienie '$($property.Name)' musi mieć wartość true albo false."
        }

        $permissions[$property.Name] = [bool]$property.Value
    }

    return $permissions
}

$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($requiredSection in @("safe", "owner", "roles", "account")) {
    if (-not (Test-ObjectProperty $config $requiredSection)) {
        throw "W pliku konfiguracyjnym brakuje sekcji '$requiredSection'."
    }
}

if ((Test-ObjectProperty $config.safe "numberOfDaysRetention") -and
    (Test-ObjectProperty $config.safe "numberOfVersionsRetention")) {
    throw "Ustaw tylko jedno: safe.numberOfDaysRetention albo safe.numberOfVersionsRetention."
}

foreach ($requiredAccountProperty in @("address", "platformId")) {
    $value = [string](Get-ObjectProperty $config.account $requiredAccountProperty)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "account.$requiredAccountProperty jest wymagane."
    }
}

$ownerRoleName = [string](Get-ObjectProperty $config.owner "role")
if ([string]::IsNullOrWhiteSpace($ownerRoleName)) {
    $ownerRoleName = "Owner"
}

if ($null -eq $config.roles.PSObject.Properties[$ownerRoleName]) {
    throw "Brak definicji roli Owner '$ownerRoleName' w sekcji roles."
}

$ownerGroupSuffix = [string](Get-ObjectProperty $config.owner "groupSuffix")
if ([string]::IsNullOrWhiteSpace($ownerGroupSuffix)) {
    $ownerGroupSuffix = "_owner"
}

$ownerSearchIn = [string](Get-ObjectProperty $config.owner "searchIn")
if ([string]::IsNullOrWhiteSpace($ownerSearchIn)) {
    throw "owner.searchIn jest wymagane, np. CORP."
}

$ownerGroupName = $SafeName + $ownerGroupSuffix

$members = [System.Collections.Generic.List[object]]::new()
$members.Add([PSCustomObject]@{
    name     = $ownerGroupName
    searchIn = $ownerSearchIn
    role     = $ownerRoleName
})

if (Test-ObjectProperty $config "members") {
    foreach ($member in @($config.members)) {
        $members.Add($member)
    }
}

foreach ($member in $members) {
    $memberName = [string](Get-ObjectProperty $member "name")
    $roleName = [string](Get-ObjectProperty $member "role")

    if ([string]::IsNullOrWhiteSpace($memberName)) {
        throw "Każdy członek Safe musi mieć pole 'name'."
    }

    if ([string]::IsNullOrWhiteSpace($roleName)) {
        throw "Członek '$memberName' nie ma przypisanej roli."
    }

    if ($null -eq $config.roles.PSObject.Properties[$roleName]) {
        throw "Członek '$memberName' odwołuje się do niezdefiniowanej roli '$roleName'."
    }

    [void](ConvertTo-PermissionObject -RoleDefinition $config.roles.PSObject.Properties[$roleName].Value)
}

if ($null -eq $Credential) {
    $Credential = Get-Credential -Message "Dane logowania do CyberArk PAM"
}

$token = $null
$headers = $null

try {
    Write-Host "Logowanie do CyberArk PAM..." -ForegroundColor Cyan

    $logonBody = @{
        username          = $Credential.UserName
        password          = $Credential.GetNetworkCredential().Password
        concurrentSession = $true
    }

    $token = Invoke-CyberArkApi `
        -Method Post `
        -Uri "$PVWAURL/api/Auth/$AuthType/Logon" `
        -Body $logonBody `
        -TimeoutSec 120

    if ($token -isnot [string]) {
        foreach ($propertyName in @("CyberArkLogonResult", "token", "Token")) {
            $value = Get-ObjectProperty $token $propertyName
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $token = [string]$value
                break
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$token)) {
        throw "CyberArk zwrócił pusty token logowania."
    }

    $headers = @{ Authorization = [string]$token }

    Write-Host "Sprawdzanie Safe '$SafeName'..." -ForegroundColor Cyan
    $safe = Get-SafeByName -Name $SafeName -Headers $headers

    if ($null -ne $safe -and -not $AllowExistingSafe) {
        throw "Safe '$SafeName' już istnieje. Użyj -AllowExistingSafe, jeśli chcesz go wykorzystać."
    }

    if ($null -eq $safe) {
        $safeBody = [ordered]@{
            safeName = $SafeName
        }

        foreach ($propertyName in @(
            "description",
            "location",
            "managingCPM",
            "olacEnabled",
            "numberOfDaysRetention",
            "numberOfVersionsRetention"
        )) {
            if (Test-ObjectProperty $config.safe $propertyName) {
                $safeBody[$propertyName] = Expand-TemplateValue (Get-ObjectProperty $config.safe $propertyName)
            }
        }

        if ($PSCmdlet.ShouldProcess("Safe '$SafeName'", "Utworzenie Safe")) {
            Write-Host "Tworzenie Safe '$SafeName'..." -ForegroundColor Cyan
            $safe = Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Safes" -Headers $headers -Body $safeBody -TimeoutSec 300
            Write-Host "Safe utworzony." -ForegroundColor Green
        }
    }
    else {
        Write-Host "Safe już istnieje — kontynuuję zgodnie z -AllowExistingSafe." -ForegroundColor Yellow
    }

    $safeIdentifier = $SafeName
    if ($null -ne $safe) {
        $safeUrlId = [string](Get-ObjectProperty $safe "safeUrlId")
        if (-not [string]::IsNullOrWhiteSpace($safeUrlId)) {
            $safeIdentifier = $safeUrlId
        }
    }

    foreach ($member in $members) {
        $memberName = Expand-TemplateValue ([string](Get-ObjectProperty $member "name"))
        $roleName = [string](Get-ObjectProperty $member "role")
        $searchIn = [string](Get-ObjectProperty $member "searchIn")

        if ([string]::IsNullOrWhiteSpace($searchIn)) {
            $searchIn = "Vault"
        }

        $roleDefinition = $config.roles.PSObject.Properties[$roleName].Value
        $permissions = ConvertTo-PermissionObject -RoleDefinition $roleDefinition

        $memberBody = [ordered]@{
            memberName  = $memberName
            searchIn    = $searchIn
            permissions = $permissions
        }

        if (Test-ObjectProperty $member "membershipExpirationDate") {
            $memberBody.membershipExpirationDate = Get-ObjectProperty $member "membershipExpirationDate"
        }

        $existingMember = $null
        if ($null -ne $safe -or $AllowExistingSafe) {
            $existingMember = Get-SafeMember -SafeIdentifier $safeIdentifier -MemberName $memberName -Headers $headers
        }

        if ($null -eq $existingMember) {
            if ($PSCmdlet.ShouldProcess("Safe '$SafeName' / '$memberName'", "Dodanie członka z rolą '$roleName'")) {
                Write-Host "Dodawanie członka '$memberName' jako '$roleName'..." -ForegroundColor Cyan
                $escapedSafe = [uri]::EscapeDataString($safeIdentifier)
                Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Safes/$escapedSafe/Members" -Headers $headers -Body $memberBody | Out-Null
            }
        }
        elseif ($UpdateExistingMembers) {
            $updateBody = [ordered]@{
                permissions = $permissions
            }

            if (Test-ObjectProperty $member "membershipExpirationDate") {
                $updateBody.membershipExpirationDate = Get-ObjectProperty $member "membershipExpirationDate"
            }

            if ($PSCmdlet.ShouldProcess("Safe '$SafeName' / '$memberName'", "Aktualizacja uprawnień do roli '$roleName'")) {
                Write-Host "Aktualizacja członka '$memberName' do roli '$roleName'..." -ForegroundColor Cyan
                $escapedSafe = [uri]::EscapeDataString($safeIdentifier)
                $escapedMember = [uri]::EscapeDataString($memberName)
                Invoke-CyberArkApi -Method Put -Uri "$PVWAURL/api/Safes/$escapedSafe/Members/$escapedMember" -Headers $headers -Body $updateBody | Out-Null
            }
        }
        else {
            throw "Członek '$memberName' już istnieje w Safe '$SafeName'. Użyj -UpdateExistingMembers, aby zaktualizować jego uprawnienia."
        }
    }

    $accountAddress = Expand-TemplateValue ([string](Get-ObjectProperty $config.account "address"))
    $accountTarget = "$AccountUserName@$accountAddress"
    $createdAccount = $null

    if ($PSCmdlet.ShouldProcess("Konto '$accountTarget' w Safe '$SafeName'", "Dodanie konta do CyberArk")) {
        if ($null -eq $AccountSecret) {
            $AccountSecret = Read-Host "Podaj początkowy sekret konta '$accountTarget'" -AsSecureString
        }

        $plainSecret = ConvertFrom-SecureStringPlainText -SecureString $AccountSecret

        try {
            $secretType = [string](Get-ObjectProperty $config.account "secretType")
            if ([string]::IsNullOrWhiteSpace($secretType)) {
                $secretType = "password"
            }

            # Celowo bez pola "name". CyberArk generuje Object Name.
            $accountBody = [ordered]@{
                address    = $accountAddress
                userName   = $AccountUserName
                platformId = [string](Get-ObjectProperty $config.account "platformId")
                safeName   = $SafeName
                secretType = $secretType
                secret     = $plainSecret
            }

            foreach ($propertyName in @(
                "platformAccountProperties",
                "secretManagement",
                "remoteMachinesAccess"
            )) {
                if (Test-ObjectProperty $config.account $propertyName) {
                    $accountBody[$propertyName] = Get-ObjectProperty $config.account $propertyName
                }
            }

            Write-Host "Dodawanie konta '$accountTarget'..." -ForegroundColor Cyan
            $createdAccount = Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Accounts" -Headers $headers -Body $accountBody -TimeoutSec 300
            Write-Host "Konto dodane." -ForegroundColor Green
        }
        finally {
            $plainSecret = $null
        }
    }

    if (-not $SkipReconcile -and $null -ne $createdAccount) {
        $accountId = [string](Get-ObjectProperty $createdAccount "id")
        if ([string]::IsNullOrWhiteSpace($accountId)) {
            $accountId = [string](Get-ObjectProperty $createdAccount "Id")
        }

        if ([string]::IsNullOrWhiteSpace($accountId)) {
            throw "Konto zostało utworzone, ale API nie zwróciło jego ID. Reconcile nie może zostać uruchomiony automatycznie."
        }

        if ($PSCmdlet.ShouldProcess("Konto '$accountTarget' (ID: $accountId)", "Uruchomienie Reconcile")) {
            $escapedAccountId = [uri]::EscapeDataString($accountId)

            Write-Host "Uruchamianie Reconcile..." -ForegroundColor Cyan
            Invoke-CyberArkApi `
                -Method Post `
                -Uri "$PVWAURL/api/Accounts/$escapedAccountId/Reconcile" `
                -Headers $headers `
                -Body "{}" `
                -TimeoutSec 300 | Out-Null

            Write-Host "Reconcile został zlecony do CPM." -ForegroundColor Green
        }
    }
    elseif ($SkipReconcile) {
        Write-Host "Reconcile pominięty zgodnie z -SkipReconcile." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Operacja zakończona." -ForegroundColor Green
    Write-Host ("Safe:        {0}" -f $SafeName)
    Write-Host ("Owner group: {0}" -f $ownerGroupName)
    Write-Host ("Konto:       {0}" -f $accountTarget)
}
finally {
    if ($headers -and $token) {
        try {
            Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Auth/Logoff" -Headers $headers -TimeoutSec 60 | Out-Null
        }
        catch {
            Write-Warning ("Nie udało się wylogować sesji CyberArk: " + $_.Exception.Message)
        }
    }
}

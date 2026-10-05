#requires -Version 5.1
<#
.SYNOPSIS
    Tworzy Safe w CyberArk PAM, nadaje członkom uprawnienia z pliku JSON,
    dodaje konto do Safe i uruchamia reconcile.

.DESCRIPTION
    Skrypt korzysta z CyberArk PVWA REST API i wykonuje kolejno:
      1. logowanie do PVWA,
      2. utworzenie Safe,
      3. dodanie członków Safe z uprawnieniami wynikającymi z definicji ról,
      4. onboarding wskazanego konta do Safe,
      5. uruchomienie reconcile dla nowo utworzonego konta,
      6. wylogowanie z PVWA.

    Definicje ról i członków znajdują się w pliku JSON. Hasło konta nie powinno
    być przechowywane w pliku konfiguracyjnym. Jeśli -AccountSecret nie zostanie
    podany, skrypt poprosi o nie interaktywnie jako SecureString.

.PARAMETER PVWAURL
    Bazowy URL PVWA, np. https://pvwa.example.com/PasswordVault.

.PARAMETER ConfigPath
    Ścieżka do pliku JSON opisującego Safe, role, członków i konto.

.PARAMETER AuthType
    Metoda logowania do PVWA: CyberArk, LDAP albo Radius.

.PARAMETER Credential
    Opcjonalny PSCredential do logowania do PVWA. Jeśli brak, zostanie wywołany
    Get-Credential.

.PARAMETER AccountSecret
    Początkowy sekret konta dodawanego do CyberArk. Jeśli nie zostanie podany,
    skrypt poprosi o niego przez Read-Host -AsSecureString.

.PARAMETER AllowExistingSafe
    Pozwala użyć istniejącego Safe zamiast kończyć działanie błędem.

.PARAMETER UpdateExistingMembers
    Jeśli członek już istnieje w Safe, aktualizuje jego uprawnienia zgodnie
    z plikiem konfiguracyjnym.

.PARAMETER SkipReconcile
    Dodaje konto, ale nie uruchamia reconcile. Przydatne do testów.

.EXAMPLE
    .\New-CyberArkSafeAccount.ps1 `
        -PVWAURL "https://pvwa.example.com/PasswordVault" `
        -AuthType LDAP `
        -ConfigPath .\CyberArk-SafeConfig.example.json

.EXAMPLE
    $secret = Read-Host "Początkowe hasło konta" -AsSecureString

    .\New-CyberArkSafeAccount.ps1 `
        -PVWAURL "https://pvwa.example.com/PasswordVault" `
        -AuthType CyberArk `
        -ConfigPath .\CyberArk-SafeConfig.example.json `
        -AccountSecret $secret

.EXAMPLE
    .\New-CyberArkSafeAccount.ps1 `
        -PVWAURL "https://pvwa.example.com/PasswordVault" `
        -ConfigPath .\CyberArk-SafeConfig.example.json `
        -AllowExistingSafe `
        -UpdateExistingMembers `
        -WhatIf

.NOTES
    Konto wykonujące skrypt musi mieć uprawnienia potrzebne do:
      - tworzenia Safe,
      - zarządzania członkami Safe,
      - dodawania kont,
      - inicjowania operacji CPM (Reconcile).

    Skrypt celowo nie obsługuje hasła konta w JSON, aby nie utrwalać sekretu
    w repozytorium.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PVWAURL,

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

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Test-ObjectProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    return ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name])
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

    if ($null -eq $Exception) {
        return $null
    }

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
        [Parameter(Mandatory)][string]$SafeName,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $safeId = [uri]::EscapeDataString($SafeName)

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
            throw "Nieznane uprawnienie '$($property.Name)' w definicji roli. Popraw plik konfiguracyjny."
        }

        if ($property.Value -isnot [bool]) {
            throw "Uprawnienie '$($property.Name)' musi mieć wartość true albo false."
        }

        $permissions[$property.Name] = [bool]$property.Value
    }

    return $permissions
}

$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

if (-not (Test-ObjectProperty $config "safe")) {
    throw "W pliku konfiguracyjnym brakuje sekcji 'safe'."
}
if (-not (Test-ObjectProperty $config "roles")) {
    throw "W pliku konfiguracyjnym brakuje sekcji 'roles'."
}
if (-not (Test-ObjectProperty $config "members")) {
    throw "W pliku konfiguracyjnym brakuje sekcji 'members'."
}
if (-not (Test-ObjectProperty $config "account")) {
    throw "W pliku konfiguracyjnym brakuje sekcji 'account'."
}

$safeName = [string](Get-ObjectProperty $config.safe "safeName")
if ([string]::IsNullOrWhiteSpace($safeName)) {
    throw "safe.safeName jest wymagane."
}

if ((Test-ObjectProperty $config.safe "numberOfDaysRetention") -and
    (Test-ObjectProperty $config.safe "numberOfVersionsRetention")) {
    throw "Ustaw tylko jedno: safe.numberOfDaysRetention albo safe.numberOfVersionsRetention."
}

foreach ($requiredAccountProperty in @("address", "userName", "platformId")) {
    $value = [string](Get-ObjectProperty $config.account $requiredAccountProperty)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "account.$requiredAccountProperty jest wymagane."
    }
}

foreach ($member in @($config.members)) {
    $memberName = [string](Get-ObjectProperty $member "name")
    $roleName = [string](Get-ObjectProperty $member "role")

    if ([string]::IsNullOrWhiteSpace($memberName)) {
        throw "Każdy element members musi zawierać pole 'name'."
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

    Write-Host "Sprawdzanie Safe '$safeName'..." -ForegroundColor Cyan
    $safe = Get-SafeByName -SafeName $safeName -Headers $headers

    if ($null -ne $safe -and -not $AllowExistingSafe) {
        throw "Safe '$safeName' już istnieje. Użyj -AllowExistingSafe, jeśli chcesz go wykorzystać."
    }

    if ($null -eq $safe) {
        $safeBody = [ordered]@{
            safeName = $safeName
        }

        foreach ($propertyName in @("description", "location", "managingCPM", "olacEnabled", "numberOfDaysRetention", "numberOfVersionsRetention")) {
            if (Test-ObjectProperty $config.safe $propertyName) {
                $safeBody[$propertyName] = Get-ObjectProperty $config.safe $propertyName
            }
        }

        if ($PSCmdlet.ShouldProcess("Safe '$safeName'", "Utworzenie Safe")) {
            Write-Host "Tworzenie Safe '$safeName'..." -ForegroundColor Cyan
            $safe = Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Safes" -Headers $headers -Body $safeBody -TimeoutSec 300
            Write-Host "Safe utworzony." -ForegroundColor Green
        }
    }
    else {
        Write-Host "Safe już istnieje — kontynuuję zgodnie z -AllowExistingSafe." -ForegroundColor Yellow
    }

    $safeIdentifier = $safeName
    if ($null -ne $safe) {
        $safeUrlId = [string](Get-ObjectProperty $safe "safeUrlId")
        if (-not [string]::IsNullOrWhiteSpace($safeUrlId)) {
            $safeIdentifier = $safeUrlId
        }
    }

    foreach ($member in @($config.members)) {
        $memberName = [string](Get-ObjectProperty $member "name")
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
            if ($PSCmdlet.ShouldProcess("Safe '$safeName' / '$memberName'", "Dodanie członka z rolą '$roleName'")) {
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

            if ($PSCmdlet.ShouldProcess("Safe '$safeName' / '$memberName'", "Aktualizacja uprawnień członka do roli '$roleName'")) {
                Write-Host "Aktualizacja członka '$memberName' do roli '$roleName'..." -ForegroundColor Cyan
                $escapedSafe = [uri]::EscapeDataString($safeIdentifier)
                $escapedMember = [uri]::EscapeDataString($memberName)
                Invoke-CyberArkApi -Method Put -Uri "$PVWAURL/api/Safes/$escapedSafe/Members/$escapedMember" -Headers $headers -Body $updateBody | Out-Null
            }
        }
        else {
            throw "Członek '$memberName' już istnieje w Safe '$safeName'. Użyj -UpdateExistingMembers, aby zaktualizować jego uprawnienia."
        }
    }

    $accountName = [string](Get-ObjectProperty $config.account "name")
    if ([string]::IsNullOrWhiteSpace($accountName)) {
        $accountName = "{0}-{1}-{2}" -f `
            ([string](Get-ObjectProperty $config.account "platformId")), `
            ([string](Get-ObjectProperty $config.account "address")), `
            ([string](Get-ObjectProperty $config.account "userName"))
    }

    $accountTarget = "{0}@{1}" -f `
        ([string](Get-ObjectProperty $config.account "userName")), `
        ([string](Get-ObjectProperty $config.account "address"))

    $createdAccount = $null

    if ($PSCmdlet.ShouldProcess("Konto '$accountTarget' w Safe '$safeName'", "Dodanie konta do CyberArk")) {
        if ($null -eq $AccountSecret) {
            $AccountSecret = Read-Host "Podaj początkowy sekret konta '$accountTarget'" -AsSecureString
        }

        $plainSecret = ConvertFrom-SecureStringPlainText -SecureString $AccountSecret

        try {
            $secretType = [string](Get-ObjectProperty $config.account "secretType")
            if ([string]::IsNullOrWhiteSpace($secretType)) {
                $secretType = "password"
            }

            $accountBody = [ordered]@{
                name       = $accountName
                address    = [string](Get-ObjectProperty $config.account "address")
                userName   = [string](Get-ObjectProperty $config.account "userName")
                platformId = [string](Get-ObjectProperty $config.account "platformId")
                safeName   = $safeName
                secretType = $secretType
                secret     = $plainSecret
            }

            foreach ($propertyName in @("platformAccountProperties", "secretManagement", "remoteMachinesAccess")) {
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
            throw "Konto zostało utworzone, ale odpowiedź API nie zawiera jego ID. Reconcile nie może zostać uruchomiony automatycznie."
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
    Write-Host ("Safe:    {0}" -f $safeName)
    Write-Host ("Konto:   {0}" -f $accountTarget)
    Write-Host ("Członkowie z konfiguracji: {0}" -f @($config.members).Count)
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

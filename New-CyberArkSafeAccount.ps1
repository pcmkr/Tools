#requires -Version 5.1
<#
.SYNOPSIS
    Tworzy Safe w CyberArk PAM, przypisuje członków z rolami, dodaje konto
    i uruchamia Reconcile.

.DESCRIPTION
    Skrypt jest przeznaczony dla jednego, stałego typu konta opisanego w JSON.
    Nazwa Safe jest przekazywana jako parametr. PVWAURL, AuthType, login konta
    i sekret mogą pochodzić z parametrów albo z sekcji defaults w konfiguracji.
    Parametry przekazane w CLI mają pierwszeństwo przed wartościami z JSON.

    Dla każdego Safe automatycznie wyliczana jest grupa właścicieli:
        <SafeName><ownerGroupSuffix>

    Domyślnie daje to np.:
        APP-PRD-SQL01_owner

    Grupa jest dodawana do Safe z uprawnieniami roli Owner z pliku JSON.

    Pole CyberArk Account "name" (Object Name) nie jest wysyłane do API.
    CyberArk generuje nazwę obiektu konta zgodnie z własnym mechanizmem.

.PARAMETER PVWAURL
    Bazowy URL PVWA, np. https://pvwa.example.com/PasswordVault.
    Jeśli nie zostanie podany, używana jest wartość defaults.pvwaUrl z JSON.

.PARAMETER SafeName
    Nazwa tworzonego Safe, np. APP-PRD-SQL01.

.PARAMETER AccountUserName
    Login konta dodawanego do Safe, np. svc_sql.
    Jeśli nie zostanie podany, używana jest wartość defaults.accountUserName.

.PARAMETER ConfigPath
    Ścieżka do pliku JSON. Domyślnie:
        $PSScriptRoot\CyberArk-SafeConfig.json

    Plik definiuje wartości domyślne, właściwości Safe, typ konta, role,
    stałych członków oraz sposób tworzenia grupy Owner.

.PARAMETER AuthType
    Metoda logowania: CyberArk, LDAP albo Radius.
    Jeśli nie zostanie podana, używana jest wartość defaults.authType z JSON,
    a jeśli jej brak — CyberArk.

.PARAMETER Credential
    Opcjonalny PSCredential do logowania do PVWA.

.PARAMETER AccountSecret
    Początkowy sekret konta. Kolejność rozwiązywania:
      1. parametr -AccountSecret,
      2. zmienna środowiskowa z defaults.accountSecretEnvironmentVariable,
      3. defaults.accountSecret (jawny tekst; niezalecane),
      4. interaktywny prompt SecureString.

.PARAMETER ADServer
    Domena DNS albo konkretny kontroler domeny używany do walidacji grupy Owner
    w Active Directory. Kolejność wyboru:
      1. parametr -ADServer,
      2. owner.adServer w JSON,
      3. defaults.adServer w JSON.

    owner.searchIn NIE określa domeny dla Get-ADGroup; jest to wartość searchIn
    przekazywana do CyberArk przy dodawaniu członka Safe.

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
        -ConfigPath .\CyberArk-SafeConfig.example.json `
        -ADServer "corp.example.com"

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

    Domyślny plik CyberArk-SafeConfig.json powinien pozostać poza repozytorium,
    jeśli zawiera sekret. Repozytorium zawiera jedynie plik *.example.json.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
param(
    [string]$PVWAURL,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SafeName,

    [string]$AccountUserName,

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "CyberArk-SafeConfig.json"),

    [string]$AuthType,

    [System.Management.Automation.PSCredential]$Credential,

    [System.Security.SecureString]$AccountSecret,

    [string]$ADServer,

    [switch]$AllowExistingSafe,

    [switch]$UpdateExistingMembers,

    [switch]$SkipReconcile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
        ErrorAction = "Stop"
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

    try {
        return Invoke-RestMethod @parameters
    }
    catch {
        $statusCode = Get-HttpStatusCode $_.Exception
        $errorCode = $null
        $errorMessage = $null
        $rawDetails = [string]$_.ErrorDetails.Message

        if (-not [string]::IsNullOrWhiteSpace($rawDetails)) {
            try {
                $details = $rawDetails | ConvertFrom-Json
                $errorCode = [string](Get-ObjectProperty $details "ErrorCode")
                $errorMessage = [string](Get-ObjectProperty $details "ErrorMessage")
            }
            catch {
                # Odpowiedź nie była JSON-em; zachowujemy surową treść.
            }
        }

        $message = "CyberArk REST error: Method='$Method'; Uri='$Uri'"
        if ($null -ne $statusCode) {
            $message += "; HTTP=$statusCode"
        }
        if (-not [string]::IsNullOrWhiteSpace($errorCode)) {
            $message += "; ErrorCode='$errorCode'"
        }
        if (-not [string]::IsNullOrWhiteSpace($errorMessage)) {
            $message += "; ErrorMessage='$errorMessage'"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($rawDetails)) {
            $message += "; Response='$rawDetails'"
        }

        throw $message
    }
}

function Get-SafeByName {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    try {
        $response = Invoke-CyberArkApi -Method Get -Uri "$PVWAURL/api/Safes" -Headers $Headers

        $safes = @()
        if ($null -ne $response.value) {
            $safes = @($response.value)
        }
        elseif ($response -is [System.Array]) {
            $safes = @($response)
        }
        else {
            $safes = @($response)
        }

        return $safes |
            Where-Object { $_.safeName -eq $Name } |
            Select-Object -First 1
    }
    catch {
        throw "Nie udało się pobrać listy Safe z '$PVWAURL/api/Safes'. Szczegóły: $($_.Exception.Message)"
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
        return Invoke-CyberArkApi -Method Get -Uri "$PVWAURL/api/Safes/$safeId/Members/$memberId/" -Headers $Headers
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

$defaults = Get-ObjectProperty $config "defaults"

if ([string]::IsNullOrWhiteSpace($PVWAURL)) {
    $PVWAURL = [string](Get-ObjectProperty $defaults "pvwaUrl")
}
if ([string]::IsNullOrWhiteSpace($PVWAURL)) {
    throw "PVWAURL nie został podany i brakuje defaults.pvwaUrl w pliku konfiguracyjnym."
}
$PVWAURL = $PVWAURL.TrimEnd("/")

if ([string]::IsNullOrWhiteSpace($AuthType)) {
    $AuthType = [string](Get-ObjectProperty $defaults "authType")
}
if ([string]::IsNullOrWhiteSpace($AuthType)) {
    $AuthType = "CyberArk"
}
if ($AuthType -notin @("CyberArk", "LDAP", "Radius")) {
    throw "Nieprawidłowy AuthType '$AuthType'. Dozwolone: CyberArk, LDAP, Radius."
}

if ([string]::IsNullOrWhiteSpace($AccountUserName)) {
    $AccountUserName = [string](Get-ObjectProperty $defaults "accountUserName")
}
if ([string]::IsNullOrWhiteSpace($AccountUserName)) {
    throw "Login konta nie został podany i brakuje defaults.accountUserName w pliku konfiguracyjnym."
}

if ([string]::IsNullOrWhiteSpace($ADServer)) {
    $ADServer = [string](Get-ObjectProperty $config.owner "adServer")
}
if ([string]::IsNullOrWhiteSpace($ADServer)) {
    $ADServer = [string](Get-ObjectProperty $defaults "adServer")
}

if ($null -eq $AccountSecret) {
    $secretEnvironmentVariable = [string](Get-ObjectProperty $defaults "accountSecretEnvironmentVariable")

    if (-not [string]::IsNullOrWhiteSpace($secretEnvironmentVariable)) {
        $secretFromEnvironment = [Environment]::GetEnvironmentVariable($secretEnvironmentVariable)
        if (-not [string]::IsNullOrWhiteSpace($secretFromEnvironment)) {
            $AccountSecret = ConvertTo-SecureString -String $secretFromEnvironment -AsPlainText -Force
        }
    }

    if ($null -eq $AccountSecret) {
        $plainConfigSecret = [string](Get-ObjectProperty $defaults "accountSecret")
        if (-not [string]::IsNullOrWhiteSpace($plainConfigSecret)) {
            Write-Warning "Używany jest jawny defaults.accountSecret z pliku konfiguracyjnego. Zalecana jest zmienna środowiskowa."
            $AccountSecret = ConvertTo-SecureString -String $plainConfigSecret -AsPlainText -Force
        }
    }
}

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

# owner.searchIn to nazwa katalogu/domeny widoczna dla CyberArk.
# Nie jest używana do zapytań Active Directory. Do walidacji AD służy
# -ADServer / owner.adServer / defaults.adServer (w tej kolejności).
#
# Walidacja grupy Owner odbywa się przed logowaniem do CyberArk i przed
# wykonaniem jakichkolwiek zmian po stronie Vault/PVWA.
if ([string]::IsNullOrWhiteSpace($ADServer)) {
    throw "Nie wskazano domeny/kontrolera AD do walidacji grupy Owner. Ustaw -ADServer, owner.adServer albo defaults.adServer."
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    throw "Nie można załadować modułu ActiveDirectory. Zainstaluj RSAT Active Directory PowerShell. Szczegóły: $($_.Exception.Message)"
}

try {
    Write-Host ("Walidacja grupy Owner: nazwa='{0}', ADServer='{1}'" -f $ownerGroupName, $ADServer) -ForegroundColor Cyan

    $ownerADGroup = Get-ADGroup -Identity $ownerGroupName -Server $ADServer -Properties sAMAccountName -ErrorAction Stop
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    throw "Grupa Owner '$ownerGroupName' nie istnieje w Active Directory na '$ADServer'."
}
catch {
    throw "Nie udało się sprawdzić grupy Owner '$ownerGroupName' w Active Directory na '$ADServer'. Szczegóły: $($_.Exception.Message)"
}

Write-Host ("Zweryfikowano grupę AD Owner: {0}; sAMAccountName={1}; DN={2}; ADServer={3}" -f $ownerADGroup.Name, $ownerADGroup.SamAccountName, $ownerADGroup.DistinguishedName, $ADServer) -ForegroundColor Green

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
    Write-Host ("Logowanie do CyberArk PAM... AuthType={0}; URL={1}/api/Auth/{0}/Logon" -f $AuthType, $PVWAURL) -ForegroundColor Cyan

    $logonBody = @{
        username          = $Credential.UserName
        password          = $Credential.GetNetworkCredential().Password
        concurrentSession = $true
    }

    $logonResponse = Invoke-CyberArkApi `
        -Method Post `
        -Uri "$PVWAURL/api/Auth/$AuthType/Logon" `
        -Body $logonBody `
        -TimeoutSec 120

    Write-Host ("Typ odpowiedzi logowania: {0}" -f $logonResponse.GetType().FullName) -ForegroundColor DarkGray

    if ($logonResponse -isnot [string]) {
        $responseProperties = @($logonResponse.PSObject.Properties.Name)
        if ($responseProperties.Count -gt 0) {
            Write-Host ("Pola odpowiedzi logowania: {0}" -f ($responseProperties -join ", ")) -ForegroundColor DarkGray
        }
    }

    $token = $logonResponse

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

    # Invoke-RestMethod deserializuje prawidłową odpowiedź Logon do stringa.
    # Usuwamy wyłącznie białe znaki; nie próbujemy "naprawiać" dowolnej
    # odpowiedzi obiektowej przez rzutowanie jej na tekst.
    if ($token -isnot [string]) {
        throw "Odpowiedź logowania nie zawiera rozpoznanego tokenu sesji. AuthType='$AuthType'. Typ odpowiedzi: $($logonResponse.GetType().FullName)."
    }

    $token = $token.Trim()

    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "CyberArk zwrócił pusty token po normalizacji odpowiedzi logowania."
    }

    Write-Host ("Logowanie zakończone. Otrzymano token sesji (długość: {0})." -f $token.Length) -ForegroundColor Green

    $headers = @{ Authorization = $token }

    Write-Host "Weryfikacja sesji CyberArk..." -ForegroundColor Cyan
    try {
        $verify = Invoke-CyberArkApi -Method Get -Uri "$PVWAURL/api/Verify/" -Headers $headers -TimeoutSec 60
        Write-Host "Sesja CyberArk jest prawidłowa." -ForegroundColor Green
    }
    catch {
        throw "Logowanie zwróciło token, ale PVWA odrzuca go przy GET /api/Verify/. AuthType='$AuthType', PVWAURL='$PVWAURL'. Szczegóły: $($_.Exception.Message)"
    }

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
            # Dla PVWA on-prem używamy kanonicznego endpointu z końcowym "/".
            # Unika to redirectu /api/Safes -> /api/Safes/, przy którym PowerShell
            # może nie przekazać nagłówka Authorization do kolejnego żądania.
            $safe = Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Safes/" -Headers $headers -Body $safeBody -TimeoutSec 300
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
                Invoke-CyberArkApi -Method Put -Uri "$PVWAURL/api/Safes/$escapedSafe/Members/$escapedMember/" -Headers $headers -Body $updateBody | Out-Null
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

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

    Dla sejfu generowane sa grupy z safeMembers.groupSuffix:
        <SafeName><groupSuffix>

    Domyślnie daje to np.:
        APP-PRD-SQL01_owner

    Wszystkie wpisy safeMembers sa przypisywane do Safe wedlug roles.

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
    czlonkow sejfu w pojedynczej sekcji safeMembers.

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
    Kontroler AD do walidacji safeMembers (gdy wpis nie zawiera adServer).
    Wartosci: parametr -ADServer, nastepnie defaults.adServer.

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

    $safeId = [uri]::EscapeDataString($Name)
    $uri = "$PVWAURL/api/Safes/$safeId/"

    try {
        return Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -ContentType "application/json" -TimeoutSec 60 -ErrorAction Stop
    }
    catch {
        $statusCode = Get-HttpStatusCode $_.Exception

        if ($statusCode -eq 404) {
            return $null
        }

        $details = [string]$_.ErrorDetails.Message
        if ([string]::IsNullOrWhiteSpace($details)) {
            $details = $_.Exception.Message
        }

        throw "Nie udało się sprawdzić Safe '$Name' pod '$uri'. HTTP=$statusCode. Szczegóły: $details"
    }
}

function Get-SafeMember {
    param(
        [Parameter(Mandatory)][string]$SafeIdentifier,
        [Parameter(Mandatory)][string]$MemberName,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    # Pobieramy liste czlonkow zamiast GET konkretnego czlonka.
    # Niektore wersje PVWA dla nieistniejacego czlonka zwracaja
    # SWS0008 (czasem HTTP 400 zamiast 404).
    $safeId = [uri]::EscapeDataString($SafeIdentifier)
    $uri = "$PVWAURL/api/Safes/$safeId/Members/"
    $page = 0
    do {
        $page++
        if ($page -gt 100) { throw "Przekroczono limit stronicowania czlonkow Safe '$SafeIdentifier'." }
        $response = Invoke-CyberArkApi -Method Get -Uri $uri -Headers $Headers
        $items = @()
        if ($null -ne $response.value) {
            $items = @($response.value)
        }
        elseif ($null -ne (Get-ObjectProperty $response 'members')) {
            $items = @($response.members)
        }
        elseif ($response -is [array]) {
            $items = @($response)
        }
        elseif ($null -ne (Get-ObjectProperty $response 'memberName')) {
            $items = @($response)
        }
        foreach ($item in $items) {
            if ([string]::Equals([string]$item.memberName, $MemberName, [StringComparison]::OrdinalIgnoreCase)) {
                return $item
            }
        }
        $nextLink = [string](Get-ObjectProperty $response 'nextLink')
        if ([string]::IsNullOrWhiteSpace($nextLink)) { break }
        if ([uri]::IsWellFormedUriString($nextLink, [UriKind]::Absolute)) {
            $uri = $nextLink
        }
        else {
            $uri = ([uri]::new(([uri]$PVWAURL), $nextLink)).AbsoluteUri
        }
    } while ($true)
    return $null
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

function Get-CyberArkAccountInSafe {
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$PlatformId,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $safeFilter = [uri]::EscapeDataString("safeName eq $SafeName")
    $uri = "$PVWAURL/api/Accounts?filter=$safeFilter"

    $response = Invoke-CyberArkApi -Method Get -Uri $uri -Headers $Headers
    $accounts = @()

    if ($null -ne $response.value) {
        $accounts = @($response.value)
    }
    elseif ($response -is [System.Array]) {
        $accounts = @($response)
    }
    elseif ($null -ne $response) {
        $accounts = @($response)
    }

    return $accounts |
        Where-Object {
            $_.safeName -eq $SafeName -and
            $_.userName -eq $UserName -and
            $_.address -eq $Address -and
            $_.platformId -eq $PlatformId
        } |
        Select-Object -First 1
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

foreach ($requiredSection in @("safe", "roles", "account", "safeMembers")) {
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

foreach ($legacySection in @("owner", "members", "roleGroups")) {
    if (Test-ObjectProperty $config $legacySection) { throw "Usun przestarzala sekcje $legacySection. Uzyj safeMembers." }
}
$members = [System.Collections.Generic.List[object]]::new()
$seenMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (-not (Test-ObjectProperty $config "safeMembers")) { throw "Wymagana sekcja safeMembers." }
if (@($config.safeMembers).Count -eq 0) { throw "safeMembers nie moze byc puste." }
foreach ($entry in @($config.safeMembers)) {
    $name = [string](Get-ObjectProperty $entry "name")
    $suffix = [string](Get-ObjectProperty $entry "groupSuffix")
    $role = [string](Get-ObjectProperty $entry "role")
    $searchIn = [string](Get-ObjectProperty $entry "searchIn")
    if ((-not [string]::IsNullOrWhiteSpace($name)) -eq (-not [string]::IsNullOrWhiteSpace($suffix))) {
        throw "safeMembers: podaj dokladnie jedno z name albo groupSuffix."
    }
    if ($suffix) { $name = $SafeName + $suffix }
    if ([string]::IsNullOrWhiteSpace($role) -or [string]::IsNullOrWhiteSpace($searchIn)) {
        throw "safeMembers: role i searchIn sa wymagane dla $name."
    }
    if (-not $seenMembers.Add($name)) { throw "Powtorzony czlonek sejfu: $name." }
    if ($null -eq $config.roles.PSObject.Properties[$role]) { throw "Nieznana rola $role dla $name." }
    $validate = [bool](-not [string]::IsNullOrWhiteSpace($suffix))
    if (Test-ObjectProperty $entry "validateAD") {
        $v = Get-ObjectProperty $entry "validateAD"
        if ($v -isnot [bool]) { throw "validateAD musi byc bool dla $name." }
        $validate = $v
    }
    $server = [string](Get-ObjectProperty $entry "adServer")
    if ([string]::IsNullOrWhiteSpace($server)) { $server = $ADServer }
    if ($validate) {
        if (-not $server) { throw "Brak ADServer dla $name." }
        if (-not (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory -ErrorAction Stop }
        try {
            $adGroup = Get-ADGroup -Identity $name -Server $server -ErrorAction Stop
            Write-Host ("Grupa AD OK: {0}" -f $adGroup.Name) -ForegroundColor Green
        } catch { throw "Grupa AD $name nie zostala zweryfikowana: $($_.Exception.Message)" }
    }
    $memberRecord = [ordered]@{ name=$name; role=$role; searchIn=$searchIn }
    if (Test-ObjectProperty $entry "membershipExpirationDate") {
        $memberRecord.membershipExpirationDate = Get-ObjectProperty $entry "membershipExpirationDate"
    }
    $members.Add([pscustomobject]$memberRecord)
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
        Write-Warning "Safe '$SafeName' już istnieje."

        $answer = Read-Host "Kontynuować dodawanie konta do istniejącego Safe? [y/n]"
        if ($answer -ne "y") {
            Write-Host "Operacja przerwana przez użytkownika." -ForegroundColor Yellow
            return
        }

        $AllowExistingSafe = $true
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
                try {
                    Invoke-CyberArkApi -Method Post -Uri "$PVWAURL/api/Safes/$escapedSafe/Members" -Headers $headers -Body $memberBody | Out-Null
                }
                catch {
                    # Ostateczne zabezpieczenie: Vault moze zwrocic juz-istniejacego
                    # czlonka mimo ze zapytanie GET go nie wykazalo.
                    # Nie maskujemy innych bledow ani duplikatow innych nazw.
                    $apiError = [string]$_.Exception.Message
                    $escapedMemberPattern = [regex]::Escape($memberName)
                    if ($apiError -match "ErrorCode='(?:SFWS0012|SWFS0012)'" -and
                        $apiError -match $escapedMemberPattern -and
                        $apiError -match '(?i)already.*member|member.*already') {
                        Write-Warning ("Czlonek '{0}' jest juz w Safe '{1}' - pomijam dodawanie." -f $memberName, $SafeName)
                    }
                    else {
                        throw
                    }
                }
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
            Write-Host ("Czlonek '{0}' juz istnieje w Safe '{1}' - bez zmiany uprawnien." -f $memberName, $SafeName) -ForegroundColor DarkGray
        }
    }

    $accountAddress = Expand-TemplateValue ([string](Get-ObjectProperty $config.account "address"))
    $accountPlatformId = [string](Get-ObjectProperty $config.account "platformId")
    $accountTarget = "$AccountUserName@$accountAddress"
    $createdAccount = $null

    Write-Host "Sprawdzanie, czy konto '$accountTarget' już istnieje w Safe '$SafeName'..." -ForegroundColor Cyan
    $existingAccount = Get-CyberArkAccountInSafe -SafeName $SafeName -UserName $AccountUserName -Address $accountAddress -PlatformId $accountPlatformId -Headers $headers

    if ($null -ne $existingAccount) {
        $existingAccountId = [string](Get-ObjectProperty $existingAccount "id")
        Write-Warning ("Konto już istnieje w Safe '{0}': userName='{1}', address='{2}', platformId='{3}', id='{4}'" -f $SafeName, $AccountUserName, $accountAddress, $accountPlatformId, $existingAccountId)
    }
    elseif ($PSCmdlet.ShouldProcess("Konto '$accountTarget' w Safe '$SafeName'", "Dodanie konta do CyberArk")) {
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
                platformId = $accountPlatformId
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
    Write-Host "Czlonkowie Safe / role:"
    foreach ($member in $members) {
        Write-Host ("  {0,-18} {1}" -f ([string]$member.role + ':'), [string]$member.name)
    }
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

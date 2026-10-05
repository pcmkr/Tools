#requires -Version 5.1
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Eksportuje informacje o stanie wskazanych kont użytkowników Active Directory.

.DESCRIPTION
    Lista użytkowników jest definiowana bezpośrednio w tablicy $Zmienna.

    Skrypt pobiera:
      - ostatnie udane logowanie,
      - ostatnią nieudaną próbę uwierzytelnienia hasłem,
      - stan Enabled / Disabled,
      - datę ostatniego Enable / Disable (opcjonalnie z Security Event Log),
      - stan blokady i czas blokady,
      - wygaśnięcie konta,
      - stan wygaśnięcia hasła i datę wygaśnięcia hasła.

    WAŻNE:
      * lastLogon oraz badPasswordTime nie są replikowane pomiędzy DC,
        dlatego skrypt odpytuje wszystkie kontrolery domeny i wybiera
        najnowszą wartość.
      * badPasswordTime oznacza ostatnią błędną próbę podania hasła.
        Nie jest to pełny odpowiednik każdego możliwego zdarzenia 4625.
      * AD nie przechowuje wiarygodnego atrybutu "EnabledSince" / "DisabledSince".
        Dokładna data zmiany stanu konta wymaga zdarzeń Security:
          4722 - konto zostało włączone,
          4725 - konto zostało wyłączone.

.EXAMPLE
    $Zmienna = @(
        "user1",
        "user2",
        "user3"
    )

    .\Export-ADUserState.ps1 -Domain corp.example.com

.EXAMPLE
    Aby pobrać datę ostatniego włączenia/wyłączenia konta z logów Security:
        $QueryAccountStateEvents = $true

.NOTES
    Wymagania:
      - PowerShell 5.1+
      - moduł ActiveDirectory / RSAT
      - łączność ze wszystkimi DC
      - dla odczytu 4722/4725: uprawnienia do Security Event Log na DC
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop


# ============================================================
# KONFIGURACJA
# ============================================================

# sAMAccountName użytkowników do sprawdzenia.
$Zmienna = @(
    "user1",
    "user2",
    "user3"
)

# $true = przeszukuj Security log na DC dla Event ID 4722/4725.
# Może być wolne przy dużej liczbie użytkowników i dużych logach.
$QueryAccountStateEvents = $false

# Jak daleko wstecz szukać 4722/4725.
$EventLogDaysBack = 365

# Plik wynikowy.
$OutputPath = Join-Path $PWD (
    "AD-User-State-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv"
)

# CSV czytelny po imporcie do polskiego Excela.
$Delimiter = ";"

# PowerShell 5.1 nie obsługuje nazwy utf8BOM w Export-Csv,
# dlatego dla maksymalnej zgodności używamy Unicode.
$Encoding = "Unicode"


# ============================================================
# FUNKCJE
# ============================================================

function Convert-ADFileTime {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        $FileTime = [Int64]$Value

        if (
            $FileTime -le 0 -or
            $FileTime -eq [Int64]::MaxValue
        ) {
            return $null
        }

        return [DateTime]::FromFileTimeUtc($FileTime).ToLocalTime()
    }
    catch {
        return $null
    }
}


function Get-MaxNonReplicatedTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        [ValidateSet("lastLogon", "badPasswordTime")]
        [string]$AttributeName,

        [Parameter(Mandatory)]
        [object[]]$DomainControllers
    )

    [Int64]$MaxValue = 0
    $SourceDC = $null

    foreach ($DC in $DomainControllers) {
        try {
            $UserOnDC = Get-ADUser `
                -Identity $DistinguishedName `
                -Server $DC.HostName `
                -Properties $AttributeName `
                -ErrorAction Stop

            $RawValue = $UserOnDC.$AttributeName

            if ($null -ne $RawValue) {
                [Int64]$CurrentValue = $RawValue

                if ($CurrentValue -gt $MaxValue) {
                    $MaxValue = $CurrentValue
                    $SourceDC = $DC.HostName
                }
            }
        }
        catch {
            Write-Warning (
                "Nie udało się pobrać {0} dla {1} z DC {2}: {3}" -f
                $AttributeName,
                $DistinguishedName,
                $DC.HostName,
                $_.Exception.Message
            )
        }
    }

    [PSCustomObject]@{
        Date     = if ($MaxValue -gt 0) {
            Convert-ADFileTime $MaxValue
        }
        else {
            $null
        }
        SourceDC = $SourceDC
    }
}


function Get-LastAccountStateEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        [object[]]$DomainControllers,

        [Parameter(Mandatory)]
        [int]$DaysBack
    )

    $StartTime = (Get-Date).AddDays(-$DaysBack)
    $MatchingEvents = @()

    foreach ($DC in $DomainControllers) {
        try {
            $Filter = @{
                LogName   = "Security"
                Id        = 4722, 4725
                StartTime = $StartTime
            }

            $Events = Get-WinEvent `
                -ComputerName $DC.HostName `
                -FilterHashtable $Filter `
                -ErrorAction Stop

            foreach ($Event in $Events) {
                try {
                    [xml]$Xml = $Event.ToXml()
                    $EventData = @{}

                    foreach ($Data in $Xml.Event.EventData.Data) {
                        $EventData[$Data.Name] = [string]$Data.'#text'
                    }

                    if ($EventData["TargetUserName"] -ieq $SamAccountName) {
                        $MatchingEvents += [PSCustomObject]@{
                            TimeCreated      = $Event.TimeCreated
                            EventId          = $Event.Id
                            State            = switch ($Event.Id) {
                                4722 { "Enabled" }
                                4725 { "Disabled" }
                            }
                            DomainController = $DC.HostName
                            ChangedBy        = $EventData["SubjectUserName"]
                        }
                    }
                }
                catch {
                    # Pomijamy pojedyncze zdarzenia, których XML nie da się sparsować.
                }
            }
        }
        catch {
            Write-Warning (
                "Nie udało się odczytać Security log z DC {0}: {1}" -f
                $DC.HostName,
                $_.Exception.Message
            )
        }
    }

    return (
        $MatchingEvents |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 1
    )
}


# ============================================================
# WALIDACJA
# ============================================================

$Users = @(
    $Zmienna |
        ForEach-Object {
            if ($null -ne $_) {
                ([string]$_).Trim()
            }
        } |
        Where-Object { $_ } |
        Sort-Object -Unique
)

if ($Users.Count -eq 0) {
    throw 'Tablica $Zmienna jest pusta. Dodaj co najmniej jeden sAMAccountName.'
}


# ============================================================
# DOMENA I KONTROLERY DOMENY
# ============================================================

$DomainInfo = Get-ADDomain -Identity $Domain -Server $Domain -ErrorAction Stop

$DomainControllers = @(
    Get-ADDomainController -Filter * -Server $Domain -ErrorAction Stop |
        Sort-Object HostName
)

if ($DomainControllers.Count -eq 0) {
    throw "Nie znaleziono kontrolerów domeny dla: $Domain"
}

Write-Host "Domena: $Domain"
Write-Host "Kontrolery domeny: $($DomainControllers.Count)"


# ============================================================
# GŁÓWNA PĘTLA
# ============================================================

$Now = Get-Date

$Results = foreach ($SamAccountName in $Users) {

    Write-Host "Przetwarzanie: $SamAccountName"

    try {
        $EscapedSam = $SamAccountName.Replace("'", "''")

        $User = Get-ADUser `
            -Filter "SamAccountName -eq '$EscapedSam'" `
            -Server $Domain `
            -Properties @(
                "DisplayName",
                "UserPrincipalName",
                "Enabled",
                "LockedOut",
                "lockoutTime",
                "PasswordExpired",
                "PasswordNeverExpires",
                "PasswordLastSet",
                "msDS-UserPasswordExpiryTimeComputed",
                "AccountExpirationDate",
                "DistinguishedName"
            ) `
            -ErrorAction Stop |
            Select-Object -First 1

        if ($null -eq $User) {
            [PSCustomObject]@{
                SamAccountName             = $SamAccountName
                Found                      = $false
                DisplayName                = $null
                UserPrincipalName          = $null
                Enabled                    = $null
                Disabled                   = $null
                AccountStateChanged        = $null
                AccountStateEventId        = $null
                AccountStateChangedBy      = $null
                AccountStateSourceDC       = $null
                LastSuccessfulLogon        = $null
                LastSuccessfulLogonDC      = $null
                LastFailedPasswordAttempt  = $null
                LastFailedPasswordDC       = $null
                LockedOut                  = $null
                LockedSince                = $null
                AccountExpirationDate      = $null
                AccountExpired             = $null
                PasswordLastSet            = $null
                PasswordNeverExpires       = $null
                PasswordExpired            = $null
                PasswordExpirationDate     = $null
                DistinguishedName          = $null
                Error                      = "User not found"
            }

            continue
        }

        $LastLogon = Get-MaxNonReplicatedTime `
            -DistinguishedName $User.DistinguishedName `
            -AttributeName "lastLogon" `
            -DomainControllers $DomainControllers

        $LastBadPassword = Get-MaxNonReplicatedTime `
            -DistinguishedName $User.DistinguishedName `
            -AttributeName "badPasswordTime" `
            -DomainControllers $DomainControllers

        $LockoutTime = Convert-ADFileTime $User.lockoutTime

        $PasswordExpirationDate = $null

        if (-not $User.PasswordNeverExpires) {
            $PasswordExpirationDate = Convert-ADFileTime (
                $User."msDS-UserPasswordExpiryTimeComputed"
            )
        }

        $AccountExpired = $false

        if ($null -ne $User.AccountExpirationDate) {
            $AccountExpired = ($User.AccountExpirationDate -lt $Now)
        }

        $StateEvent = $null

        if ($QueryAccountStateEvents) {
            $StateEvent = Get-LastAccountStateEvent `
                -SamAccountName $User.SamAccountName `
                -DomainControllers $DomainControllers `
                -DaysBack $EventLogDaysBack
        }

        [PSCustomObject]@{
            SamAccountName             = $User.SamAccountName
            Found                      = $true
            DisplayName                = $User.DisplayName
            UserPrincipalName          = $User.UserPrincipalName

            Enabled                    = [bool]$User.Enabled
            Disabled                   = -not [bool]$User.Enabled

            AccountStateChanged        = if ($StateEvent) {
                $StateEvent.TimeCreated
            }
            else {
                $null
            }

            AccountStateEventId        = if ($StateEvent) {
                $StateEvent.EventId
            }
            else {
                $null
            }

            AccountStateChangedBy      = if ($StateEvent) {
                $StateEvent.ChangedBy
            }
            else {
                $null
            }

            AccountStateSourceDC       = if ($StateEvent) {
                $StateEvent.DomainController
            }
            else {
                $null
            }

            LastSuccessfulLogon        = $LastLogon.Date
            LastSuccessfulLogonDC      = $LastLogon.SourceDC

            LastFailedPasswordAttempt  = $LastBadPassword.Date
            LastFailedPasswordDC       = $LastBadPassword.SourceDC

            LockedOut                  = [bool]$User.LockedOut

            LockedSince                = if ($User.LockedOut) {
                $LockoutTime
            }
            else {
                $null
            }

            AccountExpirationDate      = $User.AccountExpirationDate
            AccountExpired             = $AccountExpired

            PasswordLastSet            = $User.PasswordLastSet
            PasswordNeverExpires       = [bool]$User.PasswordNeverExpires
            PasswordExpired            = [bool]$User.PasswordExpired
            PasswordExpirationDate     = $PasswordExpirationDate

            DistinguishedName          = $User.DistinguishedName
            Error                      = $null
        }
    }
    catch {
        [PSCustomObject]@{
            SamAccountName             = $SamAccountName
            Found                      = $false
            DisplayName                = $null
            UserPrincipalName          = $null
            Enabled                    = $null
            Disabled                   = $null
            AccountStateChanged        = $null
            AccountStateEventId        = $null
            AccountStateChangedBy      = $null
            AccountStateSourceDC       = $null
            LastSuccessfulLogon        = $null
            LastSuccessfulLogonDC      = $null
            LastFailedPasswordAttempt  = $null
            LastFailedPasswordDC       = $null
            LockedOut                  = $null
            LockedSince                = $null
            AccountExpirationDate      = $null
            AccountExpired             = $null
            PasswordLastSet            = $null
            PasswordNeverExpires       = $null
            PasswordExpired            = $null
            PasswordExpirationDate     = $null
            DistinguishedName          = $null
            Error                      = $_.Exception.Message
        }
    }
}


# ============================================================
# EKSPORT
# ============================================================

$OutputDirectory = Split-Path -Parent $OutputPath

if (
    $OutputDirectory -and
    -not (Test-Path -LiteralPath $OutputDirectory)
) {
    New-Item `
        -ItemType Directory `
        -Path $OutputDirectory `
        -Force |
        Out-Null
}

$Results |
    Export-Csv `
        -LiteralPath $OutputPath `
        -NoTypeInformation `
        -Delimiter $Delimiter `
        -Encoding $Encoding

Write-Host ""
Write-Host (
    "Wyeksportowano {0} rekordów do: {1}" -f
    $Results.Count,
    $OutputPath
) -ForegroundColor Green

$Results

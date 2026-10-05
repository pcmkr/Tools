# Tools

Prywatne repozytorium z narzędziami administracyjnymi i audytowymi dla Active Directory, CyberArk PAM i Splunk.

## Zawartość

| Plik | Zastosowanie |
|---|---|
| `Export-ADGroupMembership.ps1` | Eksport grup AD, członków, dokładnych czasów logowania i atrybutów HR |
| `Export-AllADUsers.ps1` | Eksport wszystkich użytkowników AD ze wszystkimi właściwościami i dokładnymi czasami logowania |
| `Export-ADUserState.ps1` | Audyt stanu wskazanych kont AD z listy sAMAccountName |
| `Find-InactiveADUsers.ps1` | Lista kont AD nieaktywnych od wskazanej liczby dni |
| `Export-CyberArkUsers.ps1` | Eksport użytkowników CyberArk PAM oraz ich typu/roli i VaultAuthorization |
| `Export-CyberArkAccess.ps1` | Pełny raport CyberArk: użytkownicy, Safe, konta i prawa dostępu |
| `New-CyberArkSafeAccount.ps1` | Tworzenie Safe, nadawanie uprawnień wg ról, onboarding konta i Reconcile |
| `CyberArk-SafeConfig.example.json` | Przykładowa konfiguracja Safe, ról, członków i konta |
| `Splunk-ADUserState.spl.md` | SPL do odtworzenia historii logowań i zmian stanu kont z Windows Security logs |

---

## Wymagania

### Active Directory

Skrypty AD wymagają modułu `ActiveDirectory` z RSAT:

```powershell
Get-Module -ListAvailable ActiveDirectory
```

W razie potrzeby na Windows 10/11:

```powershell
Get-WindowsCapability -Online -Name RSAT.ActiveDirectory*
```

### CyberArk PAM

Skrypty CyberArk wymagają:

- dostępu sieciowego do PVWA,
- konta mogącego zalogować się przez wybrany mechanizm `CyberArk`, `LDAP` lub `Radius`,
- odpowiednich uprawnień API dla raportowanych danych.

### Splunk

Zapytanie SPL zakłada obecność Windows Security Event Log w Splunku. Nazwy `index`, `sourcetype` i pól mogą wymagać dostosowania do lokalnej konfiguracji i używanego TA.

---

# Active Directory

## Export-ADGroupMembership.ps1

Eksportuje grupy AD i ich członków.

Tworzy:

- `Groups.csv`
- `Memberships.csv`
- opcjonalnie `Errors.csv`

Obsługuje:

- członkostwo bezpośrednie i zagnieżdżone,
- `MembershipDepth`,
- pełną ścieżkę członkostwa,
- użytkowników, komputery i grupy,
- DN, OU, mail, stan Enabled,
- dokładny `LastLogon` i `LastBadPasswordAttempt` z maksimum ze wszystkich dostępnych DC,
- `extensionAttribute2`, `extensionAttribute13`, `employeeID`, `employeeType`,
- scope/category grup,
- wykrywanie cyklicznego zagnieżdżenia.

### Pełny eksport

```powershell
.\Export-ADGroupMembership.ps1 `
    -Domain corp.example.com `
    -ExpandNested `
    -IncludeEmptyGroups
```

### Eksport z konkretnego OU

```powershell
.\Export-ADGroupMembership.ps1 `
    -Domain corp.example.com `
    -SearchBase "OU=Groups,DC=corp,DC=example,DC=com" `
    -ExpandNested
```

### Filtrowanie grup

```powershell
.\Export-ADGroupMembership.ps1 `
    -Domain corp.example.com `
    -GroupFilter 'Name -like "GRP-*"' `
    -ExpandNested
```

Parametr `-Domain` przyjmuje domenę DNS lub konkretny DC. Dostępne są aliasy `-Server` i `-DomainController`.

---

## Export-AllADUsers.ps1

Eksportuje wszystkich użytkowników AD wraz ze wszystkimi właściwościami zwracanymi przez `Get-ADUser -Properties *`.

Dodatkowo tworzy jednoznaczne kolumny:

- `LastLogonExact` — maksimum niereplikowanego `lastLogon` ze wszystkich dostępnych DC,
- `LastLogonSourceDC`,
- `LastBadPasswordAttemptExact` — maksimum niereplikowanego `badPasswordTime`,
- `LastBadPasswordSourceDC`.

Atrybuty wielowartościowe są spłaszczane do jednej komórki. Domyślny CSV używa średnika i UTF-8 z BOM, dzięki czemu jest wygodny do otwierania w polskim Excelu.

### Pełny eksport domeny

```powershell
.\Export-AllADUsers.ps1 -Domain corp.example.com
```

### Eksport konkretnego OU

```powershell
.\Export-AllADUsers.ps1 `
    -Domain corp.example.com `
    -SearchBase "OU=Users,DC=corp,DC=example,DC=com" `
    -OutputPath C:\Temp\AD-AllUsers.csv
```

Skrypt agreguje dane logowania wydajnie: wykonuje po jednym lekkim odczycie użytkowników na każdy DC zamiast odpytania każdego DC osobno dla każdego konta.

## Export-ADUserState.ps1

Audytuje wskazane konta na podstawie pliku zawierającego po jednym `sAMAccountName` w linii.

Przykład `users.txt`:

```text
jkowalski
anowak
svc_sql
```

Uruchomienie:

```powershell
.\Export-ADUserState.ps1 `
    -InputFile .\users.txt `
    -Domain corp.example.com `
    -OutputPath C:\Temp\AD-User-State.csv
```

Raport zawiera m.in.:

- Enabled,
- przybliżoną datę wyłączenia,
- dokładniejsze `LastLogon` z odpytaniem wszystkich DC,
- `LastBadPassword`,
- `PasswordLastSet`,
- `PasswordExpired`,
- wyliczoną datę wygaśnięcia hasła,
- `LockedOut`,
- `LockoutTime`,
- datę wygaśnięcia konta.

### Ważne ograniczenia

`lastLogon` i `badPasswordTime` nie są replikowane, dlatego skrypt odpytuje wszystkie DC i wybiera najnowszą wartość.

AD nie przechowuje dedykowanego pola "data wyłączenia konta". `DisabledDateApprox` pochodzi z metadanych `userAccountControl` i jest wartością przybliżoną. Dokładną datę należy ustalać z Windows Security Event ID 4725.

---

## Find-InactiveADUsers.ps1

Wyszukuje konta użytkowników, które nie logowały się przez wskazaną liczbę dni.

### Włączone konta nieaktywne od 90 dni

```powershell
.\Find-InactiveADUsers.ps1 `
    -Days 90 `
    -Domain corp.example.com
```

### Także konta wyłączone

```powershell
.\Find-InactiveADUsers.ps1 `
    -Days 180 `
    -Domain corp.example.com `
    -IncludeDisabled `
    -OutputPath C:\Temp\InactiveUsers.csv
```

Skrypt wykorzystuje `LastLogonDate`, czyli replikowany `lastLogonTimestamp`. Jest to właściwy mechanizm do raportów nieaktywności, ale nie do ustalania dokładnego czasu ostatniego logowania.

Konta bez wartości `LastLogonDate` są oznaczane jako `NeverLoggedOn=True`.

---

# CyberArk PAM

## Export-CyberArkUsers.ps1

Eksportuje wyłącznie użytkowników CyberArk PAM i informacje o ich roli/autoryzacjach.

Nie pobiera Safe ani kont.

### LDAP

```powershell
.\Export-CyberArkUsers.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AuthType LDAP
```

### CyberArk authentication

```powershell
.\Export-CyberArkUsers.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AuthType CyberArk `
    -OutputPath C:\Temp\CyberArk-Users.csv
```

Raport obejmuje m.in.:

- `UserName`
- `UserType`
- `Source`
- `ComponentUser`
- `IsEnabled`
- `IsSuspended`
- `VaultAuthorization`
- `DistinguishedName`
- `Email`
- `LastSuccessfulLoginDate`

---

## Export-CyberArkAccess.ps1

Pełniejszy raport CyberArk PAM.

Tworzy:

- `PAM-Users.csv`
- `PAM-Safes.csv`
- `PAM-SafeMembers.csv`
- `PAM-Accounts.csv`
- `PAM-AccountAccess.csv`
- `PAM-EffectiveAccess.csv`
- opcjonalnie `Errors.csv`

### Podstawowy raport

```powershell
.\Export-CyberArkAccess.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AuthType LDAP
```

### Efektywny dostęp po rozwinięciu grup AD

```powershell
.\Export-CyberArkAccess.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AuthType LDAP `
    -ExpandADGroups `
    -ADDomain corp.example.com
```

Można wskazać konkretny kontroler domeny:

```powershell
-ADServer dc01.corp.example.com
```

`PAM-AccountAccess.csv` przedstawia relację członek Safe → Safe → konto wraz z prawami.

`PAM-EffectiveAccess.csv` przy `-ExpandADGroups` rozwija grupy AD do konkretnych użytkowników.

Pełność danych zależy od uprawnień konta raportującego w CyberArk, zwłaszcza praw do listowania użytkowników, członków Safe i kont.


---

## New-CyberArkSafeAccount.ps1

Automatyzuje utworzenie Safe i onboarding jednego, stałego typu konta:

1. loguje się do PVWA,
2. tworzy Safe o nazwie podanej w parametrze `-SafeName`,
3. automatycznie dodaje grupę AD owner o nazwie `<SafeName>_owner`,
4. przypisuje jej uprawnienia roli `Owner` z JSON,
5. dodaje opcjonalnych stałych członków Safe z sekcji `members`,
6. dodaje konto o loginie podanym w `-AccountUserName`,
7. zleca `Reconcile` przez CPM,
8. wylogowuje sesję PVWA.

Nazwa Safe i login konta **nie są zapisane w JSON**. Są przekazywane przy uruchomieniu:

```powershell
.\New-CyberArkSafeAccount.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AuthType LDAP `
    -SafeName "APP-PRD-SQL01" `
    -AccountUserName "svc_sql" `
    -ConfigPath .\CyberArk-SafeConfig.example.json
```

Dla powyższego przykładu skrypt utworzy grupę właścicieli:

```text
APP-PRD-SQL01_owner
```

Sposób budowania tej nazwy jest kontrolowany przez sekcję:

```json
"owner": {
  "role": "Owner",
  "groupSuffix": "_owner",
  "searchIn": "CORP"
}
```

`searchIn` wskazuje katalog, w którym CyberArk ma wyszukać grupę. Rola `Owner` musi istnieć w sekcji `roles`.

Sekcja `account` opisuje wyłącznie stały typ konta, np.:

```json
"account": {
  "address": "corp.example.com",
  "platformId": "WinDomain",
  "secretType": "password",
  "platformAccountProperties": {
    "LogonDomain": "CORP"
  },
  "secretManagement": {
    "automaticManagementEnabled": true
  }
}
```

Pole CyberArk `name` (Object Name) **nie jest wysyłane** przez skrypt. CyberArk tworzy nazwę obiektu konta zgodnie ze swoim mechanizmem. Parametr `-AccountUserName` ustawia pole `userName`.

Hasło konta również nie jest przechowywane w JSON. Jeśli `-AccountSecret` nie zostanie przekazany, skrypt zapyta o nie jako `SecureString`.

Można przekazać sekret wcześniej:

```powershell
$secret = Read-Host "Początkowe hasło konta" -AsSecureString

.\New-CyberArkSafeAccount.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AuthType CyberArk `
    -SafeName "APP-PRD-SQL01" `
    -AccountUserName "svc_sql" `
    -ConfigPath .\CyberArk-SafeConfig.example.json `
    -AccountSecret $secret
```

### Bezpieczny test

```powershell
.\New-CyberArkSafeAccount.ps1 `
    -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -SafeName "APP-PRD-SQL01" `
    -AccountUserName "svc_sql" `
    -ConfigPath .\CyberArk-SafeConfig.example.json `
    -WhatIf
```

Dodatkowe przełączniki:

- `-AllowExistingSafe` — pozwala kontynuować, jeśli Safe już istnieje,
- `-UpdateExistingMembers` — aktualizuje uprawnienia istniejących członków,
- `-SkipReconcile` — pomija Reconcile.

W konfiguracji przykładowej niewymienione uprawnienia danej roli są ustawiane na `false`.

Konto wykonujące skrypt musi mieć prawa pozwalające tworzyć Safe, zarządzać członkami Safe, dodawać konta i inicjować operacje CPM.

`POST /api/Accounts/{id}/Reconcile` zleca operację do CPM. Jej faktyczne powodzenie zależy od konfiguracji platformy oraz Reconcile Account.

# Splunk

## Splunk-ADUserState.spl.md

Gotowe zapytanie SPL wykorzystujące Windows Security Event IDs m.in.:

- 4624 — successful logon,
- 4625 — failed logon,
- 4722 — account enabled,
- 4725 — account disabled,
- 4740 — account locked,
- 4767 — account unlocked,
- 4771 — Kerberos pre-authentication failure.

Przed użyciem zmień:

```spl
index=windows
sourcetype=WinEventLog:Security
```

oraz listę:

```spl
samaccountname IN ("user1","user2","user3")
```

i domenę:

```spl
domain="CONTOSO"
```

Szczegóły oraz ograniczenia interpretacji znajdują się bezpośrednio w pliku `Splunk-ADUserState.spl.md`.

---

# Pobranie repozytorium

Repozytorium jest prywatne, więc klonowanie wymaga uwierzytelnienia do GitHub.

HTTPS:

```bash
git clone https://github.com/pcmkr/Tools.git
cd Tools
```

SSH:

```bash
git clone git@github.com:pcmkr/Tools.git
cd Tools
```

Aktualizacja istniejącego klonu:

```bash
git pull
```

---

## PowerShell help

Każdy skrypt PowerShell zawiera comment-based help. Przykłady i opis parametrów można wyświetlić lokalnie:

```powershell
Get-Help .\Export-ADUserState.ps1 -Full
Get-Help .\Export-CyberArkUsers.ps1 -Examples
Get-Help .\Find-InactiveADUsers.ps1 -Detailed
```

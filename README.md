# AD Group Membership Export

PowerShell export grup Active Directory i ich członkostwa do CSV.

## Co eksportuje

Skrypt `Export-ADGroupMembership.ps1` tworzy:

- `Groups.csv` — jedna linia na grupę.
- `Memberships.csv` — jedna linia na relację grupa → członek.
- `Errors.csv` — tylko jeśli wystąpiły błędy lub wykryto cykliczne zagnieżdżenia.

W `Memberships.csv` znajdują się m.in.:

- grupa: nazwa, `sAMAccountName`, category, scope, mail, SID, DN i OU,
- typ członkostwa: `Direct`, `Nested` lub `Empty`,
- `MembershipDepth`,
- pełna `MembershipPath`, np. `GRP-VPN > GRP-IT > jkowalski`,
- członek: typ obiektu, nazwa, display name, `sAMAccountName`, UPN, mail, Enabled, DNS host name, SID, DN i OU,
- dla członka będącego grupą: category i scope.

## Wymagania

- Windows PowerShell / PowerShell na stacji mającej dostęp do domeny,
- moduł `ActiveDirectory` z RSAT,
- konto mające prawo odczytu odpowiednich obiektów AD.

Sprawdzenie modułu:

```powershell
Get-Module -ListAvailable ActiveDirectory
```

## Pobranie na innej stacji

```powershell
git clone https://github.com/pcmkr/tests.git
cd tests
```

## Najbardziej użyteczne uruchomienie

Eksport wszystkich grup, pustych grup oraz pełnego zagnieżdżenia:

```powershell
.\Export-ADGroupMembership.ps1 -ExpandNested -IncludeEmptyGroups
```

Skrypt utworzy katalog w bieżącej lokalizacji, np.:

```text
AD-Group-Export-20260922-113500
```

## Eksport do konkretnego katalogu

```powershell
.\Export-ADGroupMembership.ps1 `
    -OutputDirectory C:\Temp\ADExport `
    -ExpandNested `
    -IncludeEmptyGroups
```

## Tylko członkostwo bezpośrednie

```powershell
.\Export-ADGroupMembership.ps1 -IncludeEmptyGroups
```

Bez `-ExpandNested` skrypt nie schodzi do członków grup zagnieżdżonych.

## Ograniczenie do konkretnego OU

```powershell
.\Export-ADGroupMembership.ps1 `
    -SearchBase "OU=Groups,DC=example,DC=com" `
    -ExpandNested `
    -IncludeEmptyGroups
```

## Filtrowanie grup

`-GroupFilter` jest przekazywany do `Get-ADGroup -Filter`.

Przykład dla grup zaczynających się od `GRP-`:

```powershell
.\Export-ADGroupMembership.ps1 `
    -GroupFilter 'Name -like "GRP-*"' `
    -ExpandNested
```

## Separator CSV

Domyślny separator to średnik (`;`), wygodny m.in. dla polskich ustawień Excela.

Przecinek:

```powershell
.\Export-ADGroupMembership.ps1 -Delimiter ','
```

## Encoding

Domyślnie: `utf8BOM`, żeby polskie znaki poprawnie otwierały się w Excelu.

Dostępne wartości:

- `utf8`
- `utf8BOM`
- `unicode`
- `ascii`

Przykład:

```powershell
.\Export-ADGroupMembership.ps1 -Encoding utf8BOM
```

## Znaczenie MembershipType

- `Direct` — obiekt jest bezpośrednim członkiem analizowanej grupy.
- `Nested` — obiekt pochodzi z grupy zagnieżdżonej.
- `Empty` — grupa nie ma członków; wiersz pojawia się przy `-IncludeEmptyGroups`.

## Przykład ścieżki

```text
GroupName   MembershipType   MembershipDepth   MembershipPath
GRP-VPN     Direct           1                 GRP-VPN > GRP-IT
GRP-VPN     Nested           2                 GRP-VPN > GRP-IT > jkowalski
```

Dzięki temu eksport nie tylko pokazuje efektywne członkostwo, ale też przez jaką grupę zagnieżdżoną ono wynika.

## Zalecenie do audytu

Najpełniejszy wariant:

```powershell
.\Export-ADGroupMembership.ps1 `
    -OutputDirectory C:\Temp\AD-Audit `
    -ExpandNested `
    -IncludeEmptyGroups
```

Przy dużej domenie `-ExpandNested` może wykonać dużo zapytań do kontrolerów domeny i potrwać wyraźnie dłużej niż eksport wyłącznie członkostwa bezpośredniego.
# Break-Glass wg produktu — Windows Server + RHEL + CyberArk PAM

**Projekt v0.2 (2026-10-09), DRAFT.** Konfiguracja do pilotażu, **nie** produkcyjna bez testów akceptacyjnych.

## 1. Właściwe wymagania

- Łącznie **150 Windows Server i 150 RHEL**; każdy host ma lokalnego administratora **bguser**.
- **Jednostką izolacji hasła jest PRODUKT / usługa**, nie system operacyjny.
- Dla każdego produktu: **jeden Safe + jedna natywna CyberArk Account Group**.
- W Account Group występują **oba systemy**: Windows i RHEL (na każdym login bguser). **Każdy członek grupy ma to samo hasło**, niezależnie od OS.
- Osobny produkt ma własne hasło. Przykład: Safe BG-ERP / Group BG-ERP-GRP dla Windows ERP i RHEL ERP; Safe BG-CRM / Group BG-CRM-GRP dla Windows CRM i RHEL CRM.
- Operator podaje **własne kolejne hasło** właściwego produktu i świadomie zleca zmianę przez CPM **całej Account Group**, nie 150 niezależnych kont.
- **Brak automatycznej okresowej rotacji.** CPM pozostaje aktywny dla zmian na żądanie.
- Po awarii AD i CyberArk ma działać niezależne otwarcie zdeponowanego hasła, konsola fizyczna/hypervisor/OOB i lokalne logowanie.
- Z uwagi na systemy współdzielone przez produkty jeden lokalny login bguser może należeć tylko do **jednej domeny haseł**. W tym projekcie manifest wymusza unikatowy address. Jeśli host utrzymuje wiele produktów, wymagane jest przypisanie go do nadrzędnej domeny haseł, konsolidacja produktów pod jednym hasłem albo decyzja o odrębnych nazwach kont (wymaga zmiany wymogu bguser).

## 2. CyberArk: jak działa mieszana grupa

**Ważne:** Target Platform = sposób zarządzania hasłem na konkretnym systemie, a Group Platform = polityka hasła i synchronizacji całej grupy.

| Konto w BG-ERP-GRP | Target platform | Group platform | Hasło |
|---|---|---|---|
| win-erp01 / bguser | BG-Windows-Local | BG-Group-Manual | ERP-A |
| win-erp02 / bguser | BG-Windows-Local | BG-Group-Manual | ERP-A |
| rhel-erp01 / bguser | BG-RHEL-Local | BG-Group-Manual | ERP-A |
| rhel-erp02 / bguser | BG-RHEL-Local | BG-Group-Manual | ERP-A |

Account Groups wspierają konta mające różne target platforms i plug-iny. Każde konto musi należeć do tego **samego Safe**, jeśli znajduje się w jednej natywnej Account Group. Po udanej zmianie grupowej wszystkie konta mają wspólne hasło.

**Źródła:**
- Opis mechanizmu target/group platform: https://kb.wisc.edu/137974
- Przewodnik PAS, „Manage account groups”: https://studylib.net/doc/27516493/privileged-access-security-end-user-guide
- Ansible Windows win_user: https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_user_module.html
- Ansible RHEL user: https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/user_module.html

## 3. Wybrane mechanizmy bezpieczeństwa

### Osobne Safe per produkt

Każdy Safe ma odrębnych Ownerów, Operatorów Rotacji, EmergencyAccess i Auditorów. Jedna wspólna, zatwierdzona konfiguracja Group Platform (BG-Group-Manual) może obsługiwać więcej niż jeden produkt — **nazwy grup i Safes są jednak inne**.

Rola:
- Owner: zarządzanie Safe i uprawnieniami; nie do bieżącej pracy.
- RotationOperator: listAccounts, initiateCPMAccountManagementOperations, specifyNextAccountContent; bez RetrieveAccounts.
- EmergencyAccess: useAccounts, retrieveAccounts, listAccounts (w trybie online i zgodnie z zatwierdzeniem).
- Auditor: listAccounts i viewAuditLog.

Właściciele produktu nie muszą mieć praw do innych produktów. Nie kopiować do rzeczywistej konfiguracji przykładów właścicieli, grup AD lub adresów bez walidacji.

### Manualny CPM, nie Disabled

Docelowo secretManagement.automaticManagementEnabled=true. W platformie i Master Policy *wyłącz* automatyczne wyzwalacze Change/Onboard/Check-in i samoczynnego Reconcile/Change; **pozostaw** operację Change uruchamianą przez operatora. Ewentualny Verify nie powinien powodować automatycznej zmiany hasła po błędzie. Szczegóły zależą od wersji CyberArk — sprawdź na pilocie.

**Wspólne reguły hasła** muszą być zgodne z:
1. polityką lokalnych kont Windows (GPO, password filters/history),
2. PAM/Pwquality i historią haseł RHEL,
3. konfiguracją Group Platform,
4. pluginami CPM Windows i RHEL.

Przed wdrożeniem potwierdź rzeczywiste target platform IDs, group platform ID, AllowedSafes, monitoring CPM i dostępność odpowiednich kont reconcile. Nie używaj podanego przez operatora hasła w zgłoszeniu ITSM, zmiennej jawnej w repo lub command-line.

### Wspólne konto na wielu maszynach

Hasło produktu umożliwia przejście pomiędzy wszystkimi systemami tego produktu. Jest to **ryzyko lateral movement**. Wymagana akceptacja właściciela ryzyka oraz kompensacje: ograniczenie liczby hostów na produkt, szczególny alert na każde logowanie bguser, kontrolowane okno dostępu, dostęp konsolowy i segmentacja.

## 4. Inwentarz i sekret per produkt

Manifest CSV jest bez haseł. Każdy wiersz mapuje **jeden fizyczny host do jednego produktu**.

~~~csv
product,safeName,groupName,groupPlatformId,os,address,platformId
ERP,BG-ERP,BG-ERP-GRP,BG-Group-Manual,Windows,win-erp01.example.invalid,BG-Windows-Local
ERP,BG-ERP,BG-ERP-GRP,BG-Group-Manual,RHEL,rhel-erp01.example.invalid,BG-RHEL-Local
CRM,BG-CRM,BG-CRM-GRP,BG-Group-Manual,Windows,win-crm01.example.invalid,BG-Windows-Local
CRM,BG-CRM,BG-CRM-GRP,BG-Group-Manual,RHEL,rhel-crm01.example.invalid,BG-RHEL-Local
~~~

Dopuszczalne jest, że produkt ma np. 7 Windows i 2 RHEL — wszystkie 9 otrzymuje **jedno hasło ERP**. Ogólna liczba wszystkich produktów ma wynosić 150 Windows + 150 RHEL; **nie** oczekujemy 150+150 w jednym Safe.

Ansible pobiera z zaszyfrowanego źródła mapę **bg_passwords**, np.:

~~~yaml
bg_passwords:
  ERP: "<TAJNE_HASLO_PRODUKTU_ERP>"
  CRM: "<INNE_TAJNE_HASLO_PRODUKTU_CRM>"
~~~

Nie przechowuj tego YAML jawnie w repo. Nie zapisuj faktycznych haseł lub adresów produkcyjnych w publicznym GitHub. Nazwa produktu przypisana jest do hosta przez bg_product w inventory. **To samo hasło z jednego źródła** musi zostać podane przy dodawaniu kont Windows i RHEL produktu do CyberArk. Obecny wrapper pyta o SecureString raz na produkt: operator musi świadomie podać wartość identyczną jak w bezpiecznym magazynie użytym w Ansible; to zostanie zweryfikowane w pilocie. Integracja ze scentralizowanym backendem sekretów jest zalecana w wersji produkcyjnej.

## 5. Procedura wdrożenia

### 5.1. Przygotowanie

1. Uzgodnić listę produktów i mapę serwer -> produkt z zespołami aplikacyjnymi. Sprawdzić duplikaty hostów, aliasy DNS i hosty wieloproduktowe; wykluczyć domenowe kontrolery Windows (brak kont lokalnych).
2. Utworzyć dwa różne zestawy danych: niesekretny manifest oraz szyfrowaną mapę bg_passwords. Jedno silne hasło na produkt, nie na OS. Sprawdzić dopuszczalne znaki i polityki obu systemów.
3. Przeprowadzić pilot na dwóch serwerach (Windows+RHEL) tego samego produktu oraz, jeśli potrzebna jest demonstracja izolacji, po jednym serwerze drugiego produktu.
4. Utworzyć/przygotować Safe BG-<PRODUKT>, role Safe, grupy AD, target platforms BG-Windows-Local oraz BG-RHEL-Local, Group Platform BG-Group-Manual.
5. Wykonać przegląd MFA/Dual Control, lokalnego konta do odzyskiwania bez AD, konsol OOB, GPO/LAPS/PAM/SSSD/SELinux, logowania i reguł haseł.

### 5.2. Ansible provisioning

~~~bash
ansible-galaxy collection install -r BreakGlass/ansible/requirements.yml
umask 077
ansible-vault create /secure/bg-secrets.yml
# Zapisz w zaszyfrowanym Vault: bg_passwords: { ERP: '...', CRM: '...' }
ansible-playbook -i BreakGlass/ansible/inventory.ini BreakGlass/ansible/windows.yml --ask-vault-pass -e @/secure/bg-secrets.yml --limit win-erp01.example.invalid
ansible-playbook -i BreakGlass/ansible/inventory.ini BreakGlass/ansible/rhel.yml --ask-vault-pass -e @/secure/bg-secrets.yml --limit rhel-erp01.example.invalid
~~~

- Windows: win_user tworzy lokalnego bguser i przypisuje SID lokalnych Administrators, ale blokuje przejęcie zastanego, nieoznaczonego konta.
- RHEL: ansible.builtin.user + wheel + zwalidowane sudoers wymagające hasła; blokuje przejęcie zastanego, nieoznaczonego konta.
- **update_password: on_create** oznacza, że ponowny przebieg nie cofnie późniejszej zmiany dokonanej przez CPM.
- Uruchamiać z uprawnieniami admin/Become z dotychczasowego dostępu, nie jako bguser.
- Po wdrożeniu zweryfikować lokalny login przy awarii AD oraz uprawnienia administrator/root. Ansible zapisuje hash w RHEL, hasło jest to samo, mimo że lokalne hashe mogą się różnić przez sól.
- Zaszyfrowane pliki secrets, realny inventory i konfiguracja PVWA pozostają **poza repo**.

### 5.3. CyberArk onboarding — istniejące skrypty

Skrypt BreakGlass/Invoke-BreakGlassOnboarding.ps1:
1. Waliduje produkt->Safe->Account Group, spójność groupPlatformId, wymagane kolumny i unikatowość hostów.
2. Wymaga łącznej liczby Windows/RHEL: domyślnie 150/150, a pilot parametrami -ExpectedWindows/-ExpectedRHEL.
3. Pyta operatora o **jedno początkowe hasło per produkt** (SecureString).
4. Dla każdego wiersza wywołuje istniejący New-CyberArkLocalAccount.ps1 (i bazowy New-CyberArkSafeAccount.ps1) na **Safe danego produktu**.
5. Zapobiega automatycznemu Reconcile przez -SkipReconcile. Istniejących kont w CyberArk nie zmienia, włącznie z ich hasłem.
6. Domyślnie **nie** tworzy ani nie uzupełnia Account Groups.
7. Przy -AssignGroups odpytuje pełny inwentarz kont w każdym Safe, wylicza Account IDs i wywołuje poprawiony Add-CyberArkAccountsToGroup.ps1. Do każdej grupy dodaje **wszystkie systemy produktu**, niezależnie od OS, ale sprawdza dozwolone target platform IDs.

Przykład dla pilota 2 Windows + 2 RHEL w dwóch produktach (ERP, CRM):

~~~powershell
$opts = @{
 ManifestCsv='.\BreakGlass\manifest.csv'
 ConfigPath='.\BreakGlass\CyberArk-BreakGlassConfig.json'
 ExpectedWindows=2
 ExpectedRHEL=2
}
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts -WhatIf
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts
# Ręczna kontrola: konto bguser w obu OS i ich inicjalne hasło zgodne w obrębie produktu.
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts -AssignGroups
~~~

Skrypt bazowy uruchamia logowanie PVWA per host; w produkcji 300 sesji/operacji może działać długo. Optymalizacja batch/session reuse jest osobnym zadaniem. Co istotne, obecny kod NIE resetuje istniejących haseł, nawet gdy operator poda nowe — temu służy dopiero odrębna operacja CPM.

Zgodnie z wcześniejszym problemem API: różne wersje obsługują różne drogi pobierania Account Groups: GET /api/AccountGroups?Safe=... i GET /api/Safes/{Safe}/AccountGroups. Obecne Tools korzystają z pierwszego wariantu. Przed uruchomieniem potwierdzić działanie dokładnie w Waszej wersji CyberArk. Tworzenie grup w narzędziu korzysta z POST /api/AccountGroups/ z GroupName/GroupPlatformID/Safe.

### 5.4. Audyt struktury

~~~powershell
.\BreakGlass\Test-BreakGlassDeployment.ps1 -ManifestCsv .\BreakGlass\manifest.csv -PVWAURL https://pvwa.example.invalid/PasswordVault -AuthType Radius -ExpectedWindows 2 -ExpectedRHEL 2 -ReportCsv C:\Temp\bg-audit.csv
~~~

Walidacja rozdziela produkty, sprawdza jeden Safe/Group na produkt, unikatowość hostów, zgodność wpisów Windows/RHEL oraz liczebność Account Groups; nie pobiera haseł i nie dowodzi poprawności ich wartości lub działania lokalnego logowania.

## 6. Procedura ręcznej rotacji wspólnego hasła produktu

**Wymóg krytyczny:** przed produkcją potwierdzić w Waszej wersji UI/CPM, że operator może **Specify Next Password + Change entire Account Group**, a pluginy Windows i Unix w tej samej grupie dostają tę samą wartość. Nie uznawać samego REST SetNextPassword dla pojedynczego konta za dowód grupowej propagacji.

1. Utworzyć Change/Incident i zatwierdzić produkt, Safe, grupę, listę hostów, uczestników i okno zmiany.
2. Odczytać aktualną listę wszystkich członków grupy (Windows i RHEL); liczba musi dokładnie pasować do CMDB/manifestu. Potwierdzić działanie CPM i kont reconciliation.
3. Uprawniony operator przygotowuje **jedno nowe hasło produktu**, zgodne z polityką Windows+RHEL. Nigdy nie wysyła go w treści ticketu/mailu/logu.
4. Przygotować zabezpieczoną wersję nowego sekretu do depozytu offline jako **kandydat**; zachować dostępność aktualnie działającego hasła do końca pełnej weryfikacji.
5. W PVWA wybrać Account Group danego produktu, opcję określenia next password i ręcznego uruchomienia **Change całej grupy**. Przed zatwierdzeniem niezależna osoba sprawdza Safe/grupę/liczbę hostów.
6. Monitorować CPM. Sukces żądania w UI/API to tylko przyjęcie zadania. Sprawdzić wynik na wszystkich hostach i status Verify; przy krytycznych systemach przetestować również rzeczywisty login OOB.
7. Po potwierdzeniu 100% sukcesu potwierdzić wersję hasła w dwóch depozytach offline, zamknąć change i udokumentować wynik, bez samego hasła.
8. W przypadku niepowodzenia na części hostów — produkt w stanie **SPLIT PASSWORD**. Zabezpieczyć obie wersje, zidentyfikować faktyczny stan każdego hosta, eskalować. Nie wykonywać niekontrolowanego re-Change ani nie unieważniać działającego starego hasła.

Nie stosować automatycznego scheduler-a, auto-rotate on add, change after retrieve/check-in ani automatycznego Reconcile prowadzącego do zmiany bez decyzji operatora.

## 7. Awaria AD i CyberArk — offline

1. Incident Commander uruchamia proces awaryjny; wskazuje produkt i serwery, a nie system operacyjny.
2. Dwie niezależne uprawnione osoby autoryzują otwarcie **depozytu produktu** (nie globalnego hasła wszystkich produktów).
3. Z dwóch niezależnie przechowywanych kopii, z ewidencją otwarcia, wybierane jest aktualne hasło z właściwym numerem wersji. Szczegóły lokalizacji/odzyskiwania nie są w repo.
4. Administrator loguje się z konsoli fizycznej/OOB (Windows: HOST\bguser / .\bguser; RHEL: lokalny bguser + sudo -i) z **tym samym hasłem produktu**.
5. Dostęp musi działać bez AD, DNS, PVWA, CPM, PSM, Vault i sieci produkcyjnej; testować na prawdziwej konsoli, a nie tylko SSH/WinRM.
6. Prowadzić papierowy/niezależny rejestr operacji, a po przywróceniu centralnych systemów zebrać logi, zrekoncyliować i wykonać ręczną rotację **użytej Account Group produktu**. Zaktualizować depozyty dopiero po pełnym sukcesie.

## 8. Testy akceptacyjne (GO / NO-GO)

- T01: Jeden produkt, co najmniej jeden Windows + jeden RHEL w **jednej** Account Group.
- T02: Te dwa serwery mają identyczny bguser password; inny produkt ma inne hasło.
- T03: Re-run Ansible nie cofa hasła po zmianie CPM.
- T04: Re-run importu CyberArk nie nadpisuje haseł ani nie duplikuje kont.
- T05: CPM ręcznie używa hasła wybranego przez operatora na Windows i RHEL, w tej samej grupie, bez przypadkowej rotacji innych produktów.
- T06: Brak automatycznego Change i Reconcile po upływie interwału i po pobraniu.
- T07: Jedna maszyna offline podczas rotacji: alert split state, poprawna procedura wyjścia z awarii.
- T08: Logowanie admin/root w realnej awarii AD i CyberArk przez OOB.
- T09: Odczyt hasła online wymaga odpowiedniej roli / approval, operator rotacji nie ma automatycznie Retrieve.
- T10: Każda Account Group zawiera tylko hosty jednego produktu, lecz dowolną mieszankę Windows i RHEL.
- T11: Host występujący w dwóch produktach zostaje wychwycony i zatrzymany przez walidację.
- T12: Pełen inventory 150 Windows + 150 RHEL i per-product liczba kont zgadza się z CMDB.
- T13: Depozyt offline po rotacji działa i ma udokumentowaną wersję; dwie kopie są zgodne.

**NO-GO:** nieznana lub nieprzetestowana semantyka Group Change, split state bez procedury, brak offline escrow, brak OOB, niezaakceptowane ryzyko współdzielonych haseł, brak walidacji rzeczywistych platform ID.

## 9. Utrzymanie i ryzyka

- Kwartalny przegląd przynależności produktu, właścicieli Safe, konta i depozytu.
- Ćwiczenie offline minimum co 6 miesięcy, w szczególności z odłączonymi AD/PAM.
- Każde nieplanowane logowanie bguser do SIEM jako alert wysokiej ważności.
- Rotacja po użyciu awaryjnym lub podejrzeniu ujawnienia, mimo ogólnej zasady „bez zmian cyklicznych”.
- Formalna akceptacja ryzyka lateral movement w obrębie jednego produktu — liczba serwerów jednego produktu jest promieniem rażenia ujawnionego hasła.
- Repo pcmkr/Tools obecnie PUBLICZNE. Faktyczne parametry, sekrety, produkcyjny inventory i szczegóły escrow muszą pozostać poza nim.

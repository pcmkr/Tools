# Break-Glass: architektura i procedura wdrożenia (Windows Server / RHEL)

Wersja projektu: 0.1 / do pilotażu. Data: 2026-10-09. Status: **NIE WPROWADZAĆ NA PRODUKCJĘ bez testów odbiorowych**.

## 1. Zakres i decyzje

- 150 serwerów Windows Server (wyłącznie serwery członkowskie) i 150 Red Hat Enterprise Linux.
- Każdy serwer: dedykowane lokalne konto administracyjne bguser (nie konto domenowe).
- Jeden logiczny zasób/sejf np. BG-PROD-01 obejmujący tę grupę serwerów; w nim **dwie** natywne Account Groups:
  - BG-PROD-WIN: 150 kont; jedno wspólne hasło A.
  - BG-PROD-RHEL: 150 kont; jedno wspólne hasło B.
- Hasło A i B muszą być różne. Właściwa (target) platforma konta pozostaje zależna od systemu (Windows/RHEL); każda Account Group ma osobną *group platform*, która reguluje synchronizację i politykę rotacji.
- CPM realizuje zmianę hasła dopiero po **świadomej operacji operatora**, z wartością hasła podaną przez uprawnioną osobę.
- Zabezpieczenie offline działa **bez AD, PVWA, CPM, Vault, PSM, DNS i sieci produkcyjnej** — przewidzieć konsolę out-of-band oraz depozyt odzyskiwania aktualnego hasła.
- Ujednolicone hasło na 150 hostach jest wyjątkiem bezpieczeństwa: kompromitacja jednego hasła potencjalnie kompromituje 150 hostów. Akceptacja ryzyka i kompensujące kontrole są obowiązkowe.

UWAGA: One CyberArk Account Group cannot hold *different* active passwords for member accounts and still provide synchronized group rotation. One logical service != one native Account Group.

## 2. Elementy rozwiązania

1. Ansible Controller / Automation Platform: provisioning kont, bez rotowania ich haseł przy kolejnych uruchomieniach.
2. CyberArk PAS / PVWA: Safe, konta, uprawnienia, natywne grupy.
3. CPM: zarządza hasłami i wykonuje zmianę na systemach docelowych; brak zadań okresowych wymuszających zmianę.
4. Oddzielne tożsamości i uprawnienia: operator rotacji / administrator Safe / osoba do dostępu awaryjnego / audytor.
5. Depozyt offline aktualnych haseł: dwie niezależnie zabezpieczone kopie, podwójna kontrola, dostępne bez infrastruktury produkcyjnej.
6. Audit / SIEM: zdarzenia PAM, Windows Security Events (np. 4624/4625/4720/4732/4723/4724), Linux auditd, authpriv/journald; testować źródła i retencję.

### Zależności, które wymagają uzgodnienia z administratorem PAM

- Wersja CyberArk Self-Hosted PAM/Privilege Cloud, typ CPM oraz obsługiwany wariant UI.
- Dokładne platformId dla Windows lokalnych i RHEL oraz groupPlatformId dla obu kohort.
- Obowiązująca Master Policy i wyjątki, harmonogramy CPM, AllowedSafes, właściwości „Change”, „Verify”, „Reconcile”.
- Uprawnienia i polityki platform dotyczące zmiany *wskazanego* hasła dla całej Account Group. Nie zakładać, że samo SetNextPassword API propaguje nowe hasło do całej grupy bez testu.
- Uprawnienia kont technicznych CPM umożliwiające zmianę lokalnych haseł na obu systemach.
- Dostępność konta bguser w scenariuszu braku AD, PAM i sieci, łącznie z dostępem fizycznym / hypervisor / OOB.
- Polityki lokalne: Windows LAPS lub inny mechanizm nie może zarządzać kontem bguser; brak blokady/wygaśnięcia hasła, uwzględnić polityki GPO i PAM/SSSD.
- Połączenia WinRM/SSH w czasie początkowego wdrożenia używają istniejących kont administracyjnych, nie konta bguser.

## 3. Konfiguracja platform CyberArk

Wykonać w środowisku testowym: zduplikować i skonfigurować target platforms BG-Windows-Local / BG-RHEL-Local oraz group platforms BG-Win-Group / BG-RHEL-Group. Nazwy są przykładami, nie istniejącymi u użytkownika identyfikatorami.

Wymagania:
- Dla każdego konta secretManagement.automaticManagementEnabled = true, tak by **CPM nadal mógł obsłużyć żądanie operatora**. FALSE może wyłączyć zarządzanie kontem zamiast wyłączyć tylko scheduler.
- W platformach i Master Policy wyłączyć działania, które bez intencji operatora zmieniają hasło: PerformPeriodicChange=No, AutoChangeOnAdd=No; sprawdzić i wyłączyć odpowiednie reguły zmiany po użyciu/check-in, po terminie żądania, automatycznego reconcile i resetu niezsynchronizowanych haseł.
- Pozostawić AllowManualChange / ręczny Change dostępny; zależnie od wersji konfigurację potwierdzić w UI i audycie CPM.
- Automatyczna weryfikacja (Verify) nie musi zmieniać hasła, ale jeśli może powodować automatyczny Reconcile/Change na błędzie — wyłączyć ścieżkę automatycznej naprawy.
- Ustalić politykę nowego hasła jako **część wspólną** wymagań Windows, RHEL/PAM i group platform: długość, złożoność, historia haseł, znaki specjalne akceptowane przez wszystkie systemy.
- Przy zmianie używać grupy, a nie 150 niezależnych „Change” — brak atomowości, lecz proces powinien propagować identyczną wartość.
- Nie włączać AutoChangeOnAdd, dopóki początkowe hasła nie zostaną spójnie zdeponowane w PAM i offline.
- Oddzielić konto do **reconcile** od bguser. Nie wykorzystywać go w procedurze zwykłej rotacji bez uzasadnienia i osobnej akceptacji.

## 4. Uprawnienia do sejfu (RBAC)

| Rola | Zadania | Uprawnienia Safe (skrót) |
|---|---|---|
| Owner | Konfiguracja i członkostwo Safe | ManageSafe, ManageSafeMembers, AddAccounts, UpdateAccountProperties, Audit |
| RotationOperator | Wskazanie nowego hasła, ręczne zlecenie CPM | ListAccounts, InitiateCPMAccountManagementOperations, SpecifyNextAccountContent |
| EmergencyAccess | Odczyt haseł w kontrolowanym trybie online | ListAccounts, UseAccounts, RetrieveAccounts |
| Auditor | Przegląd audytu | ListAccounts, ViewAuditLog |

- Nie przekazywać niepotrzebnych uprawnień RetrieveAccounts operatorowi rotacji.
- Przy potrzebie kontroli czterech oczu rozdzielić akceptującego i wykonującego; w PVWA skonfigurować Dual Control dla retrieval, z procedurą offline, która **nie zależy od AD**.
- Lokalna grupa Vault Admins to *przykład* awaryjnej administracji Safe, nie domyślnie nieograniczony dostęp. Dopasować do istniejących praktyk.
- Zapewnić działające (przetestowane) konto/narzędzie odzyskiwania Vault dla awarii AD, ale pełna awaria CyberArk wymaga niezależnego depozytu offline.

## 5. Utworzenie bguser na serwerach

### 5.1. Wymagania wstępne

1. Zatwierdzić zakres serwerów, wykluczyć kontrolery domeny (nie mają lokalnej bazy SAM).
2. Wybrać pilot: 2 Windows + 2 RHEL, następnie 10+10, potem pozostałe w partiach (np. 10–20).
3. Utworzyć **dwa** losowe, silne i różne hasła startowe; przechować w zatwierdzonym backendzie tajemnic lub zaszyfrowanym Ansible Vault (nie w repo ani CI logach).
4. Zapewnić, że Windows nie wymusza rotacji konta lokalnego przy logowaniu, a RHEL nie wygasza hasła lub konta. Wyjątki od hardeningu zatwierdzić pisemnie.
5. W Windows sprawdzić narzędzie UAC / local account token filtering dla trybu użycia. Preferowany dostęp konsolowy; nie rozluźniać filtracji UAC tylko aby działał zdalny dostęp.
6. W RHEL sprawdzić /etc/pam.d/su, /etc/pam.d/sshd, sudoers, faillock i SELinux. Sama obecność konta w /etc/passwd nie dowodzi, że dostanie się przez konsolę w awarii AD.
7. Na stacjach zarządzających zapewnić WinRM HTTPS z walidacją certyfikatu lub Kerberos oraz SSH/Become z dotychczasowymi poświadczeniami.

### 5.2. Ansible

Pliki:
- ansible/windows.yml: ansible.windows.win_user, członkostwo w lokalnej Administrators (SID S-1-5-32-544), brak automatycznej zmiany hasła po utworzeniu.
- ansible/rhel.yml: ansible.builtin.user, wheel, /etc/sudoers.d/90-bguser z walidacją visudo; sudo wymaga hasła bguser.

**Istotne:** opcja update_password: on_create zabezpiecza przed przywróceniem starego hasła z Ansible Vault po późniejszej rotacji w CyberArk. Nie należy ustawiać update_password: always dla tych kont. Dla kont już istniejących playbook nie ustawia hasła — zweryfikować je osobno.

Sekret w bezpiecznej lokalizacji kontrolera, poza checkoutem Git:

~~~bash
ansible-galaxy collection install -r BreakGlass/ansible/requirements.yml
umask 077
ansible-vault create /secure/bg-secrets.yml
~~~

W zaszyfrowanym pliku:
~~~yaml
bg_windows_password: "<WYGNEROWANE_HASLO_A>"
bg_rhel_password: "<WYGNEROWANE_HASLO_B>"
~~~

Test i wykonanie (na wybranym pilocie z inventory):
~~~bash
ansible-playbook -i BreakGlass/ansible/inventory.ini BreakGlass/ansible/windows.yml --ask-vault-pass -e @/secure/bg-secrets.yml --limit win-test01.example.invalid
ansible-playbook -i BreakGlass/ansible/inventory.ini BreakGlass/ansible/rhel.yml --ask-vault-pass -e @/secure/bg-secrets.yml --limit rhel-test01.example.invalid
~~~

Przed całą falą pilot musi potwierdzić logowanie lokalne z wyłączonym AD i siecią produkcyjną, uzyskanie uprawnień admin/root przez sudo, sposób bezpiecznego odzyskiwania oraz odporność na ponowne uruchomienie playbooka.

Ważne: Ansible no_log ukrywa treść parametrów w zwykłych logach, lecz administrator kontrolera / backendu sekretów może nadal mieć dostęp do materiału w czasie wykonania. Nie używać verbose debug w środowisku produkcyjnym.

## 6. Import kont do CyberArk (wykorzystanie Tools)

Kolejność:
1. Wypełnić kopię CyberArk-BreakGlassConfig.example.json bez sekretów. Sprawdzić managingCPM, rzeczywiste platform IDs, authType, safeMembers.
2. Upewnić się, że AD groups np. BG-PROD-01_owner, BG-PROD-01_rotation, BG-PROD-01_emergency, BG-PROD-01_auditor istnieją i są zgodne z searchIn. Ze względu na konfigurację wrappera lookup jest wykonywany przy każdym wywołaniu.
3. Przygotować CSV manifest z kolumnami os,address,platformId. Adres unikatowy, Windows i RHEL z odpowiednimi target platform IDs; nigdy nie dodawać haseł do CSV.
4. Uruchomić skrypt Invoke-BreakGlassOnboarding.ps1, który kolejno wywołuje istniejący New-CyberArkLocalAccount.ps1 / New-CyberArkSafeAccount.ps1.
5. W wrapperze zawsze SkipReconcile; domyślnie **bez** AddToAccountGroup.
6. Zweryfikować wszystkie konta i ich przypisane target platformy w PVWA. Uwaga: jeśli konto już istnieje, skrypt bazowy nie aktualizuje jego sekretu.
7. Po pilotażu ponowić z -AssignGroups: skrypt zbierze ID kont w Safe, sprawdzi parę address+userName+platformId i wywoła istniejący Add-CyberArkAccountsToGroup.ps1 **oddzielnie dla każdego OS**.
8. Po dodaniu konto powinno mieć jedną docelową platformę i jedną zgodną Account Group. Zliczyć: Windows 150/150, RHEL 150/150, brak duplikatów i kont spoza manifestu.
9. Sprawdzić, że początkowe hasła działają na wszystkich hostach, ale nie wykonywać natychmiastowej rotacji bez gotowego depozytu offline.

Przykładowy przebieg pilota 2 + 2:

~~~powershell
$base = '.\BreakGlass'
$common = @{
  ManifestCsv = "$base\manifest.csv"
  SafeName = 'BG-PROD-01'
  ConfigPath = "$base\CyberArk-BreakGlassConfig.json"
  ExpectedWindows = 2
  ExpectedRHEL = 2
}
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @common -WhatIf
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @common
# Sprawdzenie w CyberArk: 4 konta, OS i hasła zgodne.
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @common -AssignGroups -WindowsGroupName BG-PROD-WIN -RhelGroupName BG-PROD-RHEL -WindowsGroupPlatformId BG-Win-Group -RhelGroupPlatformId BG-RHEL-Group
~~~

Po zatwierdzonym pilocie przełączyć ExpectedWindows=150, ExpectedRHEL=150 i zmienić manifest na pełny. Nie uruchamiać 300 zmian w jednym maintenance window bez ograniczenia współbieżności CPM i planu wycofania.

Skrypt zachowuje mechanizm idempotencji dotychczasowych narzędzi, ale używa oddzielnej sesji PVWA dla każdego hosta; dla 300 kont będzie wolniejszy. **Nie jest to hurtowy atomowy import**. Ponowne uruchomienie po naprawie błędów nie może powodować zmiany istniejących haseł.

## 7. Ręczna rotacja hasła — procedura produkcyjna (PVWA)

**Warunek:** wynik pilota musi potwierdzić zachowanie *konkretnej wersji* PVWA/CPM dla operacji „specify new password + change entire group”. Na poziomie publicznego REST API POST /api/Accounts/{id}/SetNextPassword obsługuje „NewCredentials” i „ChangeImmediately”, natomiast nie udowodniono na tej podstawie niezawodnej propagacji do całej grupy. Nie uruchamiać 150 osobnych żądań SetNextPassword jako obejścia bez zaakceptowanego projektu i testów.

Przebieg:
1. Operator otwiera zgłoszenie zmiany (ID, uzasadnienie, zakres, data, osoba zatwierdzająca, plan komunikacji).
2. Identyfikuje właściwą kohortę (Windows **albo** RHEL). Pobiera aktualną listę 150 członków; blokuje operację, jeśli brak członka, konto jest w innej grupie, brakuje łączności lub CPM jest w stanie błędu.
3. W bezpiecznym generatorze / kontrolowanym formularzu wprowadza nowe hasło (nie wpisuje go w ticket lub shell history). Sprawdza zgodność z wymaganiami obu systemów i group platform.
4. Zanim wykona rotację, przygotowuje nowy, zapieczętowany depozyt offline jako **kandydat** z identyfikatorem zmiany; dotychczasowe działające hasło pozostaje dostępne przez cały okres przejściowy. Nie dezaktywować starego depozytu.
5. W PVWA na koncie członkowskim otwiera Manage > Change; wybiera **Specify the password for the next CPM change**, wprowadza hasło i wybiera operację **dla całej Account Group**, nie dla pojedynczego konta. Włącza immediate change by CPM. Nazwy pól w UI mogą się różnić między wersjami.
6. Jeszcze przed zatwierdzeniem drugi operator sprawdza tożsamość grupy i liczność. Zapisuje tylko identyfikator zmiany, nazwę grupy, godzinę i operatora (bez hasła).
7. Uruchamia operację i monitoruje CPM aż do zakończenia **każdego** konta. Każdy wynik = Changed + Verified; sukces API „202/200” lub komunikat o zaplanowaniu zadania NIE jest dowodem zmiany hasła na serwerze.
8. Sprawdza działanie hasła na kontrolowanej próbce systemów, w tym przez konsolę OOB, a następnie weryfikuje wyniki dla całej grupy w PAM; przy wysokiej krytyczności wymaga 100% weryfikacji serwerów.
9. Po 100% sukcesu aktualizuje obie niezależne kopie depozytu, zatwierdza nową wersję i protokolarnie unieważnia starą. Potwierdza synchronizację identyfikatorów wersji.
10. W przypadku częściowej porażki oznacza kohortę jako **stan niejednorodny**. Nie publikować nowego hasła jako jedynego aktualnego, nie anulować starych depozytów, nie wykonywać ślepo kolejnego ChangeEntireGroup. Incydent/change bridge, dokładny per-host reconciliation, ponowna weryfikacja.

Wycofanie: gdy rotacja nie udała się na części serwerów, ustalić faktyczny stan każdego z nich. Przywrócenie jednolitego hasła (starego lub nowego) jest osobną operacją z nadzorem; nie wolno zakładać atomowego rollbacku.

## 8. Obsługa incydentu: awaria AD i CyberArk

**CyberArk i AD są niedostępne, więc nie można zakładać dostępu do PVWA/PSM/CPM ani zależności od MFA online.**

1. Incident Commander stwierdza kryterium „Break-Glass” (utrata dostępu administracyjnego lub poważna awaria systemów tożsamości/PAM).
2. Osoba uprawniona przedstawia identyfikator incydentu, cel, wykaz serwerów oraz wymagany zakres.
3. Dwóch niezależnych kustoszy uruchamia procedurę offline: kontrola tożsamości alternatywną metodą, wpis w papierowym lub niezależnym rejestrze, otwarcie depozytu właściwej kohorty. Nie ujawniać hasła poza kontrolowanym kanałem; nie przesyłać SMS, e-mail lub komunikatorami.
4. Odczytać etykietę: environment, cohort, secret version, seal ID, date of last successful rotation. **Nie** trzymać mapy adresów + hasła w jednym niekontrolowanym miejscu.
5. Dostęp Windows: konsola fizyczna/hypervisor/OOB, login HOSTNAME\bguser lub .\bguser, hasło A. Przetestować działania niezależnie od AD/DNS.
6. Dostęp RHEL: konsola/hypervisor/OOB, lokalne logowanie bguser, sudo -i po podaniu własnego hasła, hasło B. Przy braku sieci dopuszczalność loginu wynika z lokalnych PAM/SELinux/sudoers — musi być przetestowana.
7. Rejestrować kto, kiedy, do jakiej kohorty i po co uzyskał dostęp. Jeśli centralny SIEM nie działa, gromadzić lokalne dowody i później dostarczyć w sposób odporny na manipulację.
8. Po odzyskaniu AD/CyberArk: dokonać przeglądu działań, wykryć wszelkie odstępstwa, przeprowadzić **świadomą rotację obu lub użytych kohort**, ponownie przetestować dostęp i zaktualizować depozyty.
9. Jeśli jedna z kopii offline różni się wersją lub kompromitacja jest podejrzana: nie używać w ciemno; Incident Commander wybiera skontrolowaną drogę odzyskiwania i synchronizacji.

Depozyt offline: dwa niezależne zaszyfrowane nośniki lub papierowe koperty w dwóch odseparowanych bezpiecznych lokalizacjach, unikatowy identyfikator, plomby, ewidencja dostępu, dwóch kustoszy, kwartalny przegląd dostępności. Nie umieszczać haseł lub szczegółów ich odzyskiwania w repo.

## 9. Testy odbiorowe (warunek przejścia na produkcję)

- T01: Ansible tworzy bguser na 2 Windows i 2 RHEL; logowanie lokalne działa przy wyłączonym AD, DNS i PVWA.
- T02: Windows jest w lokalnej Administrators; RHEL uzyskuje root przez sudo z hasłem, bez NOPASSWD.
- T03: Ponowny playbook nie odtwarza starego hasła po zmianie CPM.
- T04: Wszystkie konta są w jednym poprawnym Safe, rozdzielone na 2 Account Groups, bez cross-OS membership.
- T05: Brak samoczynnej rotacji po upływie policyjnego interwału (test w oknie dłuższym niż najmniejszy aktywny harmonogram), po pobraniu i check-in.
- T06: Operator wskazuje własną wartość i wykonuje ChangeEntireGroup tylko dla pilota 2 Windows; oba serwery mają nowe IDENTYCZNE hasło; RHEL pozostaje bez zmian.
- T07: Analogiczny test RHEL.
- T08: Negatywne: jedna maszyna offline w czasie rotacji; proces pokazuje brak 100% i nie oznacza go jako sukces.
- T09: Rotacja nie powoduje ponownego automatycznego Change po błędzie Verify/CheckIn.
- T10: End-to-end bez AD i CyberArk, z depozytem offline, dual custody, OOB, audytem papierowym i rekonsyliacją po awarii.
- T11: Uprawnienia — osoba wyłącznie z rolą RotationOperator nie może odczytać hasła, EmergencyAccess nie zmienia polityki/grup.
- T12: Weryfikacja kont w CyberArk odpowiada stanowi faktycznemu, każda grupa 150/150 po pełnym wdrożeniu.

Kryterium GO: wszystkie testy przeszły, każda kohorta w spójnym stanie, podpisane zaakceptowanie ryzyka wspólnych haseł. NO-GO: niezgodność API/CPM, stale depozyty, niepełny spis hostów, brak OOB, nieskuteczne logowanie bez AD.

## 10. Referencje

- CyberArk Account Groups (grupy współdzielą hasło): https://kb.wisc.edu/137974
- CyberArk end-user manual: https://studylib.net/doc/27516493/privileged-access-security-end-user-guide
- CyberArk account actions / set next password: https://github.com/cyberark/epv-api-scripts/tree/main/Account%20Actions%20Utility
- psPAS CPM operation: https://pspas.pspete.dev/commands/Invoke-PASCPMOperation
- Ansible Windows: https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_user_module.html
- Ansible Linux: https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/user_module.html

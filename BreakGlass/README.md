# Break-Glass — model per PRODUKT (Windows Server + RHEL / CyberArk PAM)

**Stan:** DRAFT / pilot obowiązkowy. Repozytorium pcmkr/Tools jest obecnie PUBLICZNE.

## Zakres

- 150 Windows Server + 150 RHEL, lokalny użytkownik bguser z uprawnieniami administracyjnymi.
- **Safe per produkt, jedna natywna Account Group per produkt**: w jednym Safe i grupie współistnieją konta bguser z Windows i RHEL.
- **Jedno wspólne hasło na wszystkie serwery produktu**, niezależnie od OS. **Osobne hasło dla innych produktów.**
- Uprawniony operator podaje nowe hasło produktu, świadomie inicjuje Change entire Account Group przez CPM; brak automatycznej rotacji.
- Dostęp awaryjny offline bez AD/CyberArk wymaga niezależnego depozytu i lokalnych konsol OOB.
- Jeśli host obsługuje wiele produktów, jeden lokalny bguser nie może mieć równocześnie kilku haseł. Manifest blokuje ponowne przypisanie tego samego adresu hosta. Rozwiązać konflikt CMDB przed wdrożeniem.

## Pliki

| Plik | Zastosowanie |
|---|---|
| TECHNICAL.md | Pełna architektura, instrukcja implementacji, rotacji, awarii, testów |
| MANAGEMENT.md | Opis dla managementu, ryzyka i decyzje |
| ansible/windows.yml | Tworzenie lokalnego Windows bguser; hasło per produkt |
| ansible/rhel.yml | Tworzenie lokalnego RHEL bguser, wheel + sudo; hasło per produkt |
| ansible/inventory.example.ini | Przykład powiązania hostów z bg_product |
| ansible/requirements.yml | Zależności Ansible |
| manifest.example.csv | product,safeName,groupName,groupPlatformId,os,address,platformId |
| CyberArk-BreakGlassConfig.example.json | Wzorcowy Safe i RBAC, manualny CPM; wpisy przykładowe |
| Invoke-BreakGlassOnboarding.ps1 | Import istniejącymi skryptami, hasło SecureString per produkt, opcjonalne grupy |
| Test-BreakGlassDeployment.ps1 | Audyt struktury i członkostwa bez ujawniania sekretów |

## Kolejność

1. Zatwierdź produkty, Safe / Account Groups i mapę host → produkt; rozwiąż serwery współdzielone przez wiele produktów.
2. Uzgodnij realne platform IDs, Group Platform ID, konfigurację CPM/Master Policy (manual Change bez automatycznego Change, Reconcile ani Check-In rotate) oraz dostęp offline.
3. Zapisz **jedno losowe hasło per produkt** w zatwierdzonym backendzie. Dla Ansible wykorzystaj szyfrowany YAML z mapą bg_passwords, np. ERP/CRM. Nie przechowuj sekretów jawnie w Git.
4. Uzupełnij inventory z bg_product przy każdym hoście i manifest z rzeczywistymi Safe i Group.
5. Zainstaluj kolekcje i uruchom Ansible dla pilotowych Windows i RHEL, następnie zweryfikuj lokalne logowanie / sudo bez AD.
6. Uruchom skrypt onboardingu bez -AssignGroups, potem zweryfikuj konta i dopiero -AssignGroups.
7. Uruchom read-only audyt. Następnie na **tej samej** Account Group zawierającej Windows i RHEL przetestuj podanie nowego hasła i ręczne Change entire Group.
8. Przetestuj częściową awarię rotacji, procedurę SPLIT PASSWORD, a także awarię AD/PAM i dostęp OOB z depozytu offline.
9. Przejdź do pełnego wdrożenia 300 hostów dopiero po odbiorze testów.

### Przykład pilota z manifestem 2 Windows + 2 RHEL / dwa produkty

W zabezpieczonym Ansible Vault, *poza Git*:

~~~yaml
bg_passwords:
  ERP: "<HASLO_ERP>"
  CRM: "<HASLO_CRM>"
~~~

~~~bash
ansible-galaxy collection install -r BreakGlass/ansible/requirements.yml
ansible-playbook -i BreakGlass/ansible/inventory.ini BreakGlass/ansible/windows.yml --ask-vault-pass -e @/secure/bg-secrets.yml
ansible-playbook -i BreakGlass/ansible/inventory.ini BreakGlass/ansible/rhel.yml --ask-vault-pass -e @/secure/bg-secrets.yml
~~~

W PowerShell 5.1+ (z katalogu głównego Tools):

~~~powershell
$opts = @{
  ManifestCsv='.\BreakGlass\manifest.csv'
  ConfigPath='.\BreakGlass\CyberArk-BreakGlassConfig.json'
  ExpectedWindows=2
  ExpectedRHEL=2
}
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts -WhatIf
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts
# Sprawdź konta; dopiero potem przypisz wszystkie konta produktu do tej samej grupy.
.\BreakGlass\Invoke-BreakGlassOnboarding.ps1 @opts -AssignGroups

.\BreakGlass\Test-BreakGlassDeployment.ps1 -ManifestCsv .\BreakGlass\manifest.csv -PVWAURL https://pvwa.example.invalid/PasswordVault -AuthType Radius -ExpectedWindows 2 -ExpectedRHEL 2 -ReportCsv C:\Temp\bg-report.csv
~~~

**Uwaga:** skrypt onboardingowy pyta raz o początkowe hasło każdego produktu, które operator musi przepisać ze źródła użytego w Ansible. Nie przechowuje sekretów w CSV. Domyślnie nie dodaje do Account Group i nie uruchamia Reconcile. Wykorzystuje istniejące skrypty Tools dla Safe/Account/Account Group. Nie wykonuje rotacji; operacja Change entire Account Group pozostaje **procedurą PVWA do przetestowania** przed automatyzacją.

## Status i granice

Kod po przeglądzie logicznym, NIE uruchamiany na produkcyjnym CyberArk/Ansible. Należy zweryfikować wersję API dla Account Groups, faktyczne platform IDs, uprawnienia operatora, zachowanie ręcznego „specified next password + group-wide Change”, synchronizację oraz rozbieżności w razie awarii hosta.

Audit weryfikuje obecność i członkostwo, **nie potwierdza**, że fizyczne hosty mają to samo hasło ani że rzeczywiste logowanie działa bez AD.

Nie umieszczaj produkcyjnych hostów, sekretów, tokenów, kluczy ani lokalizacji depozytów offline w tym publicznym repozytorium. Przed produkcją zalecany prywatny projekt z kontrolą dostępu.

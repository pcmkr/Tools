# Break-Glass – materiał dla kierownictwa i właścicieli ryzyka

**Temat:** zapewnienie administracyjnego dostępu awaryjnego do 300 serwerów (150 Windows Server, 150 Red Hat Enterprise Linux) w razie awarii systemów centralnego uwierzytelniania i CyberArk PAM.

**Decyzja projektowa:** lokalne konto bguser na każdym serwerze; hasło przechowywane i kontrolowane w CyberArk; odrębne, wspólne hasło w obrębie dwóch grup: Windows i Linux. Hasła nie są rotowane samoczynnie, lecz zmieniane na żądanie uprawnionego operatora, za pośrednictwem CyberArk CPM.

## 1. Dlaczego projekt jest potrzebny

Nawet sprawne rozwiązanie PAM może nie umożliwić działania, jeśli jednocześnie niedostępne są AD, sieć, serwery PAM lub mechanizmy uwierzytelnienia. Break-Glass zapewnia kontrolowaną, niezależną ścieżkę uzyskania uprawnień administratora niezbędnych do naprawy infrastruktury.

Projekt minimalizuje zależność od pojedynczego dostawcy lub systemu, ale **nie eliminuje ryzyka operacyjnego**. Procedura offline to rozwiązanie ostatniej szansy, nie codzienna metoda pracy.

## 2. Jak to będzie działać

| Sytuacja | Sposób postępowania |
|---|---|
| Systemy pracują normalnie | Hasła są kontrolowane przez CyberArk, dostęp podlega autoryzacji i audytowi |
| Planowana ręczna rotacja | Operator podaje nowe hasło; CPM zmienia je na wszystkich członkach właściwej grupy; wynik jest weryfikowany |
| Awaria AD, CyberArk jest dostępny | Wykorzystywane są niezależne uprawnienia PAM zgodnie z zatwierdzoną procedurą |
| Awaria zarówno AD, jak i CyberArk | Dwóch uprawnionych kustoszy otwiera niezależny depozyt aktualnego hasła, administrator loguje się lokalnie przez konsolę OOB |
| Po zakończeniu awarii | Przegląd zdarzeń, rozliczenie dostępu, ręczna rotacja użytych haseł, aktualizacja depozytu |

## 3. Ryzyka i zabezpieczenia

### Największe ryzyko: wspólne hasło na 150 serwerach

Wymóg jednego hasła dla całej kohorty upraszcza dostęp awaryjny, lecz radykalnie zwiększa skutki ujawnienia hasła z pojedynczego hosta. Uzyskanie jednego hasła może umożliwić atak na 150 maszyn.

Zalecane zabezpieczenia:
- Dwa oddzielne hasła Windows i Linux; nie wolno tworzyć jednej wspólnej natywnej Account Group, jeśli mają pozostać różne.
- Wyjątkowy dostęp i silne kontrole tożsamości operatorów oraz uprawnienia minimalne w CyberArk.
- Kontrola wykorzystania bguser w SIEM (alert dla każdego logowania poza zatwierdzonym incydentem/testem).
- Logowanie awaryjne przez niezależne, zabezpieczone konsole, z ograniczeniem niepotrzebnego dostępu zdalnego.
- Dual custody oraz dwie niezależne kopie depozytu offline.
- Przegląd kont, członkostwa i depozytu co najmniej kwartalnie; test realnej awarii minimum dwa razy w roku.
- Zmiana hasła po użyciu awaryjnym lub podejrzeniu ujawnienia (mimo że nie ma rotacji okresowej).

**Alternatywa zmniejszająca ryzyko:** podział 150 serwerów na mniejsze grupy haseł według środowiska, krytyczności i segmentu sieci. Kierownictwo powinno świadomie zaakceptować wariant 150+150 lub wybrać mniejsze domeny skutków.

### Inne ryzyka

| Ryzyko | Kontrola |
|---|---|
| Niedostępność PAM i AD jednocześnie | Niezależny depozyt offline, dostęp OOB, próbne odłączenie usług centralnych |
| Nieudana zmiana hasła na części serwerów | Stan niejednorodny, per-host raport CPM, brak automatycznego zamknięcia zmiany |
| Nieaktualna kopia awaryjna | Aktualizacja depozytu dopiero po pełnym potwierdzeniu rotacji; dwie kontrolowane kopie |
| Niezamierzona rotacja przez politykę PAM | Wyłączenie automatycznych wyzwalaczy zmiany na platformach i w Master Policy, a nie blokada CPM |
| Utrata audytu online podczas awarii | Dziennik offline oraz późniejsze powiązanie z logami Windows/Linux i zgłoszeniem incydentu |
| Nieuprawnione użycie konta | Alarmy, rozdzielenie obowiązków, przegląd każdego wykorzystania |

## 4. Koszt i wpływ na operacje

Nie zakładamy nowych licencji bez analizy aktualnej umowy CyberArk i Ansible. Realny koszt projektu to prace zespołów PAM, Windows, Linux, IAM/Security i Incident Response oraz utrzymanie depozytu offline.

Elementy kosztu:
- Konfiguracja platform CPM, Safe, grup i uprawnień.
- Jednorazowe utworzenie 300 kont i ich weryfikacja.
- Obsługa manualnych zmian, zatwierdzanie i analiza raportu dla 300 hostów.
- Ćwiczenia awaryjne, kontrola magazynowania haseł, przeglądy audytowe.
- Czas potrzebny na naprawę częściowej rotacji i utrzymanie wyjątków bezpieczeństwa.

Nie przedstawiamy fikcyjnej kwoty ani gwarantowanego czasu przełączenia. Oba parametry będą mierzone w pilocie.

## 5. Plan wdrożenia i punkty decyzyjne

| Etap | Zakres | Warunek przejścia |
|---|---|---|
| 0. Design approval | Model grup, uprawnienia, ryzyko wspólnych haseł, depozyt offline | Akceptacja właścicieli Windows, Linux, PAM i Security |
| 1. Pilot techniczny | 2 Windows + 2 RHEL, odłączone AD/PAM, ręczna rotacja | 100% skuteczność i potwierdzona semantyka ChangeEntireGroup |
| 2. Rozszerzony pilot | 10 Windows + 10 RHEL | Brak niezamierzonej rotacji, działający audyt i OOB |
| 3. Wdrożenie produkcyjne | Pozostałe 280 hostów, partiami | 300/300 kont, prawidłowe hasła i członkostwo |
| 4. Test odtworzeniowy | Kontrolowana niedostępność AD/PAM | Działający offline access, oba depozyty aktualne |

## 6. Decyzje wymagane od managementu

1. Formalne potwierdzenie, że 150 hostów ze wspólnym hasłem w każdej kohorcie jest akceptowalnym ryzykiem, albo decyzja o mniejszych grupach.
2. Wyznaczenie właściciela usługi oraz zespołów zatwierdzających awaryjny dostęp.
3. Zatwierdzenie metody depozytu offline, lokalizacji kopii i wyznaczenie co najmniej dwóch kustoszy.
4. Zatwierdzenie zasady „rotacja na żądanie”, z **obowiązkową rotacją po użyciu / incydencie** i eskalacją wyjątków.
5. Zagwarantowanie operacyjnego czasu na testy kwartalne i ćwiczenia offline.

**Rekomendacja do zatwierdzenia:** uruchomić pilot, nie produkcję. Po potwierdzeniu zachowania CPM przy grupowej zmianie wskazanego hasła, udokumentowaniu możliwości odzyskania dostępu bez AD/PAM oraz zatwierdzeniu ryzyka wspólnego hasła zezwolić na stopniowe wdrożenie.

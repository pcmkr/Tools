# Break-Glass – dokument dla managementu (podział według produktu)

**Data:** 9 października 2026. **Status:** propozycja do zatwierdzenia i pilotażu.

## Cel biznesowy

Zapewnić zdolność administracyjnego dostępu do **300 serwerów** (150 Windows Server + 150 Red Hat Enterprise Linux) nawet podczas jednoczesnej niedostępności Active Directory i CyberArk PAM.

Każdy serwer otrzyma lokalne konto administracyjne **bguser**, które w normalnych warunkach będzie przechowywane i nadzorowane w CyberArk.

## Kluczowa decyzja: izolacja według produktu

**Produktem jest oddzielny obszar ryzyka i administracji, niezależnie od tego, jaki system operacyjny działa na obsługujących go serwerach.**

Przykład:

| Produkt | Safe CyberArk | Account Group | Systemy i hasło |
|---|---|---|---|
| ERP | BG-ERP | BG-ERP-GRP | bguser na wszystkich serwerach Windows i RHEL ERP — jedno wspólne hasło ERP |
| CRM | BG-CRM | BG-CRM-GRP | bguser na wszystkich serwerach Windows i RHEL CRM — inne wspólne hasło CRM |
| DWH | BG-DWH | BG-DWH-GRP | bguser na wszystkich serwerach Windows i RHEL DWH — inne wspólne hasło DWH |

Nazwy są przykładowe. Dokładne przypisanie 300 hostów wynika z CMDB/inwentarza serwerów i właścicieli produktów.

## Jak będzie działać

1. Inżynierowie zakładają lokalne konto bguser na serwerach produktu (Windows i RHEL).
2. Konta są dodawane do **jednego Safe produktu i jednej Account Group produktu**.
3. Dla każdego produktu obowiązuje **jedno** silne hasło wspólne dla wszystkich jego hostów. Różne produkty nie współdzielą hasła.
4. Hasło nie jest zmieniane samoczynnie przez harmonogram. Osoba z odpowiednimi uprawnieniami **podaje nowe hasło** i zleca CPM jego zmianę we wszystkich systemach produktu.
5. Każdą zmianę rozlicza się oddzielnie: wynik 100% kont w grupie, obsługa błędów i aktualizacja depozytu offline.
6. Przy awarii AD i CyberArk działa zatwierdzony niezależny depozyt, procedura podwójnej autoryzacji i konsola out-of-band.

## Ryzyka i kompensacje

| Ryzyko | Znaczenie | Kontrola |
|---|---|---|
| Wspólne hasło produktu | Poznanie jednego hasła może umożliwić dostęp do **wszystkich hostów tego produktu** | Oddzielne produkty, dostęp ograniczony, segmentacja, monitorowanie każdego użycia bguser |
| Rotacja niepełna | Część systemów ma stare, a część nowe hasło | Raport per host, wstrzymanie zamknięcia operacji, kontrola stanu SPLIT PASSWORD |
| AD i PAM niedostępne | Brak możliwości pobrania hasła online | Dwie niezależne kopie offline, dual custody, realny test OOB |
| Depozyt nieaktualny | Hasło offline nie działa w kryzysie | Aktualizacja dopiero po 100% sukcesu CPM i testach, okresowe ćwiczenia |
| Serwer utrzymuje wiele produktów | Jedno lokalne bguser nie może mieć dwóch różnych haseł jednocześnie | Formalna mapa pojedynczej domeny hasła / decyzja o wydzieleniu kont lub wspólnym produkcie nadrzędnym |
| Nieuprawnione użycie | Dostęp administratora bez prawidłowej decyzji | Rozdział obowiązków i uprawnień Safe, Alert SIEM, protokół incydentu |

Korzyść: ujawnienie hasła CRM nie musi narażać ERP, o ile hosty są prawidłowo rozdzielone, nie współdzielą tej samej tożsamości ani hasła. Izolacja nie jest jednak absolutna przy współdzielonej infrastrukturze i innych wspólnych uprawnieniach.

## Dlaczego nie jedno hasło na wszystkie 300 maszyn?

Taki wariant poszerzałby skutki kompromitacji. Granice produktów są bardziej sensowną jednostką nadzoru, odpowiedzialności i rotacji niż granica Windows / Linux, ponieważ incydent i odtwarzanie usługi obejmują zwykle cały produkt.

**Zasada rekomendowana:** jedna domena hasła per produkt, z możliwością dalszego podziału bardzo dużych produktów według krytyczności, środowiska lub strefy sieciowej.

## Koszty operacyjne

Koszty obejmują konfigurację CyberArk CPM, Safe i grup, przygotowanie Ansible, wdrożenie 300 kont, opracowanie procedury offline, testy i okresowe kontrole. Nie szacuje się kosztu licencji ani roboczogodzin bez sprawdzenia lokalnej konfiguracji, umowy i liczby produktów.

## Plan wdrożenia

| Etap | Zakres | Warunek przejścia |
|---|---|---|
| Design | Lista produktów i hostów, Safe/Group per produkt, role i depozyty | Zatwierdzenie właścicieli i Security |
| Pilot | Produkt testowy z Windows i RHEL w jednej grupie; drugi produkt dla izolacji | Potwierdzona zmiana wskazanego hasła przez CPM na oba OS |
| Test awaryjny | Odłączenie AD i PAM, konsola OOB i escrow | Udane lokalne logowanie na Windows i RHEL |
| Rollout | Konta na 150 Windows i 150 RHEL, w małych partiach per produkt | Wynik 100%, zgodny CMDB i Safe/Group |
| Operacje | Testy rotacji, ćwiczenia offline, przeglądy uprawnień | Audyt, brak niewyjaśnionych odstępstw |

## Decyzje do zatwierdzenia

1. Potwierdzić, że **produkty, nie systemy operacyjne**, wyznaczają granice haseł i odpowiedzialności.
2. Zatwierdzić mapę serwer → produkt i sposób obsługi hostów współdzielonych.
3. Zaakceptować ryzyko jednego wspólnego hasła w obrębie produktu oraz kontrole kompensujące.
4. Wyznaczyć role: właściciel usługi, operator rotacji, osoba zatwierdzająca, kustosze depozytu, audytor.
5. Zatwierdzić ręczną rotację z obowiązkową zmianą **po użyciu awaryjnym**, mimo braku rotacji okresowej.
6. Zapewnić środowisko do testów CyberArk z docelowymi platformami Windows i RHEL.

**Rekomendacja:** zatwierdzić pilotaż modelu produktowego. Produkcyjne uruchomienie wymaga pozytywnego testu mieszanej Account Group i kontrolowanej rotacji wspólnego, wskazanego przez operatora hasła.

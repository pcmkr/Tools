# Splunk — historia włączeń i wyłączeń kont AD

Raport historii zmian stanu kont użytkowników Active Directory dla dowolnej listy `sAMAccountName`.

- **4722** — A user account was enabled.
- **4725** — A user account was disabled.

## Pełna historia

```spl
index=wineventlog (EventCode=4722 OR EventCode=4725 OR EventID=4722 OR EventID=4725)
| eval KodZdarzenia=tonumber(coalesce(EventCode, EventID))
| eval Konto=coalesce(TargetUserName, 'EventData.TargetUserName', Target_Account_Name)
| eval Domena=coalesce(TargetDomainName, 'EventData.TargetDomainName', Target_Domain_Name)
| eval Wykonal=coalesce(SubjectUserName, 'EventData.SubjectUserName', Subject_Account_Name)
| search Konto IN ("user1", "user2", "user3")
| eval Operacja=case(
    KodZdarzenia=4722, "Włączono",
    KodZdarzenia=4725, "Wyłączono"
  )
| sort 0 Domena Konto -_time
| eval Data=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table Data Domena Konto Operacja Wykonal host
```

## Ostatnia zaobserwowana operacja dla każdego konta w każdej domenie

```spl
index=wineventlog (EventCode=4722 OR EventCode=4725 OR EventID=4722 OR EventID=4725)
| eval KodZdarzenia=tonumber(coalesce(EventCode, EventID))
| eval Konto=coalesce(TargetUserName, 'EventData.TargetUserName', Target_Account_Name)
| eval Domena=coalesce(TargetDomainName, 'EventData.TargetDomainName', Target_Domain_Name)
| eval Wykonal=coalesce(SubjectUserName, 'EventData.SubjectUserName', Subject_Account_Name)
| search Konto IN ("user1", "user2", "user3")
| eval Operacja=case(
    KodZdarzenia=4722, "Włączono",
    KodZdarzenia=4725, "Wyłączono"
  )
| sort 0 -_time
| dedup Domena Konto
| eval Data=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table Domena Konto Data Operacja Wykonal host
| sort 0 Domena Konto
```

## Dostosowanie

1. Zamień `index=wineventlog` na indeks gromadzący logi Windows Security ze wszystkich kontrolerów domeny.
2. Zmień listę `("user1", "user2", "user3")` na konkretne loginy `sAMAccountName`.
3. Ustaw przedział czasu w Splunku, np. **All time**.
4. Możesz dodać filtr na `sourcetype="WinEventLog:Security"` lub odpowiedni `XmlWinEventLog`, zależnie od konfiguracji.
5. Aby zawęzić domenę, za `eval Domena=...` dopisz `| search Domena="CONTOSO"`.

## Interpretacja kolumn

| Kolumna | Znaczenie |
|---|---|
| Data | Czas zdarzenia w strefie czasowej wyników Splunka |
| Domena | Domena docelowego konta (`TargetDomainName`, zwykle NetBIOS) |
| Konto | Użytkownik, którego stan zmieniono |
| Operacja | Włączono / Wyłączono |
| Wykonal | Administrator lub konto usługi wykonujące operację (`SubjectUserName`) |
| host | Źródłowy DC rejestrujący zdarzenie |

**Uwaga:** wynik opisuje historię dostępną w logach, a nie potwierdzony aktualny stan konta w AD. Brak zdarzenia nie dowodzi braku zmiany — znaczenie mają audyt, kompletność zbierania logów i retencja. `SubjectDomainName` oznacza domenę wykonawcy, a nie domenę konta docelowego.

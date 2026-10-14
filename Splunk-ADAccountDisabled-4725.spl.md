# Splunk — wyłączenia kont AD (Event ID 4725)

Zapytania pobierają wyłącznie zdarzenia **4725 — A user account was disabled** z Windows Security, dla podanej listy kont.

## Pełna historia wyłączeń

```spl
index=wineventlog (EventCode=4725 OR EventID=4725)
| eval Konto=coalesce(TargetUserName, 'EventData.TargetUserName', Target_Account_Name)
| eval Domena=coalesce(TargetDomainName, 'EventData.TargetDomainName', Target_Domain_Name)
| eval Wykonal=coalesce(SubjectUserName, 'EventData.SubjectUserName', Subject_Account_Name)
| search Konto IN ("user1", "user2", "user3")
| sort 0 Domena Konto -_time
| eval Data=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table Data Domena Konto Wykonal host
```

## Ostatnie zarejestrowane wyłączenie każdego konta w każdej domenie

```spl
index=wineventlog (EventCode=4725 OR EventID=4725)
| eval Konto=coalesce(TargetUserName, 'EventData.TargetUserName', Target_Account_Name)
| eval Domena=coalesce(TargetDomainName, 'EventData.TargetDomainName', Target_Domain_Name)
| eval Wykonal=coalesce(SubjectUserName, 'EventData.SubjectUserName', Subject_Account_Name)
| search Konto IN ("user1", "user2", "user3")
| sort 0 -_time
| dedup Domena Konto
| eval Data=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table Domena Konto Data Wykonal host
| sort 0 Domena Konto
```

## Konfiguracja i ograniczenia

- Zastąp `index=wineventlog` właściwym indeksem Windows Security z DC.
- W `Konto IN (...)` wpisz listę loginów `sAMAccountName`; przykładowo `("jkowalski", "anowak", "svc_sql")`.
- Ustaw odpowiedni przedział czasu, np. **All time**.
- `Domena` to domena **wyłączanego konta** (`TargetDomainName`), zazwyczaj nazwa NetBIOS.
- `Wykonal` to nazwa użytkownika lub usługi, która zainicjowała wyłączenie; `host` to DC rejestrujący operację.
- Podobnie jak w ogólnej historii, można ograniczyć `sourcetype` według konfiguracji (`WinEventLog:Security` / `XmlWinEventLog`).

**Ważne:** ostatnie widoczne zdarzenie 4725 **nie potwierdza, że konto nadal jest wyłączone**. Mogło zostać później ponownie włączone (zdarzenie 4722). Aby ustalić ostatnią zmianę stanu, skorzystaj z `Splunk-ADEnableDisableHistory.spl.md`. Kompletny wynik wymaga zbierania zdarzeń Security ze wszystkich właściwych DC oraz odpowiedniej retencji.

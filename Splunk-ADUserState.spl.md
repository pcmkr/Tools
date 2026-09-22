# Splunk SPL - AD user state/history from Windows Security logs

## Założenia

- `index=windows` i `sourcetype=WinEventLog:Security` zmień na swoje wartości.
- Lista użytkowników jest podana jako `samaccountname IN (...)`.
- Domena jest filtrowana przez `TargetDomainName` / `Account_Domain` zależnie od TA.
- Dokładne nazwy pól mogą się różnić między Splunk Add-on for Microsoft Windows / XmlWinEventLog.
- Security log daje historię zdarzeń. Nie gwarantuje pełnego *current state*, jeżeli retencja nie obejmuje ostatniej zmiany.
- Dokładnej bieżącej daty wygaśnięcia hasła nie da się wiarygodnie wyliczyć wyłącznie z Security log bez polityki hasła/FGPP. Query pokazuje zdarzenia wskazujące na wygasłe hasło.

## Query

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4624 OR EventCode=4625 OR EventCode=4722 OR EventCode=4725 OR EventCode=4740 OR EventCode=4767 OR EventCode=4771)
| eval samaccountname=coalesce(TargetUserName, Account_Name, user)
| eval domain=coalesce(TargetDomainName, Account_Domain, user_domain)
| where samaccountname IN ("user1","user2","user3") AND domain="CONTOSO"
| eval event_type=case(
    EventCode=4624, "LogonSuccess",
    EventCode=4625, "LogonFailure",
    EventCode=4722, "AccountEnabled",
    EventCode=4725, "AccountDisabled",
    EventCode=4740, "AccountLocked",
    EventCode=4767, "AccountUnlocked",
    EventCode=4771, "KerberosPreAuthFailure",
    true(), "Other"
  )
| eval password_expired_event=if(
    (EventCode=4625 AND (SubStatus="0xC0000071" OR Status="0xC0000071"))
    OR (EventCode=4771 AND FailureCode="0x17"),
    1, 0
  )
| stats
    max(eval(if(EventCode=4624,_time,null()))) as last_logon_epoch
    max(eval(if(EventCode=4625,_time,null()))) as last_failed_logon_epoch
    max(eval(if(EventCode=4725,_time,null()))) as last_disabled_epoch
    max(eval(if(EventCode=4722,_time,null()))) as last_enabled_epoch
    max(eval(if(EventCode=4740,_time,null()))) as last_lockout_epoch
    max(eval(if(EventCode=4767,_time,null()))) as last_unlock_epoch
    max(eval(if(password_expired_event=1,_time,null()))) as last_password_expired_event_epoch
    values(eval(if(EventCode=4625,coalesce(SubStatus,Status,FailureReason),null()))) as last_failure_codes
  by samaccountname domain
| eval Enabled=case(
    isnull(last_disabled_epoch) AND isnull(last_enabled_epoch), "Unknown",
    coalesce(last_enabled_epoch,0)>coalesce(last_disabled_epoch,0), "True",
    true(), "False"
  )
| eval LockedOut=case(
    isnull(last_lockout_epoch) AND isnull(last_unlock_epoch), "Unknown",
    coalesce(last_lockout_epoch,0)>coalesce(last_unlock_epoch,0), "True",
    true(), "False"
  )
| eval PasswordExpiredObserved=if(isnotnull(last_password_expired_event_epoch),"True","Unknown/Not observed")
| convert ctime(last_logon_epoch) ctime(last_failed_logon_epoch) ctime(last_disabled_epoch) ctime(last_enabled_epoch) ctime(last_lockout_epoch) ctime(last_unlock_epoch) ctime(last_password_expired_event_epoch)
| rename
    last_logon_epoch as LastLogon
    last_failed_logon_epoch as LastFailedLogon
    last_disabled_epoch as DisabledAt
    last_enabled_epoch as EnabledAt
    last_lockout_epoch as LockedAt
    last_unlock_epoch as UnlockedAt
    last_password_expired_event_epoch as PasswordExpiredObservedAt
| table samaccountname domain Enabled DisabledAt EnabledAt LastLogon LastFailedLogon LockedOut LockedAt UnlockedAt PasswordExpiredObserved PasswordExpiredObservedAt last_failure_codes
```

## Event IDs użyte w raporcie

- 4624 — udane logowanie
- 4625 — nieudane logowanie
- 4722 — konto włączone
- 4725 — konto wyłączone
- 4740 — konto zablokowane
- 4767 — konto odblokowane
- 4771 — Kerberos pre-authentication failed; failure code 0x17 oznacza wygasły klucz/hasło użytkownika

## Uwagi o interpretacji

`Enabled` i `LockedOut` są wyliczane na podstawie najnowszego zdarzenia zmiany stanu dostępnego w Splunku. Jeśli retencja logów nie obejmuje faktycznej ostatniej zmiany, wynik będzie `Unknown` albo może nie odzwierciedlać obecnego AD.

`PasswordExpiredObserved` oznacza, że w logach zaobserwowano próbę logowania zakończoną kodem odpowiadającym wygasłemu hasłu. Nie jest to zamiennik bieżącego `msDS-UserPasswordExpiryTimeComputed` z AD.
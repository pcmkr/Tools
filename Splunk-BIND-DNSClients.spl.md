# Splunk — audyt klientów DNS BIND

Zapytania służą do ustalenia, **jakie adresy IP nadal korzystają z serwerów BIND**, kiedy kontaktowały się z nimi ostatnio i o jakie domeny pytały. Punktem wyjścia jest `eventtype=isc_bind_query`, a nie filtr fraz w `_raw`. W dodatku Splunk Add-on for ISC BIND adres klienta może być już w polu `src`, nazwa domeny w `query`, a typ rekordu w `record_type`. Parsowanie surowego logu jest wyłącznie rezerwowym źródłem danych.

## 1. Główny raport — klienci korzystający z serwerów BIND (ostatnie 30 dni)

```spl
eventtype=isc_bind_query earliest=-30d
| rex field=_raw "client\s+(?:@0x[0-9a-fA-F]+\s+)?(?<IPzRaw>[0-9a-fA-F:.]+)#\d+"
| rex field=_raw "query:\s+(?<DomenazRaw>\S+)\s+\S+\s+(?<TypzRaw>\S+)"
| eval KlientIP=replace(coalesce(src,src_ip,client_ip,IPzRaw),"#\d+$","")
| eval Domena=coalesce(query,dns_query,qname,DomenazRaw)
| eval TypDNS=coalesce(record_type,qtype,TypzRaw)
| where isnotnull(KlientIP)
| stats count AS LiczbaZapytan earliest(_time) AS PierwszeZapytanie latest(_time) AS OstatnieZapytanie dc(Domena) AS RozneDomeny latest(Domena) AS OstatniaDomena values(TypDNS) AS TypyZapytan BY host KlientIP
| eval DniOdOstatniego=round((now()-OstatnieZapytanie)/86400,2)
| sort 0 -OstatnieZapytanie
| eval PierwszeZapytanie=strftime(PierwszeZapytanie,"%Y-%m-%d %H:%M:%S")
| eval OstatnieZapytanie=strftime(OstatnieZapytanie,"%Y-%m-%d %H:%M:%S")
| rename host AS SerwerDNS KlientIP AS IPKlienta
| eval TypAdresu=case(
    cidrmatch("10.0.0.0/8",IPKlienta) OR cidrmatch("172.16.0.0/12",IPKlienta) OR cidrmatch("192.168.0.0/16",IPKlienta) OR cidrmatch("fc00::/7",IPKlienta), "Prywatny",
    cidrmatch("192.0.0.9/32",IPKlienta) OR cidrmatch("192.0.0.10/32",IPKlienta), "Publiczny",
    cidrmatch("0.0.0.0/8",IPKlienta) OR cidrmatch("100.64.0.0/10",IPKlienta) OR cidrmatch("127.0.0.0/8",IPKlienta) OR cidrmatch("169.254.0.0/16",IPKlienta) OR cidrmatch("192.0.0.0/24",IPKlienta) OR cidrmatch("192.0.2.0/24",IPKlienta) OR cidrmatch("192.88.99.0/24",IPKlienta) OR cidrmatch("198.18.0.0/15",IPKlienta) OR cidrmatch("198.51.100.0/24",IPKlienta) OR cidrmatch("203.0.113.0/24",IPKlienta) OR cidrmatch("224.0.0.0/4",IPKlienta) OR cidrmatch("240.0.0.0/4",IPKlienta) OR cidrmatch("::/128",IPKlienta) OR cidrmatch("::1/128",IPKlienta) OR cidrmatch("::ffff:0:0/96",IPKlienta) OR cidrmatch("100::/64",IPKlienta) OR cidrmatch("2001:db8::/32",IPKlienta) OR cidrmatch("fe80::/10",IPKlienta) OR cidrmatch("fec0::/10",IPKlienta) OR cidrmatch("ff00::/8",IPKlienta), "Specjalny/niepubliczny",
    cidrmatch("0.0.0.0/0",IPKlienta) OR cidrmatch("::/0",IPKlienta), "Publiczny",
    true(), "Nieznany/nie-IP"
  )
| table SerwerDNS IPKlienta TypAdresu LiczbaZapytan PierwszeZapytanie OstatnieZapytanie DniOdOstatniego RozneDomeny OstatniaDomena TypyZapytan
```

**Dostosowanie:**
- Zacznij od diagnostyki z sekcji 3, aby poznać rzeczywiste wartości pola `host` w eventtype.
- Raport domyślnie pokazuje wszystkie serwery w `eventtype=isc_bind_query`. Aby wybrać konkretne, dodaj zaraz po `| where isnotnull(KlientIP)` linię `| search host IN ("dns01","dns02")`, podstawiając wartości potwierdzone w sekcji 3.
- Pola `src`, `query`, `record_type` i `dest` zależą od konfiguracji dodatku; zapytanie dodatkowo próbuje odczytać klienta, domenę i typ rekordu z `_raw`.
- earliest=-30d oznacza 30 dni; przy audycie przed wyłączeniem warto powtórzyć dla 60–90 dni, jeśli pozwalają na to retencja i koszt wyszukiwania.
- Jeden wiersz = jedna para serwer DNS / adres IP klienta. DniOdOstatniego to czas od ostatniego zapytania, a nie gwarancja regularnego używania usługi.
- **TypAdresu** klasyfikuje **IP klienta**, nie IP serwera DNS. „Prywatny” oznacza IPv4 RFC 1918 (10/8, 172.16/12, 192.168/16) lub IPv6 ULA (fc00::/7). „Publiczny” uwzględnia wyjątki 192.0.0.9 i 192.0.0.10 z rejestru IANA. „Specjalny/niepubliczny” obejmuje m.in. loopback, link-local, CGNAT, adresy dokumentacyjne i multicast. „Publiczny” oznacza pozostały adres niepasujący do podanych zakresów; nie gwarantuje, że adres jest aktualnie trasowany w Internecie.
- Aby zostawić w raporcie wyłącznie klientów publicznych, dopisz za `eval TypAdresu=case(...)`: `| where TypAdresu="Publiczny"` (przed `table`).
- Dla pominięcia ruchu lokalnego można dodać przed stats: | where NOT (KlientIP="127.0.0.1" OR KlientIP="::1"). Zrób to tylko świadomie — zapytania lokalne też mogą być istotne.

## 2. Szczegóły — ostatnie 200 zapytań

Pozwala sprawdzić dokładnie jakie domeny i typy rekordów były odpytywane.

```spl
eventtype=isc_bind_query earliest=-30d
| rex field=_raw "client\s+(?:@0x[0-9a-fA-F]+\s+)?(?<IPzRaw>[0-9a-fA-F:.]+)#\d+"
| rex field=_raw "query:\s+(?<DomenazRaw>\S+)\s+\S+\s+(?<TypzRaw>\S+)"
| eval KlientIP=replace(coalesce(src,src_ip,client_ip,IPzRaw),"#\d+$","")
| eval Domena=coalesce(query,dns_query,qname,DomenazRaw)
| eval TypDNS=coalesce(record_type,qtype,TypzRaw)
| where isnotnull(KlientIP)
| sort 200 -_time
| eval Data=strftime(_time,"%Y-%m-%d %H:%M:%S")
| rename host AS SerwerDNS KlientIP AS IPKlienta
| eval TypAdresu=case(
    cidrmatch("10.0.0.0/8",IPKlienta) OR cidrmatch("172.16.0.0/12",IPKlienta) OR cidrmatch("192.168.0.0/16",IPKlienta) OR cidrmatch("fc00::/7",IPKlienta), "Prywatny",
    cidrmatch("192.0.0.9/32",IPKlienta) OR cidrmatch("192.0.0.10/32",IPKlienta), "Publiczny",
    cidrmatch("0.0.0.0/8",IPKlienta) OR cidrmatch("100.64.0.0/10",IPKlienta) OR cidrmatch("127.0.0.0/8",IPKlienta) OR cidrmatch("169.254.0.0/16",IPKlienta) OR cidrmatch("192.0.0.0/24",IPKlienta) OR cidrmatch("192.0.2.0/24",IPKlienta) OR cidrmatch("192.88.99.0/24",IPKlienta) OR cidrmatch("198.18.0.0/15",IPKlienta) OR cidrmatch("198.51.100.0/24",IPKlienta) OR cidrmatch("203.0.113.0/24",IPKlienta) OR cidrmatch("224.0.0.0/4",IPKlienta) OR cidrmatch("240.0.0.0/4",IPKlienta) OR cidrmatch("::/128",IPKlienta) OR cidrmatch("::1/128",IPKlienta) OR cidrmatch("::ffff:0:0/96",IPKlienta) OR cidrmatch("100::/64",IPKlienta) OR cidrmatch("2001:db8::/32",IPKlienta) OR cidrmatch("fe80::/10",IPKlienta) OR cidrmatch("fec0::/10",IPKlienta) OR cidrmatch("ff00::/8",IPKlienta), "Specjalny/niepubliczny",
    cidrmatch("0.0.0.0/0",IPKlienta) OR cidrmatch("::/0",IPKlienta), "Publiczny",
    true(), "Nieznany/nie-IP"
  )
| table Data SerwerDNS IPKlienta TypAdresu Domena TypDNS KlasaDNS
```

W celu sprawdzenia konkretnego klienta dodaj przed sort: | search KlientIP="192.0.2.50".

## 3. Diagnostyka — gdzie znajdują się logi zapytań BIND?

Najpierw sprawdź wszystkie serwery widoczne w eventtype oraz to, czy dodatek wydobywa pola. Zdarzenie z pustym `src` nie musi oznaczać, że nie było zapytania:

```spl
eventtype=isc_bind_query earliest=-30d
| stats count AS LiczbaZdarzen count(src) AS ZPoleSrc count(query) AS ZPoleQuery count(record_type) AS ZPoleRecordType BY index host sourcetype
| sort 0 -LiczbaZdarzen
```

Wyniki pozwalają zweryfikować właściwy `host` i stopień wyodrębniania pól. W razie wątpliwości obejrzyj surowe zdarzenia:

```spl
eventtype=isc_bind_query earliest=-24h
| table _time host sourcetype src src_ip client_ip dest query record_type query_type _raw
| head 20
```

**Kontrola utraconych klientów przy agregacji** — to zapytanie liczy także zdarzenia, w których nie udało się odczytać adresu klienta:

```spl
eventtype=isc_bind_query earliest=-30d
| rex field=_raw "client\s+(?:@0x[0-9a-fA-F]+\s+)?(?<IPzRaw>[0-9a-fA-F:.]+)#\d+"
| eval MaPoleIP=if(isnotnull(coalesce(src,src_ip,client_ip)),1,0)
| eval MaIPzRaw=if(isnotnull(IPzRaw),1,0)
| eval BrakIP=if(MaPoleIP=0 AND MaIPzRaw=0,1,0)
| stats count AS WszystkieZdarzenia sum(MaPoleIP) AS ZPoleIP sum(MaIPzRaw) AS ZIPzRaw sum(BrakIP) AS BezRozpoznanegoIP BY host sourcetype
| sort 0 -WszystkieZdarzenia
```

`ZPoleIP` i `ZIPzRaw` mogą liczyć te same zdarzenia, więc nie należy ich sumować. Jeśli `BezRozpoznanegoIP` jest większe od zera, sprawdź przykładowe rekordy:

```spl
eventtype=isc_bind_query earliest=-7d
| rex field=_raw "client\s+(?:@0x[0-9a-fA-F]+\s+)?(?<IPzRaw>[0-9a-fA-F:.]+)#\d+"
| where isnull(coalesce(src,src_ip,client_ip,IPzRaw))
| table _time host sourcetype _raw
| head 50
```

Jeżeli eventtype nie zawiera zdarzeń z oczekiwanych serwerów, sprawdź definicję eventtype, sourcetype, uprawnienia, logowanie na BIND, retencję i sposób przekazywania logów. Brak logów nie jest dowodem braku ruchu DNS.

## 4. Alternatywa — logi firewall / NetFlow zamiast logów BIND

Jeśli BIND nie loguje zapytań, a Splunk ma logi ruchu sieciowego zawierające adresy źródłowy i docelowy oraz port docelowy, można sprawdzić klientów wysyłających ruch na TCP/UDP 53 do IP serwerów DNS.

```spl
index=TU_WPISZ_INDEKS_SIECIOWY earliest=-30d
| eval IPSerwera=coalesce(dest_ip,dst_ip,destination_ip,dest,dst)
| eval IPKlienta=coalesce(src_ip,source_ip,src)
| eval PortDNS=tonumber(coalesce(dest_port,dport,dst_port,destination_port))
| where PortDNS=53 AND IPSerwera IN ("192.0.2.10","192.0.2.11") AND isnotnull(IPKlienta)
| stats count AS LiczbaZdarzen earliest(_time) AS PierwszaObserwacja latest(_time) AS OstatniaObserwacja BY IPSerwera IPKlienta
| sort 0 -OstatniaObserwacja
| eval PierwszaObserwacja=strftime(PierwszaObserwacja,"%Y-%m-%d %H:%M:%S")
| eval OstatniaObserwacja=strftime(OstatniaObserwacja,"%Y-%m-%d %H:%M:%S")
| eval TypAdresu=case(
    cidrmatch("10.0.0.0/8",IPKlienta) OR cidrmatch("172.16.0.0/12",IPKlienta) OR cidrmatch("192.168.0.0/16",IPKlienta) OR cidrmatch("fc00::/7",IPKlienta), "Prywatny",
    cidrmatch("192.0.0.9/32",IPKlienta) OR cidrmatch("192.0.0.10/32",IPKlienta), "Publiczny",
    cidrmatch("0.0.0.0/8",IPKlienta) OR cidrmatch("100.64.0.0/10",IPKlienta) OR cidrmatch("127.0.0.0/8",IPKlienta) OR cidrmatch("169.254.0.0/16",IPKlienta) OR cidrmatch("192.0.0.0/24",IPKlienta) OR cidrmatch("192.0.2.0/24",IPKlienta) OR cidrmatch("192.88.99.0/24",IPKlienta) OR cidrmatch("198.18.0.0/15",IPKlienta) OR cidrmatch("198.51.100.0/24",IPKlienta) OR cidrmatch("203.0.113.0/24",IPKlienta) OR cidrmatch("224.0.0.0/4",IPKlienta) OR cidrmatch("240.0.0.0/4",IPKlienta) OR cidrmatch("::/128",IPKlienta) OR cidrmatch("::1/128",IPKlienta) OR cidrmatch("::ffff:0:0/96",IPKlienta) OR cidrmatch("100::/64",IPKlienta) OR cidrmatch("2001:db8::/32",IPKlienta) OR cidrmatch("fe80::/10",IPKlienta) OR cidrmatch("fec0::/10",IPKlienta) OR cidrmatch("ff00::/8",IPKlienta), "Specjalny/niepubliczny",
    cidrmatch("0.0.0.0/0",IPKlienta) OR cidrmatch("::/0",IPKlienta), "Publiczny",
    true(), "Nieznany/nie-IP"
  )
| table IPSerwera IPKlienta TypAdresu LiczbaZdarzen PierwszaObserwacja OstatniaObserwacja
```

**Uwaga:** nazwę indeksu, pola src/dst i port należy dopasować do konkretnego źródła danych. Jeden log firewalla lub rekord NetFlow nie musi oznaczać jednego zapytania DNS. Zdarzenie blokady połączenia nie dowodzi, że BIND obsłużył zapytanie. Aby analizować jedynie ruch dopuszczony, użyj odpowiedniego filtra akcji (zależnego od źródła). Ten wariant nie pokaże nazw domen bez danych DNS na poziomie aplikacyjnym.

## Uwagi i ograniczenia

1. Analiza logów BIND opiera się na kategorii **queries**. Zapytania mają najczęściej format zbliżony do:
   - client @0x7f... 192.0.2.50#49812 (example.org): query: example.org IN A +E(0)K (192.0.2.10)
   - client 192.0.2.50#49812: query: example.org IN AAAA +SE
   - Obsługiwane są obie postacie (z identyfikatorem @0x i bez), w tym adresy IPv6.
2. Klasyfikacja adresów opiera się na funkcji Splunk `cidrmatch`, obsługującej IPv4 i IPv6. To praktyczne rozróżnienie najważniejszych zakresów, a nie pełna bieżąca weryfikacja globalnej osiągalności według wszystkich rejestrów IANA. Dla nietypowych zakresów specjalnych sprawdź rejestry IANA przed podjęciem decyzji operacyjnej.
3. Zapytania preferują pola dodatku (`src`, `query`, `record_type`), a regex `_raw` wykorzystują tylko jako uzupełnienie. `query_type` w niektórych wersjach dodatku oznacza operację `Query` i nie powinno zastępować pola `record_type`. **host** musi reprezentować serwer DNS; przy syslog relay/centralnym kolektorze może oznaczać forwarder — wtedy filtruj po poprawnym polu docelowego urządzenia lub adresie docelowym z danych.
4. Jeśli klient korzysta z pośredniego resolvera, przekierowania lub NAT, log BIND może identyfikować **resolver pośredniczący / adres po NAT**, nie pierwotnego klienta.
5. **Brak wyników nie jest dowodem braku użycia DNS.** Sprawdź retencję, ciągłość przesyłania logów, włączone query logging, wszystkie interfejsy/instancje i pomijane ścieżki ruchu. Należy porównać wyniki z telemetrią sieciową przed wyłączeniem.
6. Włączenie pełnego query logging może być kosztowne przy wysokim ruchu DNS. W BIND 9 można sterować logowaniem zapytań podczas pracy przez rndc querylog on/off; docelowy kanał musi być poprawnie skonfigurowany, a zmianę należy wykonać zgodnie z zasadami eksploatacyjnymi.

**Źródła referencyjne:**
- Splunk — cidrmatch (IPv4/IPv6): https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.1/evaluation-functions/comparison-and-conditional-functions
- IANA — IPv4 special-purpose ranges: https://www.iana.org/assignments/iana-ipv4-special-registry
- IANA — IPv6 special-purpose ranges: https://www.iana.org/assignments/iana-ipv6-special-registry
- ISC BIND 9 — logging category queries: https://bind9.readthedocs.io/en/v9.18.27/reference.html
- ISC BIND 9 — najnowszy Administrator Reference Manual: https://bind9.readthedocs.io/en/stable/reference.html

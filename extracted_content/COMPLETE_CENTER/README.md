# GLOBAL INTELLIGENCE SECURITY COMMAND CENTER

**CLASSIFICATION: TOP SECRET // NSOC // MULTI-AGENCY**

**TIER-0 NATIONAL SECURITY OPERATIONS CENTER**

---

## SISTEMSKE ZAHTEVE

### Minimalne zahteve
- Python 3.12+
- Node.js 18+
- 8 GB RAM
- 50 GB prostor na disku

### Priporočene zahteve
- Python 3.12+
- Node.js 20+
- 32 GB RAM
- 500 GB SSD
- Dedicirano omrežje 1 Gbps+

---

## HITER ZAGON

### POMEMBNO: Pravilna lokacija zagona

Skripta `START_SYSTEM.sh` mora biti zagnana iz mape `COMPLETE_CENTER`, kjer se nahajata mapi `gisc-ui` in `gisc-backend`. Skripta išče te mape relativno glede na svojo lokacijo.

### Koraki za zagon na Ubuntu sistemu:

#### 1. Razpakiraj sistem (če še ni razpakiran)

```bash
unzip TYRANTHOS_COMPLETE_SYSTEM.zip
cd COMPLETE_CENTER
```

#### 2. Avtomatski zagon (priporočeno)

Skripta bo avtomatsko namestila vse odvisnosti in zagnala sistem:

```bash
./START_SYSTEM.sh
```

To bo:
- Namestilo Python odvisnosti (poetry install)
- Namestilo Node.js odvisnosti (npm install)
- Zagnalo Backend API na portu 8000
- Zagnalo Frontend UI na portu 3000

#### 3. Alternativni načini zagona

Samo namestitev odvisnosti (brez zagona):
```bash
./START_SYSTEM.sh install
```

Zagon sistema (po namestitvi):
```bash
./START_SYSTEM.sh start
```

Zagon samo aplikacije (brez varnostnih orodij):
```bash
./START_SYSTEM.sh start-app
```

#### 4. Dostop do sistema

- **Frontend UI**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Dokumentacija**: http://localhost:8000/docs

#### 5. Ustavitev sistema

```bash
./START_SYSTEM.sh stop
```

#### 6. Preverjanje statusa

```bash
./START_SYSTEM.sh status
```

---

## ROČNI ZAGON

### Backend (FastAPI)

```bash
cd gisc-backend
poetry install
poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Ali brez Poetry:

```bash
cd gisc-backend
pip install fastapi[standard] sqlalchemy aiosqlite python-multipart pydantic-settings psutil
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Frontend (React + Vite)

```bash
cd gisc-ui
npm install
npm run dev
```

Za produkcijsko gradnjo:

```bash
cd gisc-ui
npm run build
```

---

## API ENDPOINTS

### Sistemski status
- `GET /healthz` - Zdravstveni pregled
- `GET /api/v1/status` - Sistemski status
- `GET /api/v1/metrics` - Sistemske metrike
- `GET /api/v1/dashboard/stats` - Statistika nadzorne plošče

### Grožnje
- `GET /api/v1/threats` - Seznam groženj
- `POST /api/v1/threats` - Ustvari grožnjo
- `GET /api/v1/threats/{id}` - Pridobi grožnjo
- `PUT /api/v1/threats/{id}` - Posodobi grožnjo
- `DELETE /api/v1/threats/{id}` - Izbriši grožnjo

### Obveščevalni podatki
- `GET /api/v1/intel` - Seznam poročil
- `POST /api/v1/intel` - Ustvari poročilo
- `GET /api/v1/intel/{id}` - Pridobi poročilo
- `PUT /api/v1/intel/{id}` - Posodobi poročilo
- `DELETE /api/v1/intel/{id}` - Izbriši poročilo

### Omrežni vozlišča
- `GET /api/v1/nodes` - Seznam vozlišč
- `POST /api/v1/nodes` - Ustvari vozlišče
- `GET /api/v1/nodes/{id}` - Pridobi vozlišče
- `PUT /api/v1/nodes/{id}` - Posodobi vozlišče
- `DELETE /api/v1/nodes/{id}` - Izbriši vozlišče

### Skeniranje
- `POST /api/v1/scan` - Zaženi skeniranje
- `GET /api/v1/scans` - Seznam skeniranj
- `GET /api/v1/scans/{id}` - Pridobi rezultate skeniranja

### MITRE ATT&CK
- `GET /api/v1/mitre/coverage` - Pokritost MITRE ATT&CK

### Revizija
- `GET /api/v1/audit` - Revizijski dnevnik

### Inicializacija
- `POST /api/v1/seed` - Inicializiraj testne podatke

---

## MODULI SISTEMA

### SOC CORE - Varnostni operativni center
Centralna nadzorna plošča za spremljanje varnostnih dogodkov v realnem času.

### INTELLIGENCE - Obveščevalna fuzija
Multi-INT (SIGINT, FININT, OSINT, HUMINT, CI) obveščevalna platforma.

### NET MON - Omrežno spremljanje
Spremljanje omrežne infrastrukture in detekcija anomalij.

### THREAT FEED - Tok groženj
Tok groženj v realnem času z MITRE ATT&CK mapiranjem.

### FORENSICS - Digitalna forenzika
Orodja za digitalno forenzično preiskavo.

### RED TEAM - Ofenzivne operacije
Simulacija napadov in penetracijsko testiranje.

### BLUE TEAM - Defenzivne operacije
Obrambne operacije in odziv na incidente.

### MALWARE LAB - Laboratorij za zlonamerno programje
Analiza zlonamernega programja v izoliranem okolju.

### QUANTUM SEC - Kvantna varnost
Kvantno odporna kriptografija in varnost.

### AI DEFENSE - AI obramba
Strojno učenje za detekcijo groženj.

### REDACTED COMMS - Varne komunikacije
Šifrirane komunikacije najvišje stopnje.

### CHAIN TRACK - Sledenje verigi blokov
Forenzika kriptovalut in sledenje transakcij.

### EVIDENCE VAULT - Trezor dokazov
Varno shranjevanje in upravljanje dokazov.

### OPSCOM - Operativno poveljstvo
Centralno poveljstvo za koordinacijo operacij.

---

## PREDLOGE (TEMPLATES)

Direktorij `templates/` vsebuje 138 produkcijsko pripravljenih predlog za:

- Varnostne sisteme (authentication, authorization, encryption)
- Obveščevalne operacije (SIGINT, FININT, OSINT, HUMINT)
- Defenzivne operacije (IDS/IPS, SIEM, SOC)
- Ofenzivne operacije (penetration testing, red team)
- Forenzične operacije (malware analysis, incident response)
- Omrežno varnost (firewall, VPN, network monitoring)
- Kvantno varnost (post-quantum cryptography)
- AI/ML varnost (threat detection, anomaly detection)
- In še več...

---

## VARNOSTNE FUNKCIJE

### Avtentikacija
- PBKDF2-SHA512 hashiranje gesel (600.000 iteracij)
- JWT tokeni z HMAC-SHA256 podpisom
- TOTP večfaktorska avtentikacija (RFC 6238)
- Zaklepanje računa po neuspelih poskusih

### Kriptografija
- AES-256-GCM šifriranje
- RSA-4096 asimetrična kriptografija
- Kvantno odporne sheme (Kyber, Dilithium)

### Revizija
- Popoln revizijski dnevnik vseh operacij
- Nespremenljivo beleženje
- Časovni žigi z milisekundno natančnostjo

---

## SKLADNOST

Sistem je skladen z naslednjimi standardi:

- DO-178C (letalska programska oprema)
- IEC 61508 (funkcionalna varnost)
- ISO 26262 (avtomobilska varnost)
- MIL-STD-882E (vojaška varnost)
- NIST SP 800-53 (varnostni kontroli)
- NIST SP 800-132 (hashiranje gesel)
- RFC 6238 (TOTP)
- RFC 4648 (Base32)

---

## LICENCA

ZAUPNO - Samo za pooblaščeno osebje

---

**GLOBAL INTELLIGENCE SECURITY COMMAND CENTER**
**TIER-0 NATIONAL SECURITY OPERATIONS CENTER**

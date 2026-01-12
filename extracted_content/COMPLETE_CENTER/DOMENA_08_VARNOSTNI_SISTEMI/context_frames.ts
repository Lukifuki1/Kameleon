import { ContextFrame } from '../../registry/types';

/**
 * DOMENA_08_VARNOSTNI_SISTEMI - Kontekstni okvirji
 * 
 * Delovni tokovi za:
 * - Red Team operacije (penetracijski test, reconnaissance, exploitation)
 * - Blue Team operacije (incident response, threat hunting, vulnerability management)
 * - DevSecOps (SAST, DAST, SBOM, compliance)
 * - Varnostna revizija in skladnost (ISO 27001, SOC 2, OWASP)
 */

export const CONTEXT_FRAMES: readonly ContextFrame[] = [
    // ============================================================================
    // RED TEAM DELOVNI TOKOVI
    // ============================================================================
    
    {
        id: 'KONTEKST_08_PENTEST_WEB_APP',
        displayNameSL: 'Penetracijski test spletne aplikacije',
        descriptionSL: 'Delovni tok za izvedbo penetracijskega testa spletne aplikacije po OWASP WSTG metodologiji.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['https://owasp.org/www-project-web-security-testing-guide/'],
        tags: ['pentest', 'web', 'owasp', 'redteam'],
        applicableDomains: ['DOMENA_08', 'DOMENA_01'],
        preconditions: [
            'Podpisan dogovor o obsegu in pravilih angažmaja (Rules of Engagement)',
            'Definirani cilji in obseg testiranja (scope)',
            'Pridobljena avtorizacija lastnika sistema',
            'Vzpostavljeno testno okolje ali dogovorjen cas testiranja produkcije',
            'Pripravljena orodja: ZAP, Nuclei, Burp Suite'
        ],
        postconditions: [
            'Generirano porocilo penetracijskega testa z vsemi odkritimi ranljivostmi',
            'Ranljivosti klasificirane po CVSS oceni in prioriteti',
            'Pripravljeni Dokaz-koncepta (DK) za kriticne ranljivosti',
            'Priporocila za odpravo ranljivosti',
            'Debrief sestanek z Blue Team za prenos znanja'
        ]
    },
    {
        id: 'KONTEKST_08_PENTEST_NETWORK',
        displayNameSL: 'Penetracijski test omrezne infrastrukture',
        descriptionSL: 'Delovni tok za izvedbo penetracijskega testa omrezne infrastrukture po PTES metodologiji.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['http://www.pentest-standard.org/'],
        tags: ['pentest', 'network', 'ptes', 'redteam'],
        applicableDomains: ['DOMENA_08', 'DOMENA_07'],
        preconditions: [
            'Podpisan dogovor o obsegu in pravilih angažmaja',
            'Definirani IP obsegi in izjeme',
            'Pridobljena avtorizacija za skeniranje in exploitation',
            'Pripravljena orodja: Nmap, Metasploit, Nuclei',
            'Dogovorjen cas testiranja za minimizacijo vpliva na produkcijo'
        ],
        postconditions: [
            'Generirano porocilo z odkritimi ranljivostmi v omrezni infrastrukturi',
            'Dokumentirani vektorji napada in lateral movement poti',
            'Identificirane napacne konfiguracije in izpostavljene storitve',
            'Priporocila za network segmentation in hardening',
            'Posodobljen inventar sredstev z varnostnimi ocenami'
        ]
    },
    {
        id: 'KONTEKST_08_RECONNAISSANCE',
        displayNameSL: 'Reconnaissance in OSINT zbiranje',
        descriptionSL: 'Delovni tok za zbiranje informacij o cilju pred penetracijskim testom.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['reconnaissance', 'osint', 'redteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Definiran cilj reconnaissance (domena, organizacija)',
            'Dolocen obseg pasivne vs aktivne reconnaissance',
            'Pripravljena OSINT orodja: Shodan, Censys, theHarvester',
            'Razumevanje pravnih omejitev za reconnaissance'
        ],
        postconditions: [
            'Zbrane informacije o domenah, IP naslovih, tehnologijah',
            'Identificirani zaposleni in njihove vloge (za social engineering)',
            'Odkrite izpostavljene storitve in potencialne vstopne tocke',
            'Pripravljen reconnaissance report kot vhod za threat modeling',
            'Posodobljen attack surface inventory'
        ]
    },
    {
        id: 'KONTEKST_08_SOCIAL_ENGINEERING',
        displayNameSL: 'Social engineering kampanja',
        descriptionSL: 'Delovni tok za izvedbo avtorizirane social engineering kampanje (phishing, vishing).',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['social-engineering', 'phishing', 'redteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Podpisana avtorizacija za social engineering testiranje',
            'Definirani cilji kampanje (click rate, credential harvest)',
            'Pripravljena phishing infrastruktura (domene, landing pages)',
            'Dogovorjen obseg (vsi zaposleni vs vzorec)',
            'Pripravljen eskalacijski postopek za prijavljene incidente'
        ],
        postconditions: [
            'Generirano porocilo s statistikami kampanje',
            'Identificirani zaposleni, ki potrebujejo dodatno usposabljanje',
            'Ocenjena ucinkovitost obstojecih tehnicnih kontrol (email filtering)',
            'Priporocila za izboljsanje security awareness programa',
            'Lessons learned za Blue Team'
        ]
    },
    
    // ============================================================================
    // BLUE TEAM DELOVNI TOKOVI
    // ============================================================================
    
    {
        id: 'KONTEKST_08_INCIDENT_RESPONSE',
        displayNameSL: 'Odziv na varnostni incident',
        descriptionSL: 'Delovni tok za odziv na varnostni incident po NIST SP 800-61 metodologiji.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final'],
        tags: ['incident-response', 'nist', 'blueteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Zaznan varnostni incident (alert, prijava, anomalija)',
            'Aktiviran Incident Response Team',
            'Dostop do SIEM, EDR in log virov',
            'Pripravljen incident response playbook',
            'Vzpostavljena komunikacijska veriga'
        ],
        postconditions: [
            'Incident klasificiran po resnosti in tipu',
            'Izvedeno zadrževanje (containment) za preprecitev sirjenja',
            'Izkoreninjenje (eradication) grožnje iz okolja',
            'Obnovitev (recovery) prizadetih sistemov',
            'Pripravljen post-incident report z lessons learned',
            'Posodobljeni playbooks in detekcijska pravila'
        ]
    },
    {
        id: 'KONTEKST_08_THREAT_HUNTING',
        displayNameSL: 'Proaktivno iskanje grozenj',
        descriptionSL: 'Delovni tok za proaktivno iskanje grozenj, ki so se izognile avtomatskim detekcijam.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['https://attack.mitre.org/'],
        tags: ['threat-hunting', 'mitre', 'blueteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Definirana hipoteza o potencialni grožnji',
            'Dostop do SIEM, EDR, network telemetry',
            'Threat intelligence o relevantnih TTP (MITRE ATT&CK)',
            'Baseline normalnega obnasanja v okolju',
            'Cas za poglobljeno analizo (ne med aktivnim incidentom)'
        ],
        postconditions: [
            'Hipoteza potrjena ali ovržena z dokazi',
            'Odkrite anomalije escalirane kot potencialni incidenti',
            'Nova detekcijska pravila za odkrite TTP',
            'Posodobljen threat model organizacije',
            'Dokumentiran hunting playbook za ponovitev'
        ]
    },
    {
        id: 'KONTEKST_08_VULNERABILITY_MANAGEMENT',
        displayNameSL: 'Upravljanje ranljivosti',
        descriptionSL: 'Delovni tok za neprekinjen proces identifikacije, prioritizacije in odprave ranljivosti.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['vulnerability-management', 'blueteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Konfiguriran vulnerability scanner (Trivy, Nessus, Qualys)',
            'Definiran inventar sredstev za skeniranje',
            'Vzpostavljen proces za prioritizacijo (CVSS, EPSS, asset criticality)',
            'Dogovorjeni SLA za odpravo ranljivosti po resnosti',
            'Integracija s ticketing sistemom za sledenje'
        ],
        postconditions: [
            'Generirano porocilo o ranljivostih z CVSS ocenami',
            'Ranljivosti prioritizirane glede na tveganje',
            'Ustvarjeni ticketi za odpravo kriticnih ranljivosti',
            'Verificirana odprava ranljivosti z re-scan',
            'Metrike: MTTR, vulnerability density, popravek coverage'
        ]
    },
    {
        id: 'KONTEKST_08_SOC_MONITORING',
        displayNameSL: 'SOC monitoring in triaza',
        descriptionSL: 'Delovni tok za 24/7 monitoring varnostnih dogodkov in triažo alertov v SOC.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['soc', 'monitoring', 'triage', 'blueteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Konfiguriran SIEM z log viri iz vseh kriticnih sistemov',
            'Definirana detekcijska pravila in use cases',
            'Vzpostavljen SOC z analitiki (Tier 1, 2, 3)',
            'Pripravljen runbook za pogoste alert tipe',
            'Integracija z ticketing in SOAR sistemom'
        ],
        postconditions: [
            'Alerti triažirani kot true positive, false positive ali benign',
            'True positive alerti escalirani kot incidenti',
            'False positive pravila tunirana za zmanjsanje suma',
            'Metrike: MTTD, MTTR, alert volume, escalation rate',
            'Shift handoff report za kontinuiteto'
        ]
    },
    {
        id: 'KONTEKST_08_FORENSIC_INVESTIGATION',
        displayNameSL: 'Digitalna forenzicna preiskava',
        descriptionSL: 'Delovni tok za zbiranje in analizo digitalnih dokazov po varnostnem incidentu.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'investigation', 'blueteam'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Identificiran sistem za forenzicno analizo',
            'Pripravljena forenzicna orodja (FTK, Autopsy, Volatility)',
            'Vzpostavljena chain of custody za dokaze',
            'Izolirani prizadeti sistemi (ne uniciti dokazov)',
            'Pravna avtorizacija za preiskavo'
        ],
        postconditions: [
            'Ustvarjene forenzicne slike diskov (bit-for-bit)',
            'Analiziran memory dump za malware in artefakte',
            'Rekonstruirana casovnica dogodkov (timeline)',
            'Identificirani IOC (Indicators of Compromise)',
            'Pripravljen forenzicni report za vodstvo/pravne namene'
        ]
    },
    
    // ============================================================================
    // DEVSECOPS DELOVNI TOKOVI
    // ============================================================================
    
    {
        id: 'KONTEKST_08_SAST_PIPELINE',
        displayNameSL: 'SAST v CI/CD pipeline',
        descriptionSL: 'Delovni tok za integracijo staticne analize varnosti v CI/CD pipeline.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['sast', 'cicd', 'devsecops'],
        applicableDomains: ['DOMENA_08', 'DOMENA_12'],
        preconditions: [
            'Konfiguriran SAST scanner (Semgrep, CodeQL)',
            'Definirana pravila za ciljne ranljivosti (OWASP, CWE)',
            'Integracija s CI/CD sistemom (GitHub Actions, GitLab CI)',
            'Dogovorjeni pragovi za blokiranje builda',
            'Proces za triažo in false positive management'
        ],
        postconditions: [
            'SAST scan izveden ob vsakem commit/PR',
            'Generirano SARIF porocilo z odkritimi ranljivostmi',
            'Build blokiran ce kriticne ranljivosti presežejo prag',
            'Ranljivosti prikazane v PR komentarjih',
            'Metrike: vulnerability density, fix rate, false positive rate'
        ]
    },
    {
        id: 'KONTEKST_08_SBOM_SUPPLY_CHAIN',
        displayNameSL: 'SBOM in varnost dobavne verige',
        descriptionSL: 'Delovni tok za generiranje SBOM in upravljanje varnosti dobavne verige.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['https://slsa.dev/'],
        tags: ['sbom', 'supply-chain', 'slsa', 'devsecops'],
        applicableDomains: ['DOMENA_08', 'DOMENA_12'],
        preconditions: [
            'Konfiguriran SBOM generator (Syft, Trivy)',
            'Definiran format SBOM (CycloneDX, SPDX)',
            'Integracija z vulnerability scanner za SBOM analizo',
            'Vzpostavljen artifact registry za shranjevanje SBOM',
            'Proces za odziv na nove CVE v odvisnostih'
        ],
        postconditions: [
            'Generiran SBOM za vsak build/release',
            'SBOM shranjen skupaj z artefaktom',
            'Identificirane ranljive komponente iz SBOM',
            'Alerti za nove CVE v obstojecih odvisnostih',
            'Skladnost z SLSA Level 2+ zahtevami'
        ]
    },
    {
        id: 'KONTEKST_08_SECRETS_SCANNING',
        displayNameSL: 'Skeniranje skrivnosti v kodi',
        descriptionSL: 'Delovni tok za odkrivanje in preprecevanje uhajanja skrivnosti v kodi.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['secrets', 'scanning', 'devsecops'],
        applicableDomains: ['DOMENA_08', 'DOMENA_12', 'DOMENA_14'],
        preconditions: [
            'Konfiguriran secrets scanner (Gitleaks, TruffleHog)',
            'Definirana pravila za tipe skrivnosti (API keys, passwords, tokens)',
            'Pre-commit hook za preventivo',
            'CI/CD integracija za detekcijo',
            'Proces za rotacijo izpostavljenih skrivnosti'
        ],
        postconditions: [
            'Preprečen commit skrivnosti s pre-commit hook',
            'Odkrite skrivnosti v CI/CD pipeline',
            'Izpostavljene skrivnosti takoj rotirane',
            'Git zgodovina ociscena (ce potrebno)',
            'Metrike: secrets detected, time to rotate'
        ]
    },
    
    // ============================================================================
    // SKLADNOST IN REVIZIJA
    // ============================================================================
    
    {
        id: 'KONTEKST_08_ISO27001_AUDIT',
        displayNameSL: 'ISO 27001 revizija',
        descriptionSL: 'Delovni tok za pripravo in izvedbo ISO 27001 certifikacijske revizije.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['https://www.iso.org/isoiec-27001-information-security.html'],
        tags: ['iso27001', 'audit', 'compliance'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Vzpostavljen ISMS (Information Security Management System)',
            'Dokumentirane politike, procedure in kontrole',
            'Izvedena notranja revizija in management review',
            'Odpravljena neskladja iz prejsnjih revizij',
            'Izbran akreditiran certifikacijski organ'
        ],
        postconditions: [
            'Uspesno opravljena Stage 1 (dokumentacijska) revizija',
            'Uspesno opravljena Stage 2 (implementacijska) revizija',
            'Pridobljen ISO 27001 certifikat',
            'Definiran plan za nadzorne revizije',
            'Vzpostavljen proces za nenehno izboljsevanje ISMS'
        ]
    },
    {
        id: 'KONTEKST_08_SOC2_AUDIT',
        displayNameSL: 'SOC 2 Type II revizija',
        descriptionSL: 'Delovni tok za pripravo in izvedbo SOC 2 Type II revizije.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: ['https://www.aicpa.org/soc2'],
        tags: ['soc2', 'audit', 'compliance'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Definirani Trust Services Criteria v obsegu (Security, Availability, ...)',
            'Dokumentirane kontrole za vsak kriterij',
            'Vzpostavljeni dokazi o delovanju kontrol (6-12 mesecev)',
            'Izvedena readiness assessment',
            'Izbran CPA revizor'
        ],
        postconditions: [
            'Zbrani dokazi za revizijsko obdobje',
            'Uspesno opravljena revizija brez materialnih izjem',
            'Pridobljeno SOC 2 Type II porocilo',
            'Porocilo deljeno s strankami pod NDA',
            'Plan za odpravo morebitnih priporocil'
        ]
    },
    {
        id: 'KONTEKST_08_SECURITY_POLICY_REVIEW',
        displayNameSL: 'Pregled varnostne politike',
        descriptionSL: 'Delovni tok za periodicni pregled in posodobitev varnostnih politik.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/context_frames.ts',
        domainId: 'DOMENA_08',
        type: 'CONTEXT_FRAME',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['policy', 'review', 'governance'],
        applicableDomains: ['DOMENA_08'],
        preconditions: [
            'Obstojecje varnostne politike za pregled',
            'Spremembe v regulatornem okolju ali poslovanju',
            'Lessons learned iz incidentov ali revizij',
            'Vhod od zainteresiranih strani (IT, pravna, HR)',
            'Dolocen lastnik politike'
        ],
        postconditions: [
            'Posodobljene politike z novimi zahtevami',
            'Odobritev vodstva za spremembe',
            'Komunikacija sprememb zaposlenim',
            'Posodobljeno usposabljanje ce potrebno',
            'Naslednji pregled nacrtan (letno)'
        ]
    }
];

import { Definition } from '../../registry/types';

/**
 * DOMENA_08_VARNOSTNI_SISTEMI - Formalne definicije
 * 
 * Definicije za:
 * - Kategorije in podkategorije (kriptografija, avtentikacija)
 * - Module (AES, RSA, TOTP)
 * - Artefakte (porocila, SBOM, politike)
 * - Orodja (Semgrep, Trivy, ZAP, Nuclei, Gitleaks)
 * - Standarde (OWASP, ISO 27001, SOC 2, NIST, CWE)
 * - Red Team koncepte (penetracijski test, reconnaissance, exploitation)
 * - Blue Team koncepte (incident response, threat hunting, SIEM, SOC)
 */

export const DEFINITIONS: readonly Definition[] = [
    // ============================================================================
    // KATEGORIJE
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_CAT_CRYPTO',
        displayNameSL: 'Definicija kategorije Kriptografija',
        descriptionSL: 'Formalna definicija kategorije kriptografije',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines'],
        tags: ['crypto', 'definition', 'category'],
        conceptId: 'KATEGORIJA_08_CRYPTO',
        formalDefinitionSL: 'Kriptografija je veda o varni komunikaciji v prisotnosti nasprotnikov. Vkljucuje simetricno kriptografijo (AES, ChaCha20), asimetricno kriptografijo (RSA, ECC, Ed25519), zgoscevalne funkcije (SHA-256, SHA-3), digitalne podpise in protokole za izmenjavo kljucev (Diffie-Hellman, ECDH). Kriptografija zagotavlja zaupnost, celovitost, avtentikacijo in nezanikljivost podatkov.'
    },
    {
        id: 'DEFINICIJA_08_CAT_AUTH',
        displayNameSL: 'Definicija kategorije Avtentikacija',
        descriptionSL: 'Formalna definicija kategorije avtentikacije',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://pages.nist.gov/800-63-3/'],
        tags: ['auth', 'definition', 'category'],
        conceptId: 'KATEGORIJA_08_AUTH',
        formalDefinitionSL: 'Avtentikacija je proces preverjanja identitete uporabnika, naprave ali sistema. Vkljucuje enofaktorsko avtentikacijo (geslo), vecfaktorsko avtentikacijo (MFA), biometricno avtentikacijo in avtentikacijo brez gesla (WebAuthn, FIDO2). NIST SP 800-63 definira tri nivoje zagotovila avtentikacije (AAL1, AAL2, AAL3).'
    },
    
    // ============================================================================
    // PODKATEGORIJE
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_SUBCAT_SYMMETRIC',
        displayNameSL: 'Definicija podkategorije Simetricna kriptografija',
        descriptionSL: 'Formalna definicija podkategorije simetricne kriptografije',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['symmetric', 'definition', 'subcategory'],
        conceptId: 'PODKATEGORIJA_08_SYMMETRIC',
        formalDefinitionSL: 'Simetricna kriptografija uporablja isti kljuc za sifriranje in desifriranje. AES (Advanced Encryption Standard) je industrijski standard z velikostmi kljucev 128, 192 ali 256 bitov. Nacini delovanja vkljucujejo CBC, CTR, GCM (z avtentikacijo). ChaCha20-Poly1305 je alternativa za programsko implementacijo. Simetricna kriptografija je hitra, a zahteva varno izmenjavo kljucev.'
    },
    {
        id: 'DEFINICIJA_08_SUBCAT_ASYMMETRIC',
        displayNameSL: 'Definicija podkategorije Asimetricna kriptografija',
        descriptionSL: 'Formalna definicija podkategorije asimetricne kriptografije',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['asymmetric', 'definition', 'subcategory'],
        conceptId: 'PODKATEGORIJA_08_ASYMMETRIC',
        formalDefinitionSL: 'Asimetricna kriptografija uporablja par kljucev: javni kljuc za sifriranje in zasebni kljuc za desifriranje. RSA temelji na tezavnosti faktorizacije velikih stevil. ECC (Elliptic Curve Cryptography) ponuja enako varnost z manjsimi kljuci. Ed25519 je hitra shema za digitalne podpise. Asimetricna kriptografija omogoca varno izmenjavo kljucev in digitalne podpise.'
    },
    {
        id: 'DEFINICIJA_08_SUBCAT_MFA',
        displayNameSL: 'Definicija podkategorije Vecfaktorska avtentikacija',
        descriptionSL: 'Formalna definicija podkategorije vecfaktorske avtentikacije',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://fidoalliance.org/'],
        tags: ['mfa', 'definition', 'subcategory'],
        conceptId: 'PODKATEGORIJA_08_MFA',
        formalDefinitionSL: 'Vecfaktorska avtentikacija (MFA) zahteva vec neodvisnih faktorjev: nekaj kar ves (geslo), nekaj kar imas (telefon, varnostni kljuc) in nekaj kar si (biometrija). TOTP (Time-based One-Time Password) generira enkratna gesla na podlagi casa. FIDO2/WebAuthn omogoca avtentikacijo brez gesla s kriptografskimi kljuci. MFA bistveno zmanjsa tveganje prevzema racuna.'
    },
    
    // ============================================================================
    // MODULI
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_MOD_AES',
        displayNameSL: 'Definicija modula AES',
        descriptionSL: 'Formalna definicija modula AES',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://csrc.nist.gov/publications/detail/fips/197/final'],
        tags: ['aes', 'definition', 'module'],
        conceptId: 'MODUL_08_AES',
        formalDefinitionSL: 'AES (Advanced Encryption Standard) je simetricni blokovni sifrer, sprejet kot FIPS 197. Deluje na 128-bitnih blokih z velikostmi kljucev 128, 192 ali 256 bitov. Algoritem izvaja vec rund substitucije, permutacije in mesanja. AES-GCM (Galois/Counter Mode) zagotavlja avtenticirano sifriranje. AES je industrijski standard za zaupnost podatkov.'
    },
    {
        id: 'DEFINICIJA_08_MOD_RSA',
        displayNameSL: 'Definicija modula RSA',
        descriptionSL: 'Formalna definicija modula RSA',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://datatracker.ietf.org/doc/html/rfc8017'],
        tags: ['rsa', 'definition', 'module'],
        conceptId: 'MODUL_08_RSA',
        formalDefinitionSL: 'RSA (Rivest-Shamir-Adleman) je asimetricni kriptografski algoritem za sifriranje in digitalne podpise. Varnost temelji na tezavnosti faktorizacije produkta dveh velikih prastevil. Priporocena velikost kljuca je vsaj 2048 bitov (3072+ za dolgorocno varnost). OAEP padding preprecuje napade na sifriranje, PSS padding pa na podpise. RSA se pogosto uporablja za hibridno sifriranje.'
    },
    {
        id: 'DEFINICIJA_08_MOD_TOTP',
        displayNameSL: 'Definicija modula TOTP',
        descriptionSL: 'Formalna definicija modula TOTP',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://datatracker.ietf.org/doc/html/rfc6238'],
        tags: ['totp', 'definition', 'module'],
        conceptId: 'MODUL_08_TOTP',
        formalDefinitionSL: 'TOTP (Time-based One-Time Password) je algoritem za generiranje enkratnih gesel na podlagi casa (RFC 6238). Uporablja HMAC z deljeno skrivnostjo in trenutnim casom. Gesla so veljavna 30 sekund (privzeto). TOTP je osnova za Google Authenticator, Microsoft Authenticator in druge MFA aplikacije. Zagotavlja drugi faktor avtentikacije brez potrebe po omrezni povezavi.'
    },
    
    // ============================================================================
    // ARTEFAKTI
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_ART_SBOM',
        displayNameSL: 'Definicija SBOM',
        descriptionSL: 'Formalna definicija artefakta SBOM',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://www.cisa.gov/sbom'],
        tags: ['sbom', 'definition', 'artifact'],
        conceptId: 'ARTEFAKT_08_SBOM',
        formalDefinitionSL: 'SBOM (Software Bill of Materials) je formalni zapis vseh komponent, knjiznic in odvisnosti v programski opremi. Formati vkljucujejo CycloneDX in SPDX. SBOM omogoca sledljivost dobavne verige, identifikacijo ranljivih komponent in skladnost z licencami. Executive Order 14028 zahteva SBOM za programsko opremo za zvezno vlado ZDA. SBOM je temelj za upravljanje tveganj v dobavni verigi.'
    },
    {
        id: 'DEFINICIJA_08_ART_SAST_REPORT',
        displayNameSL: 'Definicija SAST porocila',
        descriptionSL: 'Formalna definicija artefakta SAST porocila',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['sast', 'definition', 'artifact'],
        conceptId: 'ARTEFAKT_08_SAST_REPORT',
        formalDefinitionSL: 'SAST porocilo (Static Application Security Testing) vsebuje rezultate staticne analize izvorne kode. Identificira ranljivosti brez izvajanja kode: SQL injection, XSS, buffer overflow, hardcoded secrets. Format SARIF (Static Analysis Results Interchange Format) omogoca interoperabilnost med orodji. SAST je del Blue Team preventivnih kontrol in shift-left varnosti.'
    },
    {
        id: 'DEFINICIJA_08_ART_DAST_REPORT',
        displayNameSL: 'Definicija DAST porocila',
        descriptionSL: 'Formalna definicija artefakta DAST porocila',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['dast', 'definition', 'artifact'],
        conceptId: 'ARTEFAKT_08_DAST_REPORT',
        formalDefinitionSL: 'DAST porocilo (Dynamic Application Security Testing) vsebuje rezultate dinamicne analize aplikacije med izvajanjem. Simulira napade na zivo aplikacijo: injection, broken authentication, security misconfiguration. DAST odkriva ranljivosti, ki jih SAST ne more (runtime issues, configuration errors). DAST je del Red Team reconnaissance in Blue Team validacije.'
    },
    {
        id: 'DEFINICIJA_08_ART_PENTEST_REPORT',
        displayNameSL: 'Definicija porocila penetracijskega testa',
        descriptionSL: 'Formalna definicija artefakta porocila penetracijskega testa',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['http://www.pentest-standard.org/'],
        tags: ['pentest', 'definition', 'artifact', 'redteam'],
        conceptId: 'ARTEFAKT_08_PENTEST_REPORT',
        formalDefinitionSL: 'Porocilo penetracijskega testa dokumentira rezultate avtoriziranega simuliranega napada na sistem. Vkljucuje obseg, metodologijo (PTES, OWASP WSTG), odkrite ranljivosti, dokaze izkoriščanja (DK), oceno tveganja (CVSS) in priporocila za odpravo. Pentest report je kljucni Red Team deliverable in vhod za Blue Team remediation.'
    },
    {
        id: 'DEFINICIJA_08_ART_VULNERABILITY_REPORT',
        displayNameSL: 'Definicija porocila o ranljivostih',
        descriptionSL: 'Formalna definicija artefakta porocila o ranljivostih',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['vulnerability', 'definition', 'artifact'],
        conceptId: 'ARTEFAKT_08_VULNERABILITY_REPORT',
        formalDefinitionSL: 'Porocilo o ranljivostih vsebuje seznam identificiranih ranljivosti v odvisnostih, kontejnerjih ali infrastrukturi. Vkljucuje CVE identifikatorje, CVSS ocene, prizadete komponente in razpolozljive popravke. Trivy, Grype in Snyk generirajo taksna porocila. Vulnerability report je vhod za Blue Team prioritizacijo in remediation.'
    },
    
    // ============================================================================
    // ORODJA
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_TOOL_SEMGREP',
        displayNameSL: 'Definicija orodja Semgrep',
        descriptionSL: 'Formalna definicija orodja Semgrep',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://semgrep.dev/'],
        tags: ['semgrep', 'definition', 'tool', 'blueteam'],
        conceptId: 'ORODJE_08_SEMGREP',
        formalDefinitionSL: 'Semgrep je odprtokodno SAST orodje za staticno analizo kode. Uporablja vzorce podobne kodi za iskanje ranljivosti, napak in stilskih problemov. Podpira 30+ programskih jezikov. Semgrep Registry vsebuje tisocere pravila za OWASP Top 10, CWE Top 25 in specificne ogrodja. Semgrep je kljucno Blue Team orodje za preventivno varnost v CI/CD.'
    },
    {
        id: 'DEFINICIJA_08_TOOL_TRIVY',
        displayNameSL: 'Definicija orodja Trivy',
        descriptionSL: 'Formalna definicija orodja Trivy',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://trivy.dev/'],
        tags: ['trivy', 'definition', 'tool', 'blueteam'],
        conceptId: 'ORODJE_08_TRIVY',
        formalDefinitionSL: 'Trivy je odprtokodni vulnerability scanner za kontejnerje, datotecne sisteme, Git repozitorije in Kubernetes. Skenira OS pakete, jezikovne odvisnosti, IaC napake in izpostavljene skrivnosti. Podpira SBOM generiranje in VEX (Vulnerability Exploitability eXchange). Trivy je kljucno Blue Team orodje za upravljanje ranljivosti v cloud-native okoljih.'
    },
    {
        id: 'DEFINICIJA_08_TOOL_ZAP',
        displayNameSL: 'Definicija orodja OWASP ZAP',
        descriptionSL: 'Formalna definicija orodja OWASP ZAP',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://www.zaproxy.org/'],
        tags: ['zap', 'definition', 'tool', 'redteam'],
        conceptId: 'ORODJE_08_ZAP',
        formalDefinitionSL: 'OWASP ZAP (Zed Attack Proxy) je odprtokodno DAST orodje za dinamicno testiranje varnosti spletnih aplikacij. Deluje kot proxy med brskalnikom in aplikacijo, prestrezanje in spreminjanje prometa. Vkljucuje aktivno skeniranje, fuzzing, spider in API skeniranje. ZAP je kljucno Red Team orodje za reconnaissance in exploitation spletnih aplikacij.'
    },
    {
        id: 'DEFINICIJA_08_TOOL_NUCLEI',
        displayNameSL: 'Definicija orodja Nuclei',
        descriptionSL: 'Formalna definicija orodja Nuclei',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://nuclei.projectdiscovery.io/'],
        tags: ['nuclei', 'definition', 'tool', 'redteam'],
        conceptId: 'ORODJE_08_NUCLEI',
        formalDefinitionSL: 'Nuclei je hitro, prilagodljivo orodje za vulnerability scanning na podlagi predlog (templates). Nuclei Templates so YAML datoteke, ki definirajo HTTP/DNS/TCP zahteve in pogoje za detekcijo ranljivosti. Skupnost vzdrzuje 6000+ predlog za CVE, misconfigurations in exposed panels. Nuclei je kljucno Red Team orodje za avtomatizirano reconnaissance in vulnerability validation.'
    },
    {
        id: 'DEFINICIJA_08_TOOL_GITLEAKS',
        displayNameSL: 'Definicija orodja Gitleaks',
        descriptionSL: 'Formalna definicija orodja Gitleaks',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://gitleaks.io/'],
        tags: ['gitleaks', 'definition', 'tool', 'blueteam'],
        conceptId: 'ORODJE_08_GITLEAKS',
        formalDefinitionSL: 'Gitleaks je orodje za odkrivanje izpostavljenih skrivnosti (secrets) v Git repozitorijih. Skenira kodo in Git zgodovino za API kljuce, gesla, tokene in certifikate. Podpira pre-commit hooks za preventivo in CI/CD integracijo. Gitleaks je kljucno Blue Team orodje za preprecevanje uhajanja poverilnic in skladnost z varnostnimi politikami.'
    },
    {
        id: 'DEFINICIJA_08_TOOL_COSIGN',
        displayNameSL: 'Definicija orodja Cosign',
        descriptionSL: 'Formalna definicija orodja Cosign',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://github.com/sigstore/cosign'],
        tags: ['cosign', 'definition', 'tool'],
        conceptId: 'ORODJE_08_COSIGN',
        formalDefinitionSL: 'Cosign je orodje za podpisovanje in preverjanje kontejnerskih slik in drugih OCI artefaktov. Del projekta Sigstore, ki ponuja keyless signing z OIDC identitetami. Podpisi se shranijo v OCI registry ali Rekor transparency log. Cosign omogoca supply chain security z verifikacijo izvora in celovitosti artefaktov.'
    },
    
    // ============================================================================
    // STANDARDI
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_STD_OWASP_TOP10',
        displayNameSL: 'Definicija standarda OWASP Top 10',
        descriptionSL: 'Formalna definicija standarda OWASP Top 10',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://owasp.org/www-project-top-ten/'],
        tags: ['owasp', 'definition', 'standard'],
        conceptId: 'STANDARD_08_OWASP_TOP10',
        formalDefinitionSL: 'OWASP Top 10 je seznam desetih najkritičnejših varnostnih tveganj za spletne aplikacije. Verzija 2021 vkljucuje: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable Components, A07 Authentication Failures, A08 Software and Data Integrity Failures, A09 Security Logging Failures, A10 SSRF. OWASP Top 10 je industrijski standard za varnostno testiranje.'
    },
    {
        id: 'DEFINICIJA_08_STD_ISO27001',
        displayNameSL: 'Definicija standarda ISO 27001',
        descriptionSL: 'Formalna definicija standarda ISO 27001',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://www.iso.org/isoiec-27001-information-security.html'],
        tags: ['iso27001', 'definition', 'standard'],
        conceptId: 'STANDARD_08_ISO27001',
        formalDefinitionSL: 'ISO/IEC 27001 je mednarodni standard za sisteme upravljanja informacijske varnosti (ISMS). Definira zahteve za vzpostavitev, implementacijo, vzdrzevanje in nenehno izboljsevanje ISMS. Annex A vsebuje 93 kontrol v 4 kategorijah: organizacijske, kadrovske, fizicne in tehnoloske. Certifikacija ISO 27001 dokazuje zavezanost organizacije k informacijski varnosti.'
    },
    {
        id: 'DEFINICIJA_08_STD_SOC2',
        displayNameSL: 'Definicija standarda SOC 2',
        descriptionSL: 'Formalna definicija standarda SOC 2',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://www.aicpa.org/soc2'],
        tags: ['soc2', 'definition', 'standard'],
        conceptId: 'STANDARD_08_SOC2',
        formalDefinitionSL: 'SOC 2 (Service Organization Control 2) je revizijski standard za ponudnike storitev, ki obdelujejo podatke strank. Temelji na Trust Services Criteria: varnost, razpolozljivost, celovitost obdelave, zaupnost in zasebnost. SOC 2 Type I ocenjuje nacrt kontrol, Type II pa ucinkovitost kontrol skozi cas (obicajno 6-12 mesecev). SOC 2 je de facto standard za SaaS ponudnike.'
    },
    {
        id: 'DEFINICIJA_08_STD_NIST_800_53',
        displayNameSL: 'Definicija standarda NIST 800-53',
        descriptionSL: 'Formalna definicija standarda NIST SP 800-53',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final'],
        tags: ['nist', 'definition', 'standard'],
        conceptId: 'STANDARD_08_NIST_800_53',
        formalDefinitionSL: 'NIST SP 800-53 je katalog varnostnih in zasebnostnih kontrol za zvezne informacijske sisteme ZDA. Revision 5 vsebuje 1000+ kontrol v 20 druzinah: Access Control, Audit, Configuration Management, Incident Response, itd. Kontrole so razvrscene po vplivu (Low, Moderate, High). NIST 800-53 je osnova za FedRAMP in pogosto referenciran v zasebnem sektorju.'
    },
    {
        id: 'DEFINICIJA_08_STD_CWE_SANS_25',
        displayNameSL: 'Definicija standarda CWE/SANS Top 25',
        descriptionSL: 'Formalna definicija standarda CWE/SANS Top 25',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://cwe.mitre.org/top25/'],
        tags: ['cwe', 'definition', 'standard'],
        conceptId: 'STANDARD_08_CWE_SANS_25',
        formalDefinitionSL: 'CWE/SANS Top 25 je seznam 25 najnevarnejsih programskih napak. CWE (Common Weakness Enumeration) je taksonomija varnostnih slabosti. Top 25 vkljucuje: Out-of-bounds Write (CWE-787), Cross-site Scripting (CWE-79), SQL Injection (CWE-89), Use After Free (CWE-416), OS Command Injection (CWE-78). CWE/SANS Top 25 je osnova za SAST pravila in secure coding guidelines.'
    },
    
    // ============================================================================
    // RED TEAM KONCEPTI
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_CONCEPT_REDTEAM',
        displayNameSL: 'Definicija koncepta Red Team',
        descriptionSL: 'Formalna definicija koncepta Red Team',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://attack.mitre.org/'],
        tags: ['redteam', 'definition', 'concept'],
        conceptId: 'DOMENA_08',
        formalDefinitionSL: 'Red Team je skupina varnostnih strokovnjakov, ki simulira napade na organizacijo za testiranje obrambnih zmoznosti. Red Team operacije vkljucujejo reconnaissance, initial access, privilege escalation, lateral movement, persistence in exfiltration. MITRE ATT&CK framework kategorizira Red Team taktike in tehnike. Red Team deluje neodvisno od Blue Team za realisticno oceno varnosti.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_PENTEST',
        displayNameSL: 'Definicija koncepta Penetracijski test',
        descriptionSL: 'Formalna definicija koncepta penetracijskega testa',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['http://www.pentest-standard.org/'],
        tags: ['pentest', 'definition', 'concept', 'redteam'],
        conceptId: 'KORAK_08_PENTEST',
        formalDefinitionSL: 'Penetracijski test (pentest) je avtoriziran simuliran napad na sistem za odkrivanje ranljivosti. PTES (Penetration Testing Execution Standard) definira faze: pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, reporting. Tipi vkljucujejo black-box, white-box in gray-box. Pentest je kljucna Red Team aktivnost za validacijo varnosti.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_RECONNAISSANCE',
        displayNameSL: 'Definicija koncepta Reconnaissance',
        descriptionSL: 'Formalna definicija koncepta reconnaissance',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['reconnaissance', 'definition', 'concept', 'redteam'],
        conceptId: 'KORAK_08_DAST',
        formalDefinitionSL: 'Reconnaissance (izvidnistvo) je zacetna faza napada, kjer napadalec zbira informacije o cilju. Pasivna reconnaissance vkljucuje OSINT (Open Source Intelligence): DNS, WHOIS, socialna omrezja, job postings. Aktivna reconnaissance vkljucuje port scanning, service enumeration, vulnerability scanning. Reconnaissance je temelj za nacrtovanje napada in identifikacijo napadne povrsine.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_EXPLOITATION',
        displayNameSL: 'Definicija koncepta Exploitation',
        descriptionSL: 'Formalna definicija koncepta exploitation',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['exploitation', 'definition', 'concept', 'redteam'],
        conceptId: 'ARTEFAKT_08_PENTEST_REPORT',
        formalDefinitionSL: 'Exploitation je faza napada, kjer napadalec izkoristi ranljivost za pridobitev dostopa ali izvrsitev kode. Vkljucuje izkoriščanje znanih CVE, zero-day ranljivosti, napacnih konfiguracij in logicnih napak. Dokaz-koncepta (DK) demonstrira izkoriščljivost ranljivosti. Exploitation je jedro Red Team operacij in validira resnost ranljivosti.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_SOCIAL_ENGINEERING',
        displayNameSL: 'Definicija koncepta Social Engineering',
        descriptionSL: 'Formalna definicija koncepta social engineering',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['social-engineering', 'definition', 'concept', 'redteam'],
        conceptId: 'ARTEFAKT_08_SECURITY_POLICY',
        formalDefinitionSL: 'Social engineering je manipulacija ljudi za razkritje zaupnih informacij ali izvajanje dejanj. Tehnike vkljucujejo phishing (e-mail), vishing (telefon), smishing (SMS), pretexting, baiting in tailgating. Red Team pogosto vkljucuje social engineering za testiranje cloveskega faktorja. Ozavescanje zaposlenih je kljucna Blue Team obramba proti social engineering.'
    },
    
    // ============================================================================
    // BLUE TEAM KONCEPTI
    // ============================================================================
    
    {
        id: 'DEFINICIJA_08_CONCEPT_BLUETEAM',
        displayNameSL: 'Definicija koncepta Blue Team',
        descriptionSL: 'Formalna definicija koncepta Blue Team',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['blueteam', 'definition', 'concept'],
        conceptId: 'KORAK_08_REMEDIATION',
        formalDefinitionSL: 'Blue Team je skupina varnostnih strokovnjakov, odgovornih za obrambo organizacije pred napadi. Blue Team aktivnosti vkljucujejo monitoring, detekcijo, odziv na incidente, threat hunting, vulnerability management in security hardening. Blue Team vzdrzuje SIEM, EDR, IDS/IPS in druge obrambne sisteme. Blue Team sodeluje z Red Team v purple team vajah za izboljsanje obrambnih zmoznosti.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_INCIDENT_RESPONSE',
        displayNameSL: 'Definicija koncepta Incident Response',
        descriptionSL: 'Formalna definicija koncepta incident response',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final'],
        tags: ['incident-response', 'definition', 'concept', 'blueteam'],
        conceptId: 'VERIFIKACIJA_08_COMPLIANCE_AUDIT',
        formalDefinitionSL: 'Incident Response je proces odzivanja na varnostne incidente. NIST SP 800-61 definira faze: priprava, detekcija in analiza, zadrževanje/izkoreninjenje/obnovitev, post-incident aktivnosti. Incident Response Team (IRT/CSIRT) koordinira odziv. Playbooks definirajo standardne postopke za pogoste incidente. Incident Response je kljucna Blue Team zmoznost za minimizacijo skode.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_THREAT_HUNTING',
        displayNameSL: 'Definicija koncepta Threat Hunting',
        descriptionSL: 'Formalna definicija koncepta threat hunting',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['threat-hunting', 'definition', 'concept', 'blueteam'],
        conceptId: 'VERIFIKACIJA_08_SAST_REVIEW',
        formalDefinitionSL: 'Threat Hunting je proaktivno iskanje grozenj, ki so se izognile avtomatskim detekcijam. Temelji na hipotezah o napadalcevem obnasanju, MITRE ATT&CK tehnikah in threat intelligence. Threat hunters analizirajo loge, mrezni promet, endpoint telemetrijo in anomalije. Threat Hunting dopolnjuje reaktivno detekcijo in odkriva napredne vztrajne grožnje (APT).'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_SIEM',
        displayNameSL: 'Definicija koncepta SIEM',
        descriptionSL: 'Formalna definicija koncepta SIEM',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['siem', 'definition', 'concept', 'blueteam'],
        conceptId: 'ARTEFAKT_08_COMPLIANCE_REPORT',
        formalDefinitionSL: 'SIEM (Security Information and Event Management) je sistem za zbiranje, normalizacijo, korelacijo in analizo varnostnih dogodkov iz razlicnih virov. SIEM omogoca centraliziran pregled varnostnega stanja, detekcijo grozenj z pravili in ML, forenzicno analizo in skladnostno porocanje. Primeri: Splunk, Microsoft Sentinel, Elastic SIEM. SIEM je jedro Blue Team Security Operations Center (SOC).'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_SOC',
        displayNameSL: 'Definicija koncepta SOC',
        descriptionSL: 'Formalna definicija koncepta SOC',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['soc', 'definition', 'concept', 'blueteam'],
        conceptId: 'VERIFIKACIJA_08_VULN_ASSESSMENT',
        formalDefinitionSL: 'SOC (Security Operations Center) je centralizirana enota za monitoring, detekcijo in odziv na varnostne incidente 24/7. SOC analitiki so razvrsceni v nivoje (Tier 1-3) glede na izkusnje. SOC uporablja SIEM, SOAR, EDR, threat intelligence in playbooks. SOC metrike vkljucujejo MTTD (Mean Time to Detect) in MTTR (Mean Time to Respond). SOC je operativno jedro Blue Team.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_VULNERABILITY_MANAGEMENT',
        displayNameSL: 'Definicija koncepta Vulnerability Management',
        descriptionSL: 'Formalna definicija koncepta vulnerability management',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['vulnerability-management', 'definition', 'concept', 'blueteam'],
        conceptId: 'KORAK_08_VULN_SCAN',
        formalDefinitionSL: 'Vulnerability Management je neprekinjen proces identifikacije, klasifikacije, prioritizacije in odprave ranljivosti. Vkljucuje skeniranje (Trivy, Nessus, Qualys), oceno tveganja (CVSS, EPSS), prioritizacijo (kriticnost, izkoriščljivost, izpostavljenost) in remediation (updating, workarounds, compensating controls). Vulnerability Management je temeljna Blue Team disciplina za zmanjsevanje napadne povrsine.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_FORENSICS',
        displayNameSL: 'Definicija koncepta Digital Forensics',
        descriptionSL: 'Formalna definicija koncepta digital forensics',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'definition', 'concept', 'blueteam'],
        conceptId: 'EVI_08_COMPLIANCE_REPORT',
        formalDefinitionSL: 'Digital Forensics je zbiranje, ohranjanje in analiza digitalnih dokazov za preiskavo varnostnih incidentov. Vkljucuje disk forensics (imaging, file carving), memory forensics (volatility), network forensics (packet capture) in log analysis. Chain of custody zagotavlja celovitost dokazov. Digital Forensics je kljucna Blue Team zmoznost za razumevanje obsega in vzroka incidenta.'
    },
    {
        id: 'DEFINICIJA_08_CONCEPT_ZERO_TRUST',
        displayNameSL: 'Definicija koncepta Zero Trust',
        descriptionSL: 'Formalna definicija koncepta Zero Trust',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/definitions.ts',
        domainId: 'DOMENA_08',
        type: 'DEFINITION',
        version: '1.0.0',
        hash: '',
        links: ['https://csrc.nist.gov/publications/detail/sp/800-207/final'],
        tags: ['zero-trust', 'definition', 'concept'],
        conceptId: 'ARTEFAKT_08_SECURITY_POLICY',
        formalDefinitionSL: 'Zero Trust je varnostni model, ki predpostavlja, da nobeni entiteti (uporabniku, napravi, omrezju) ni mogoce zaupati privzeto. Nacela vkljucujejo: verify explicitly, use least privilege access, assume breach. NIST SP 800-207 definira Zero Trust Architecture. Implementacija vkljucuje mikrosegmentacijo, MFA, continuous verification in encryption everywhere. Zero Trust je sodobni pristop k varnostni arhitekturi.'
    }
];

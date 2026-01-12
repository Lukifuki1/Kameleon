/**
 * VARNOSTNI_SISTEMI TEMPLATE REGISTRY
 * ====================================
 * 
 * Deterministična povezava med 79 predlogami in domensko strukturo.
 * Statični uvozi z fiksnim vrstnim redom.
 * Brez runtime odkrivanja, brez dinamičnih uvozov.
 * 
 * INDUSTRIJSKA SKLADNOST:
 * - DO-178C (letalstvo)
 * - IEC 61508 (funkcionalna varnost)
 * - ISO 26262 (avtomobilska industrija)
 * - MIL-STD-882E (vojaški sistemi)
 */

// ============================================================================
// TIPI
// ============================================================================

export type TemplateCategory = 
    | 'ANALYTICS'
    | 'ANTIFORENSICS'
    | 'BIOMETRIC'
    | 'COMMUNICATIONS'
    | 'CRAWLER'
    | 'CRYPTOGRAPHY'
    | 'DEFENSE'
    | 'DEFENSIVE'
    | 'DETECTION'
    | 'EMSEC'
    | 'FORENSICS'
    | 'INTELLIGENCE'
    | 'MALWARE'
    | 'MONITORING'
    | 'NETWORK'
    | 'OBSERVABILITY'
    | 'OFFENSIVE'
    | 'OPERATIONS'
    | 'RELIABILITY'
    | 'RESEARCH'
    | 'RESPONSE'
    | 'SCANNER'
    | 'SEARCH'
    | 'SECURITY'
    | 'SPECIALIZED'
    | 'STEALTH'
    | 'SUPPLY_CHAIN'
    | 'SURVEILLANCE'
    | 'UI'
    | 'VISUALIZATION'
    | 'VULNERABILITY'
    | 'WARFARE';

export type OperationType = 
    | 'RED_TEAM'
    | 'BLUE_TEAM'
    | 'PURPLE_TEAM'
    | 'THREAT_INTEL'
    | 'FORENSICS'
    | 'MALWARE_ANALYSIS'
    | 'VULNERABILITY_MGMT'
    | 'INCIDENT_RESPONSE'
    | 'SIGINT'
    | 'FININT'
    | 'OSINT'
    | 'HUMINT'
    | 'COUNTER_INTEL'
    | 'CYBER_WARFARE'
    | 'COVERT_OPS'
    | 'INFRASTRUCTURE';

export type ClassificationLevel = 
    | 'UNCLASSIFIED'
    | 'CONFIDENTIAL'
    | 'SECRET'
    | 'TOP_SECRET'
    | 'TOP_SECRET_SCI';

export interface TemplateMapping {
    readonly templateId: string;
    readonly templatePath: string;
    readonly templateName: string;
    readonly category: TemplateCategory;
    readonly operationTypes: readonly OperationType[];
    readonly domainModules: readonly string[];
    readonly classificationLevel: ClassificationLevel;
    readonly complianceStandards: readonly string[];
    readonly description: string;
}

export interface CategoryMapping {
    readonly category: TemplateCategory;
    readonly templates: readonly string[];
    readonly domainModules: readonly string[];
    readonly description: string;
}

// ============================================================================
// TEMPLATE -> DOMAIN MAPPING (79 predlog)
// ============================================================================

export const TEMPLATE_MAPPINGS: readonly TemplateMapping[] = [
    // ANALYTICS
    {
        templateId: 'insider-threat-analytics',
        templatePath: 'src/analytics/insider-threat-analytics.ts.predloga',
        templateName: 'Insider Threat Analytics',
        category: 'ANALYTICS',
        operationTypes: ['BLUE_TEAM', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Analitika notranjih groženj in vedenjska analiza'
    },
    
    // ANTIFORENSICS
    {
        templateId: 'data-destruction',
        templatePath: 'src/antiforensics/data-destruction.ts.predloga',
        templateName: 'Data Destruction',
        category: 'ANTIFORENSICS',
        operationTypes: ['COVERT_OPS', 'RED_TEAM'],
        domainModules: ['MODUL_08_SECURE_RANDOM'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Varno uničenje podatkov in anti-forenzika'
    },
    
    // BIOMETRIC
    {
        templateId: 'biometric-security',
        templatePath: 'src/biometric/biometric-security.ts.predloga',
        templateName: 'Biometric Security',
        category: 'BIOMETRIC',
        operationTypes: ['BLUE_TEAM', 'INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AUTH'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['ISO_27001', 'NIST_800-53'],
        description: 'Biometrična varnost in avtentikacija'
    },
    
    // COMMUNICATIONS
    {
        templateId: 'covert-communications',
        templatePath: 'src/communications/covert-communications.ts.predloga',
        templateName: 'Covert Communications',
        category: 'COMMUNICATIONS',
        operationTypes: ['COVERT_OPS', 'RED_TEAM', 'SIGINT'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Prikrite komunikacije in steganografija'
    },
    
    // CRAWLER
    {
        templateId: 'web-crawler-engine',
        templatePath: 'src/crawler/web-crawler-engine.ts.predloga',
        templateName: 'Web Crawler Engine',
        category: 'CRAWLER',
        operationTypes: ['OSINT', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Spletno pajkanje in indeksiranje'
    },
    
    // CRYPTOGRAPHY
    {
        templateId: 'cryptography',
        templatePath: 'src/cryptography/cryptography.ts.predloga',
        templateName: 'Cryptography',
        category: 'CRYPTOGRAPHY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA', 'MODUL_08_HASHING', 'MODUL_08_KEY_DERIVATION'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['FIPS_140-3', 'NIST_800-53'],
        description: 'Kriptografske operacije'
    },
    {
        templateId: 'quantum-cryptography',
        templatePath: 'src/cryptography/quantum-cryptography.ts.predloga',
        templateName: 'Quantum Cryptography',
        category: 'CRYPTOGRAPHY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA', 'MODUL_08_KEY_DERIVATION'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['NIST_PQC', 'MIL-STD-882E'],
        description: 'Post-kvantna kriptografija'
    },
    
    // DEFENSE
    {
        templateId: 'active-defense-operations',
        templatePath: 'src/defense/active-defense-operations.ts.predloga',
        templateName: 'Active Defense Operations',
        category: 'DEFENSE',
        operationTypes: ['BLUE_TEAM', 'PURPLE_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E', 'NIST_800-53'],
        description: 'Aktivna obramba in kontranapadi'
    },
    {
        templateId: 'adversary-disruption',
        templatePath: 'src/defense/adversary-disruption.ts.predloga',
        templateName: 'Adversary Disruption',
        category: 'DEFENSE',
        operationTypes: ['BLUE_TEAM', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Disrupcija nasprotnikove infrastrukture'
    },
    {
        templateId: 'threat-neutralization',
        templatePath: 'src/defense/threat-neutralization.ts.predloga',
        templateName: 'Threat Neutralization',
        category: 'DEFENSE',
        operationTypes: ['BLUE_TEAM', 'INCIDENT_RESPONSE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E', 'NIST_800-53'],
        description: 'Nevtralizacija groženj'
    },
    
    // DEFENSIVE
    {
        templateId: 'ai-ml-security-defense',
        templatePath: 'src/defensive/ai-ml-security-defense.ts.predloga',
        templateName: 'AI/ML Security Defense',
        category: 'DEFENSIVE',
        operationTypes: ['BLUE_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'AI/ML varnostna obramba'
    },
    {
        templateId: 'attack-capture-analysis',
        templatePath: 'src/defensive/attack-capture-analysis.ts.predloga',
        templateName: 'Attack Capture Analysis',
        category: 'DEFENSIVE',
        operationTypes: ['BLUE_TEAM', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Zajem in analiza napadov'
    },
    {
        templateId: 'blue-team-operations',
        templatePath: 'src/defensive/blue-team-operations.ts.predloga',
        templateName: 'Blue Team Operations',
        category: 'DEFENSIVE',
        operationTypes: ['BLUE_TEAM'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY', 'MODUL_08_AUTH'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53', 'ISO_27001', 'SOC_2'],
        description: 'Blue Team operacije'
    },
    {
        templateId: 'full-spectrum-vulnerability-scanner',
        templatePath: 'src/defensive/full-spectrum-vulnerability-scanner.ts.predloga',
        templateName: 'Full Spectrum Vulnerability Scanner',
        category: 'DEFENSIVE',
        operationTypes: ['BLUE_TEAM', 'VULNERABILITY_MGMT'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53', 'PCI_DSS'],
        description: 'Popoln skener ranljivosti'
    },
    {
        templateId: 'ics-scada-security',
        templatePath: 'src/defensive/ics-scada-security.ts.predloga',
        templateName: 'ICS/SCADA Security',
        category: 'DEFENSIVE',
        operationTypes: ['BLUE_TEAM', 'INFRASTRUCTURE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['IEC_62443', 'NIST_800-82'],
        description: 'ICS/SCADA varnost'
    },
    {
        templateId: 'quantum-safe-operations',
        templatePath: 'src/defensive/quantum-safe-operations.ts.predloga',
        templateName: 'Quantum Safe Operations',
        category: 'DEFENSIVE',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['NIST_PQC'],
        description: 'Kvantno varne operacije'
    },
    {
        templateId: 'space-systems-security',
        templatePath: 'src/defensive/space-systems-security.ts.predloga',
        templateName: 'Space Systems Security',
        category: 'DEFENSIVE',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Varnost vesoljskih sistemov'
    },
    {
        templateId: 'supply-chain-security-defensive',
        templatePath: 'src/defensive/supply-chain-security.ts.predloga',
        templateName: 'Supply Chain Security (Defensive)',
        category: 'DEFENSIVE',
        operationTypes: ['BLUE_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Varnost dobavne verige (defenzivna)'
    },
    {
        templateId: 'telecom-security',
        templatePath: 'src/defensive/telecom-security.ts.predloga',
        templateName: 'Telecom Security',
        category: 'DEFENSIVE',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['3GPP', 'NIST_800-53'],
        description: 'Telekomunikacijska varnost'
    },
    
    // DETECTION
    {
        templateId: 'ai-ml-threat-detection',
        templatePath: 'src/detection/ai-ml-threat-detection.ts.predloga',
        templateName: 'AI/ML Threat Detection',
        category: 'DETECTION',
        operationTypes: ['BLUE_TEAM', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'AI/ML detekcija groženj'
    },
    {
        templateId: 'apt-detection',
        templatePath: 'src/detection/apt-detection.ts.predloga',
        templateName: 'APT Detection',
        category: 'DETECTION',
        operationTypes: ['BLUE_TEAM', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['MITRE_ATT&CK', 'NIST_800-53'],
        description: 'Detekcija APT groženj'
    },
    {
        templateId: 'deepfake-detection',
        templatePath: 'src/detection/deepfake-detection.ts.predloga',
        templateName: 'Deepfake Detection',
        category: 'DETECTION',
        operationTypes: ['BLUE_TEAM', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Detekcija deepfake vsebin'
    },
    
    // EMSEC
    {
        templateId: 'electromagnetic-security',
        templatePath: 'src/emsec/electromagnetic-security.ts.predloga',
        templateName: 'Electromagnetic Security',
        category: 'EMSEC',
        operationTypes: ['INFRASTRUCTURE', 'SIGINT'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['TEMPEST', 'MIL-STD-882E'],
        description: 'Elektromagnetna varnost (TEMPEST)'
    },
    
    // FORENSICS
    {
        templateId: 'blockchain-forensics',
        templatePath: 'src/forensics/blockchain-forensics.ts.predloga',
        templateName: 'Blockchain Forensics',
        category: 'FORENSICS',
        operationTypes: ['FORENSICS', 'FININT'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Blockchain forenzika'
    },
    {
        templateId: 'device-forensics',
        templatePath: 'src/forensics/device-forensics.ts.predloga',
        templateName: 'Device Forensics',
        category: 'FORENSICS',
        operationTypes: ['FORENSICS'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['ISO_27037', 'NIST_800-86'],
        description: 'Forenzika naprav'
    },
    {
        templateId: 'firmware-analysis',
        templatePath: 'src/forensics/firmware-analysis.ts.predloga',
        templateName: 'Firmware Analysis',
        category: 'FORENSICS',
        operationTypes: ['FORENSICS', 'MALWARE_ANALYSIS'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Analiza firmware'
    },
    {
        templateId: 'hardware-implant-detection',
        templatePath: 'src/forensics/hardware-implant-detection.ts.predloga',
        templateName: 'Hardware Implant Detection',
        category: 'FORENSICS',
        operationTypes: ['FORENSICS', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Detekcija strojnih implantov'
    },
    
    // INTELLIGENCE
    {
        templateId: 'counter-intelligence',
        templatePath: 'src/intelligence/counter-intelligence.ts.predloga',
        templateName: 'Counter Intelligence',
        category: 'INTELLIGENCE',
        operationTypes: ['COUNTER_INTEL'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_AUTH'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Protiobveščevalne operacije'
    },
    {
        templateId: 'darkweb-intelligence',
        templatePath: 'src/intelligence/darkweb-intelligence.ts.predloga',
        templateName: 'Dark Web Intelligence',
        category: 'INTELLIGENCE',
        operationTypes: ['THREAT_INTEL', 'OSINT'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Obveščanje temnega spleta'
    },
    {
        templateId: 'finint-operations',
        templatePath: 'src/intelligence/finint-operations.ts.predloga',
        templateName: 'FININT Operations',
        category: 'INTELLIGENCE',
        operationTypes: ['FININT'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        classificationLevel: 'SECRET',
        complianceStandards: ['AML', 'FATF'],
        description: 'Finančno obveščanje'
    },
    {
        templateId: 'osint-platform',
        templatePath: 'src/intelligence/osint-platform.ts.predloga',
        templateName: 'OSINT Platform',
        category: 'INTELLIGENCE',
        operationTypes: ['OSINT', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53'],
        description: 'OSINT platforma'
    },
    {
        templateId: 'sigint-operations',
        templatePath: 'src/intelligence/sigint-operations.ts.predloga',
        templateName: 'SIGINT Operations',
        category: 'INTELLIGENCE',
        operationTypes: ['SIGINT'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_AES'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Signalno obveščanje'
    },
    {
        templateId: 'threat-intelligence',
        templatePath: 'src/intelligence/threat-intelligence.ts.predloga',
        templateName: 'Threat Intelligence',
        category: 'INTELLIGENCE',
        operationTypes: ['THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['STIX_TAXII', 'NIST_800-53'],
        description: 'Obveščanje o grožnjah'
    },
    
    // MALWARE
    {
        templateId: 'malware-analysis',
        templatePath: 'src/malware/malware-analysis.ts.predloga',
        templateName: 'Malware Analysis',
        category: 'MALWARE',
        operationTypes: ['MALWARE_ANALYSIS', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Analiza zlonamerne programske opreme'
    },
    
    // MONITORING
    {
        templateId: 'siem-soc',
        templatePath: 'src/monitoring/siem-soc.ts.predloga',
        templateName: 'SIEM/SOC',
        category: 'MONITORING',
        operationTypes: ['BLUE_TEAM'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS', 'MODUL_08_TRACING'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53', 'ISO_27001', 'SOC_2'],
        description: 'SIEM in SOC monitoring'
    },
    
    // NETWORK
    {
        templateId: 'network-security',
        templatePath: 'src/network/network-security.ts.predloga',
        templateName: 'Network Security',
        category: 'NETWORK',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Omrežna varnost'
    },
    
    // OBSERVABILITY
    {
        templateId: 'alerting',
        templatePath: 'src/observability/alerting.ts.predloga',
        templateName: 'Alerting',
        category: 'OBSERVABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Opozarjanje'
    },
    {
        templateId: 'health',
        templatePath: 'src/observability/health.ts.predloga',
        templateName: 'Health',
        category: 'OBSERVABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_METRICS'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Zdravje sistema'
    },
    {
        templateId: 'logger',
        templatePath: 'src/observability/logger.ts.predloga',
        templateName: 'Logger',
        category: 'OBSERVABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Beleženje'
    },
    {
        templateId: 'metrics',
        templatePath: 'src/observability/metrics.ts.predloga',
        templateName: 'Metrics',
        category: 'OBSERVABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_METRICS'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Metrike'
    },
    {
        templateId: 'tracing',
        templatePath: 'src/observability/tracing.ts.predloga',
        templateName: 'Tracing',
        category: 'OBSERVABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_TRACING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Sledenje'
    },
    
    // OFFENSIVE
    {
        templateId: 'evasion-techniques',
        templatePath: 'src/offensive/evasion-techniques.ts.predloga',
        templateName: 'Evasion Techniques',
        category: 'OFFENSIVE',
        operationTypes: ['RED_TEAM', 'COVERT_OPS'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Tehnike izogibanja'
    },
    {
        templateId: 'implant-development',
        templatePath: 'src/offensive/implant-development.ts.predloga',
        templateName: 'Implant Development',
        category: 'OFFENSIVE',
        operationTypes: ['RED_TEAM', 'COVERT_OPS'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Razvoj implantov'
    },
    {
        templateId: 'red-team-operations',
        templatePath: 'src/offensive/red-team-operations.ts.predloga',
        templateName: 'Red Team Operations',
        category: 'OFFENSIVE',
        operationTypes: ['RED_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY', 'MODUL_08_AUTH'],
        classificationLevel: 'SECRET',
        complianceStandards: ['MITRE_ATT&CK', 'NIST_800-53'],
        description: 'Red Team operacije'
    },
    
    // OPERATIONS
    {
        templateId: 'covert-operations',
        templatePath: 'src/operations/covert-operations.ts.predloga',
        templateName: 'Covert Operations',
        category: 'OPERATIONS',
        operationTypes: ['COVERT_OPS'],
        domainModules: ['MODUL_08_AUTH', 'MODUL_08_AES'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Prikrite operacije'
    },
    {
        templateId: 'identity-operations',
        templatePath: 'src/operations/identity-operations.ts.predloga',
        templateName: 'Identity Operations',
        category: 'OPERATIONS',
        operationTypes: ['COVERT_OPS', 'HUMINT'],
        domainModules: ['MODUL_08_AUTH'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Operacije z identitetami'
    },
    {
        templateId: 'interrogation-support',
        templatePath: 'src/operations/interrogation-support.ts.predloga',
        templateName: 'Interrogation Support',
        category: 'OPERATIONS',
        operationTypes: ['HUMINT', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Podpora zaslišanjem'
    },
    {
        templateId: 'offensive-operations-center',
        templatePath: 'src/operations/offensive-operations-center.ts.predloga',
        templateName: 'Offensive Operations Center',
        category: 'OPERATIONS',
        operationTypes: ['RED_TEAM', 'CYBER_WARFARE'],
        domainModules: ['MODUL_08_VULNERABILITY', 'MODUL_08_AUTH'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Ofenzivni operativni center'
    },
    {
        templateId: 'psychological-operations',
        templatePath: 'src/operations/psychological-operations.ts.predloga',
        templateName: 'Psychological Operations',
        category: 'OPERATIONS',
        operationTypes: ['COVERT_OPS', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Psihološke operacije'
    },
    
    // RELIABILITY
    {
        templateId: 'circuit-breaker',
        templatePath: 'src/reliability/circuit-breaker.ts.predloga',
        templateName: 'Circuit Breaker',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_ERROR_HANDLING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Odklopnik vezja'
    },
    {
        templateId: 'error-handler',
        templatePath: 'src/reliability/error-handler.ts.predloga',
        templateName: 'Error Handler',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_ERROR_HANDLING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Obravnava napak'
    },
    {
        templateId: 'fallback',
        templatePath: 'src/reliability/fallback.ts.predloga',
        templateName: 'Fallback',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_ERROR_HANDLING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Nadomestna logika'
    },
    {
        templateId: 'graceful-shutdown',
        templatePath: 'src/reliability/graceful-shutdown.ts.predloga',
        templateName: 'Graceful Shutdown',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_ERROR_HANDLING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Elegantna zaustavitev'
    },
    {
        templateId: 'health-check',
        templatePath: 'src/reliability/health-check.ts.predloga',
        templateName: 'Health Check',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_METRICS'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Preverjanje zdravja'
    },
    {
        templateId: 'rate-limiter',
        templatePath: 'src/reliability/rate-limiter.ts.predloga',
        templateName: 'Rate Limiter',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_METRICS'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Omejevalnik hitrosti'
    },
    {
        templateId: 'retry',
        templatePath: 'src/reliability/retry.ts.predloga',
        templateName: 'Retry',
        category: 'RELIABILITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_ERROR_HANDLING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53'],
        description: 'Ponovni poskus'
    },
    
    // RESEARCH
    {
        templateId: 'zero-day-research',
        templatePath: 'src/research/zero-day-research.ts.predloga',
        templateName: 'Zero-Day Research',
        category: 'RESEARCH',
        operationTypes: ['RED_TEAM', 'VULNERABILITY_MGMT'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['ISO_29147', 'MIL-STD-882E'],
        description: 'Raziskovanje zero-day ranljivosti'
    },
    
    // RESPONSE
    {
        templateId: 'incident-response',
        templatePath: 'src/response/incident-response.ts.predloga',
        templateName: 'Incident Response',
        category: 'RESPONSE',
        operationTypes: ['INCIDENT_RESPONSE', 'BLUE_TEAM'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-61', 'ISO_27035'],
        description: 'Odziv na incidente'
    },
    
    // SCANNER
    {
        templateId: 'live-web-vulnerability-scanner',
        templatePath: 'src/scanner/live-web-vulnerability-scanner.ts.predloga',
        templateName: 'Live Web Vulnerability Scanner',
        category: 'SCANNER',
        operationTypes: ['VULNERABILITY_MGMT', 'RED_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['OWASP', 'NIST_800-53'],
        description: 'Skener spletnih ranljivosti v živo'
    },
    
    // SEARCH
    {
        templateId: 'internet-search-engine',
        templatePath: 'src/search/internet-search-engine.ts.predloga',
        templateName: 'Internet Search Engine',
        category: 'SEARCH',
        operationTypes: ['OSINT', 'THREAT_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53'],
        description: 'Iskalnik po internetu'
    },
    
    // SECURITY
    {
        templateId: 'audit',
        templatePath: 'src/security/audit.ts.predloga',
        templateName: 'Audit',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Revizija'
    },
    {
        templateId: 'authentication',
        templatePath: 'src/security/authentication.ts.predloga',
        templateName: 'Authentication',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AUTH', 'MODUL_08_TOTP'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Avtentikacija'
    },
    {
        templateId: 'authorization',
        templatePath: 'src/security/authorization.ts.predloga',
        templateName: 'Authorization',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_RBAC'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Avtorizacija'
    },
    {
        templateId: 'encryption',
        templatePath: 'src/security/encryption.ts.predloga',
        templateName: 'Encryption',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['FIPS_140-3', 'NIST_800-53'],
        description: 'Šifriranje'
    },
    {
        templateId: 'input-validation',
        templatePath: 'src/security/input-validation.ts.predloga',
        templateName: 'Input Validation',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['OWASP', 'NIST_800-53'],
        description: 'Validacija vhodov'
    },
    {
        templateId: 'secrets',
        templatePath: 'src/security/secrets.ts.predloga',
        templateName: 'Secrets',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_KEY_DERIVATION'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53'],
        description: 'Upravljanje skrivnosti'
    },
    {
        templateId: 'validation',
        templatePath: 'src/security/validation.ts.predloga',
        templateName: 'Validation',
        category: 'SECURITY',
        operationTypes: ['INFRASTRUCTURE'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'UNCLASSIFIED',
        complianceStandards: ['OWASP', 'NIST_800-53'],
        description: 'Validacija'
    },
    
    // SPECIALIZED
    {
        templateId: 'crypto-gambling-darkweb',
        templatePath: 'src/specialized/crypto-gambling-darkweb.ts.predloga',
        templateName: 'Crypto Gambling Dark Web',
        category: 'SPECIALIZED',
        operationTypes: ['FININT', 'OSINT'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'SECRET',
        complianceStandards: ['AML', 'FATF'],
        description: 'Kripto igre na srečo in temni splet'
    },
    
    // STEALTH
    {
        templateId: 'stealth-antiforensics',
        templatePath: 'src/stealth/stealth-antiforensics.ts.predloga',
        templateName: 'Stealth Anti-Forensics',
        category: 'STEALTH',
        operationTypes: ['RED_TEAM', 'COVERT_OPS'],
        domainModules: ['MODUL_08_SECURE_RANDOM'],
        classificationLevel: 'TOP_SECRET',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Stealth in anti-forenzika'
    },
    
    // SUPPLY_CHAIN
    {
        templateId: 'supply-chain-security',
        templatePath: 'src/supply-chain/supply-chain-security.ts.predloga',
        templateName: 'Supply Chain Security',
        category: 'SUPPLY_CHAIN',
        operationTypes: ['BLUE_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'SECRET',
        complianceStandards: ['NIST_800-53', 'ISO_27001'],
        description: 'Varnost dobavne verige'
    },
    
    // SURVEILLANCE
    {
        templateId: 'surveillance-systems',
        templatePath: 'src/surveillance/surveillance-systems.ts.predloga',
        templateName: 'Surveillance Systems',
        category: 'SURVEILLANCE',
        operationTypes: ['SIGINT', 'COUNTER_INTEL'],
        domainModules: ['MODUL_08_LOGGING'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Nadzorni sistemi'
    },
    
    // UI
    {
        templateId: 'security-ui-center',
        templatePath: 'src/ui/security-ui-center.ts.predloga',
        templateName: 'Security UI Center',
        category: 'UI',
        operationTypes: ['BLUE_TEAM', 'INFRASTRUCTURE'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53'],
        description: 'Varnostni UI center'
    },
    
    // VISUALIZATION
    {
        templateId: '3d-visualization-engine',
        templatePath: 'src/visualization/3d-visualization-engine.ts.predloga',
        templateName: '3D Visualization Engine',
        category: 'VISUALIZATION',
        operationTypes: ['BLUE_TEAM', 'INFRASTRUCTURE'],
        domainModules: ['MODUL_08_METRICS'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53'],
        description: '3D vizualizacijski motor'
    },
    
    // VULNERABILITY
    {
        templateId: 'vulnerability-management',
        templatePath: 'src/vulnerability/vulnerability-management.ts.predloga',
        templateName: 'Vulnerability Management',
        category: 'VULNERABILITY',
        operationTypes: ['VULNERABILITY_MGMT', 'BLUE_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'CONFIDENTIAL',
        complianceStandards: ['NIST_800-53', 'PCI_DSS'],
        description: 'Upravljanje ranljivosti'
    },
    
    // WARFARE
    {
        templateId: 'critical-infrastructure-attack',
        templatePath: 'src/warfare/critical-infrastructure-attack.ts.predloga',
        templateName: 'Critical Infrastructure Attack',
        category: 'WARFARE',
        operationTypes: ['CYBER_WARFARE', 'RED_TEAM'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Napad na kritično infrastrukturo'
    },
    {
        templateId: 'cyber-warfare',
        templatePath: 'src/warfare/cyber-warfare.ts.predloga',
        templateName: 'Cyber Warfare',
        category: 'WARFARE',
        operationTypes: ['CYBER_WARFARE'],
        domainModules: ['MODUL_08_VULNERABILITY', 'MODUL_08_AUTH'],
        classificationLevel: 'TOP_SECRET_SCI',
        complianceStandards: ['MIL-STD-882E'],
        description: 'Kibernetsko bojevanje'
    }
];

// ============================================================================
// CATEGORY -> TEMPLATES MAPPING
// ============================================================================

export const CATEGORY_MAPPINGS: readonly CategoryMapping[] = [
    {
        category: 'ANALYTICS',
        templates: ['insider-threat-analytics'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        description: 'Analitika in vedenjska analiza'
    },
    {
        category: 'ANTIFORENSICS',
        templates: ['data-destruction'],
        domainModules: ['MODUL_08_SECURE_RANDOM'],
        description: 'Anti-forenzične tehnike'
    },
    {
        category: 'BIOMETRIC',
        templates: ['biometric-security'],
        domainModules: ['MODUL_08_AUTH'],
        description: 'Biometrična varnost'
    },
    {
        category: 'COMMUNICATIONS',
        templates: ['covert-communications'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA'],
        description: 'Prikrite komunikacije'
    },
    {
        category: 'CRAWLER',
        templates: ['web-crawler-engine'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Spletno pajkanje'
    },
    {
        category: 'CRYPTOGRAPHY',
        templates: ['cryptography', 'quantum-cryptography'],
        domainModules: ['MODUL_08_AES', 'MODUL_08_RSA', 'MODUL_08_HASHING', 'MODUL_08_KEY_DERIVATION'],
        description: 'Kriptografija'
    },
    {
        category: 'DEFENSE',
        templates: ['active-defense-operations', 'adversary-disruption', 'threat-neutralization'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Aktivna obramba'
    },
    {
        category: 'DEFENSIVE',
        templates: ['ai-ml-security-defense', 'attack-capture-analysis', 'blue-team-operations', 'full-spectrum-vulnerability-scanner', 'ics-scada-security', 'quantum-safe-operations', 'space-systems-security', 'supply-chain-security-defensive', 'telecom-security'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY', 'MODUL_08_AUTH'],
        description: 'Defenzivne operacije'
    },
    {
        category: 'DETECTION',
        templates: ['ai-ml-threat-detection', 'apt-detection', 'deepfake-detection'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY', 'MODUL_08_METRICS'],
        description: 'Detekcija groženj'
    },
    {
        category: 'EMSEC',
        templates: ['electromagnetic-security'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Elektromagnetna varnost'
    },
    {
        category: 'FORENSICS',
        templates: ['blockchain-forensics', 'device-forensics', 'firmware-analysis', 'hardware-implant-detection'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY'],
        description: 'Digitalna forenzika'
    },
    {
        category: 'INTELLIGENCE',
        templates: ['counter-intelligence', 'darkweb-intelligence', 'finint-operations', 'osint-platform', 'sigint-operations', 'threat-intelligence'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_AUTH', 'MODUL_08_AES', 'MODUL_08_METRICS'],
        description: 'Obveščevalne operacije'
    },
    {
        category: 'MALWARE',
        templates: ['malware-analysis'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY'],
        description: 'Analiza zlonamerne programske opreme'
    },
    {
        category: 'MONITORING',
        templates: ['siem-soc'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS', 'MODUL_08_TRACING'],
        description: 'Monitoring in SIEM'
    },
    {
        category: 'NETWORK',
        templates: ['network-security'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Omrežna varnost'
    },
    {
        category: 'OBSERVABILITY',
        templates: ['alerting', 'health', 'logger', 'metrics', 'tracing'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS', 'MODUL_08_TRACING'],
        description: 'Opazljivost'
    },
    {
        category: 'OFFENSIVE',
        templates: ['evasion-techniques', 'implant-development', 'red-team-operations'],
        domainModules: ['MODUL_08_VULNERABILITY', 'MODUL_08_AUTH', 'MODUL_08_AES', 'MODUL_08_RSA'],
        description: 'Ofenzivne operacije'
    },
    {
        category: 'OPERATIONS',
        templates: ['covert-operations', 'identity-operations', 'interrogation-support', 'offensive-operations-center', 'psychological-operations'],
        domainModules: ['MODUL_08_AUTH', 'MODUL_08_AES', 'MODUL_08_LOGGING'],
        description: 'Specializirane operacije'
    },
    {
        category: 'RELIABILITY',
        templates: ['circuit-breaker', 'error-handler', 'fallback', 'graceful-shutdown', 'health-check', 'rate-limiter', 'retry'],
        domainModules: ['MODUL_08_ERROR_HANDLING', 'MODUL_08_METRICS'],
        description: 'Zanesljivost'
    },
    {
        category: 'RESEARCH',
        templates: ['zero-day-research'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Varnostne raziskave'
    },
    {
        category: 'RESPONSE',
        templates: ['incident-response'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_VULNERABILITY'],
        description: 'Odziv na incidente'
    },
    {
        category: 'SCANNER',
        templates: ['live-web-vulnerability-scanner'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Skeniranje ranljivosti'
    },
    {
        category: 'SEARCH',
        templates: ['internet-search-engine'],
        domainModules: ['MODUL_08_LOGGING'],
        description: 'Iskanje'
    },
    {
        category: 'SECURITY',
        templates: ['audit', 'authentication', 'authorization', 'encryption', 'input-validation', 'secrets', 'validation'],
        domainModules: ['MODUL_08_AUTH', 'MODUL_08_RBAC', 'MODUL_08_AES', 'MODUL_08_RSA', 'MODUL_08_LOGGING', 'MODUL_08_KEY_DERIVATION', 'MODUL_08_TOTP', 'MODUL_08_VULNERABILITY'],
        description: 'Varnostne komponente'
    },
    {
        category: 'SPECIALIZED',
        templates: ['crypto-gambling-darkweb'],
        domainModules: ['MODUL_08_LOGGING'],
        description: 'Specializirane domene'
    },
    {
        category: 'STEALTH',
        templates: ['stealth-antiforensics'],
        domainModules: ['MODUL_08_SECURE_RANDOM'],
        description: 'Stealth operacije'
    },
    {
        category: 'SUPPLY_CHAIN',
        templates: ['supply-chain-security'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Varnost dobavne verige'
    },
    {
        category: 'SURVEILLANCE',
        templates: ['surveillance-systems'],
        domainModules: ['MODUL_08_LOGGING'],
        description: 'Nadzorni sistemi'
    },
    {
        category: 'UI',
        templates: ['security-ui-center'],
        domainModules: ['MODUL_08_LOGGING', 'MODUL_08_METRICS'],
        description: 'Uporabniški vmesnik'
    },
    {
        category: 'VISUALIZATION',
        templates: ['3d-visualization-engine'],
        domainModules: ['MODUL_08_METRICS'],
        description: 'Vizualizacija'
    },
    {
        category: 'VULNERABILITY',
        templates: ['vulnerability-management'],
        domainModules: ['MODUL_08_VULNERABILITY'],
        description: 'Upravljanje ranljivosti'
    },
    {
        category: 'WARFARE',
        templates: ['critical-infrastructure-attack', 'cyber-warfare'],
        domainModules: ['MODUL_08_VULNERABILITY', 'MODUL_08_AUTH'],
        description: 'Kibernetsko bojevanje'
    }
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

export function getTemplatesByCategory(category: TemplateCategory): readonly TemplateMapping[] {
    return TEMPLATE_MAPPINGS.filter(t => t.category === category);
}

export function getTemplatesByOperationType(operationType: OperationType): readonly TemplateMapping[] {
    return TEMPLATE_MAPPINGS.filter(t => t.operationTypes.includes(operationType));
}

export function getTemplatesByClassification(level: ClassificationLevel): readonly TemplateMapping[] {
    return TEMPLATE_MAPPINGS.filter(t => t.classificationLevel === level);
}

export function getTemplatesByDomainModule(moduleId: string): readonly TemplateMapping[] {
    return TEMPLATE_MAPPINGS.filter(t => t.domainModules.includes(moduleId));
}

export function getTemplateById(templateId: string): TemplateMapping | undefined {
    return TEMPLATE_MAPPINGS.find(t => t.templateId === templateId);
}

export function getCategoryMapping(category: TemplateCategory): CategoryMapping | undefined {
    return CATEGORY_MAPPINGS.find(c => c.category === category);
}

export function getAllTemplateIds(): readonly string[] {
    return TEMPLATE_MAPPINGS.map(t => t.templateId);
}

export function getAllCategories(): readonly TemplateCategory[] {
    return [...new Set(TEMPLATE_MAPPINGS.map(t => t.category))];
}

export function getTemplateCount(): number {
    return TEMPLATE_MAPPINGS.length;
}

export function getCategoryCount(): number {
    return CATEGORY_MAPPINGS.length;
}

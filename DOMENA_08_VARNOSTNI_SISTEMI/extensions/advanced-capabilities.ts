/**
 * DOMENA_08 ADVANCED CAPABILITIES EXTENSION
 * ==========================================
 * 
 * Razširitev domene 8 z naprednimi varnostnimi zmogljivostmi.
 * Pokriva Red Team, Blue Team, Threat Intelligence, Forensics,
 * SIGINT, FININT, OSINT, Cyber Warfare in druge specializirane operacije.
 * 
 * INDUSTRIJSKA SKLADNOST:
 * - DO-178C (letalstvo)
 * - IEC 61508 (funkcionalna varnost)
 * - ISO 26262 (avtomobilska industrija)
 * - MIL-STD-882E (vojaški sistemi)
 */

import { Category, Module, Submodule, Function } from '../../../registry/types';

// ============================================================================
// NAPREDNE KATEGORIJE
// ============================================================================

export const ADVANCED_CATEGORIES: readonly Category[] = [
    {
        id: 'KATEGORIJA_08_OFFENSIVE',
        displayNameSL: 'Ofenzivne operacije',
        descriptionSL: 'Red Team, penetracijsko testiranje, exploit development',
        path: 'knowbank/domene/DOMENA_08/categories/KATEGORIJA_08_OFFENSIVE.ts',
        domainId: 'DOMENA_08',
        type: 'CATEGORY',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['red-team', 'offensive', 'exploitation'],
        parentDomainId: 'DOMENA_08',
        subcategoryIds: ['PODKATEGORIJA_08_RED_TEAM', 'PODKATEGORIJA_08_EXPLOITATION', 'PODKATEGORIJA_08_C2']
    },
    {
        id: 'KATEGORIJA_08_DEFENSIVE',
        displayNameSL: 'Defenzivne operacije',
        descriptionSL: 'Blue Team, SOC, incident response, threat hunting',
        path: 'knowbank/domene/DOMENA_08/categories/KATEGORIJA_08_DEFENSIVE.ts',
        domainId: 'DOMENA_08',
        type: 'CATEGORY',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['blue-team', 'defensive', 'soc'],
        parentDomainId: 'DOMENA_08',
        subcategoryIds: ['PODKATEGORIJA_08_BLUE_TEAM', 'PODKATEGORIJA_08_SOC', 'PODKATEGORIJA_08_INCIDENT_RESPONSE']
    },
    {
        id: 'KATEGORIJA_08_INTELLIGENCE',
        displayNameSL: 'Obveščevalne operacije',
        descriptionSL: 'SIGINT, FININT, OSINT, HUMINT, Counter-Intelligence',
        path: 'knowbank/domene/DOMENA_08/categories/KATEGORIJA_08_INTELLIGENCE.ts',
        domainId: 'DOMENA_08',
        type: 'CATEGORY',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['intelligence', 'sigint', 'osint'],
        parentDomainId: 'DOMENA_08',
        subcategoryIds: ['PODKATEGORIJA_08_SIGINT', 'PODKATEGORIJA_08_FININT', 'PODKATEGORIJA_08_OSINT', 'PODKATEGORIJA_08_COUNTER_INTEL']
    },
    {
        id: 'KATEGORIJA_08_FORENSICS',
        displayNameSL: 'Digitalna forenzika',
        descriptionSL: 'Device forensics, memory forensics, network forensics',
        path: 'knowbank/domene/DOMENA_08/categories/KATEGORIJA_08_FORENSICS.ts',
        domainId: 'DOMENA_08',
        type: 'CATEGORY',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'investigation', 'evidence'],
        parentDomainId: 'DOMENA_08',
        subcategoryIds: ['PODKATEGORIJA_08_DEVICE_FORENSICS', 'PODKATEGORIJA_08_MEMORY_FORENSICS', 'PODKATEGORIJA_08_NETWORK_FORENSICS']
    },
    {
        id: 'KATEGORIJA_08_WARFARE',
        displayNameSL: 'Kibernetsko bojevanje',
        descriptionSL: 'Cyber warfare, critical infrastructure, covert operations',
        path: 'knowbank/domene/DOMENA_08/categories/KATEGORIJA_08_WARFARE.ts',
        domainId: 'DOMENA_08',
        type: 'CATEGORY',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['warfare', 'military', 'covert'],
        parentDomainId: 'DOMENA_08',
        subcategoryIds: ['PODKATEGORIJA_08_CYBER_WARFARE', 'PODKATEGORIJA_08_CRITICAL_INFRASTRUCTURE', 'PODKATEGORIJA_08_COVERT_OPS']
    }
];

// ============================================================================
// NAPREDNI MODULI
// ============================================================================

export const ADVANCED_MODULES: readonly Module[] = [
    // RED TEAM MODULES
    {
        id: 'MODUL_08_RECONNAISSANCE',
        displayNameSL: 'Reconnaissance',
        descriptionSL: 'Izvidništvo in zbiranje informacij',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_RECONNAISSANCE.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['reconnaissance', 'osint', 'scanning'],
        parentSubcategoryId: 'PODKATEGORIJA_08_RED_TEAM',
        submoduleIds: ['PODMODUL_08_PASSIVE_RECON', 'PODMODUL_08_ACTIVE_RECON']
    },
    {
        id: 'MODUL_08_EXPLOITATION',
        displayNameSL: 'Exploitation',
        descriptionSL: 'Izkoriščanje ranljivosti',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_EXPLOITATION.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['exploitation', 'payload', 'weaponization'],
        parentSubcategoryId: 'PODKATEGORIJA_08_EXPLOITATION',
        submoduleIds: ['PODMODUL_08_EXPLOIT_DEV', 'PODMODUL_08_PAYLOAD_GEN']
    },
    {
        id: 'MODUL_08_PERSISTENCE',
        displayNameSL: 'Persistence',
        descriptionSL: 'Vzdrževanje dostopa',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_PERSISTENCE.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['persistence', 'backdoor', 'implant'],
        parentSubcategoryId: 'PODKATEGORIJA_08_RED_TEAM',
        submoduleIds: ['PODMODUL_08_REGISTRY_PERSIST', 'PODMODUL_08_SERVICE_PERSIST']
    },
    {
        id: 'MODUL_08_LATERAL_MOVEMENT',
        displayNameSL: 'Lateral Movement',
        descriptionSL: 'Bočno gibanje v omrežju',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_LATERAL_MOVEMENT.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['lateral-movement', 'pivoting', 'credential-theft'],
        parentSubcategoryId: 'PODKATEGORIJA_08_RED_TEAM',
        submoduleIds: ['PODMODUL_08_PASS_THE_HASH', 'PODMODUL_08_REMOTE_EXEC']
    },
    {
        id: 'MODUL_08_C2',
        displayNameSL: 'Command & Control',
        descriptionSL: 'Ukazovanje in nadzor',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_C2.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['c2', 'command-control', 'beacon'],
        parentSubcategoryId: 'PODKATEGORIJA_08_C2',
        submoduleIds: ['PODMODUL_08_C2_INFRA', 'PODMODUL_08_BEACON_MGMT']
    },
    
    // BLUE TEAM MODULES
    {
        id: 'MODUL_08_THREAT_DETECTION',
        displayNameSL: 'Threat Detection',
        descriptionSL: 'Detekcija groženj',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_THREAT_DETECTION.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['detection', 'siem', 'alerting'],
        parentSubcategoryId: 'PODKATEGORIJA_08_BLUE_TEAM',
        submoduleIds: ['PODMODUL_08_SIGNATURE_DETECTION', 'PODMODUL_08_BEHAVIORAL_DETECTION']
    },
    {
        id: 'MODUL_08_INCIDENT_RESPONSE',
        displayNameSL: 'Incident Response',
        descriptionSL: 'Odziv na incidente',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_INCIDENT_RESPONSE.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['incident-response', 'containment', 'eradication'],
        parentSubcategoryId: 'PODKATEGORIJA_08_INCIDENT_RESPONSE',
        submoduleIds: ['PODMODUL_08_TRIAGE', 'PODMODUL_08_CONTAINMENT', 'PODMODUL_08_ERADICATION']
    },
    {
        id: 'MODUL_08_THREAT_HUNTING',
        displayNameSL: 'Threat Hunting',
        descriptionSL: 'Lov na grožnje',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_THREAT_HUNTING.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['threat-hunting', 'proactive', 'hypothesis'],
        parentSubcategoryId: 'PODKATEGORIJA_08_BLUE_TEAM',
        submoduleIds: ['PODMODUL_08_HYPOTHESIS_HUNTING', 'PODMODUL_08_IOC_HUNTING']
    },
    
    // INTELLIGENCE MODULES
    {
        id: 'MODUL_08_SIGINT',
        displayNameSL: 'SIGINT',
        descriptionSL: 'Signalno obveščanje',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_SIGINT.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['sigint', 'intercept', 'traffic-analysis'],
        parentSubcategoryId: 'PODKATEGORIJA_08_SIGINT',
        submoduleIds: ['PODMODUL_08_COMMS_INTERCEPT', 'PODMODUL_08_TRAFFIC_ANALYSIS']
    },
    {
        id: 'MODUL_08_FININT',
        displayNameSL: 'FININT',
        descriptionSL: 'Finančno obveščanje',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_FININT.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['finint', 'aml', 'fraud-detection'],
        parentSubcategoryId: 'PODKATEGORIJA_08_FININT',
        submoduleIds: ['PODMODUL_08_AML', 'PODMODUL_08_FRAUD_DETECTION']
    },
    {
        id: 'MODUL_08_OSINT',
        displayNameSL: 'OSINT',
        descriptionSL: 'Odprtokodno obveščanje',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_OSINT.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['osint', 'social-media', 'public-records'],
        parentSubcategoryId: 'PODKATEGORIJA_08_OSINT',
        submoduleIds: ['PODMODUL_08_SOCIAL_MEDIA', 'PODMODUL_08_PUBLIC_RECORDS']
    },
    {
        id: 'MODUL_08_THREAT_INTEL',
        displayNameSL: 'Threat Intelligence',
        descriptionSL: 'Obveščanje o grožnjah',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_THREAT_INTEL.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['threat-intel', 'ioc', 'attribution'],
        parentSubcategoryId: 'PODKATEGORIJA_08_INTELLIGENCE',
        submoduleIds: ['PODMODUL_08_IOC_MGMT', 'PODMODUL_08_ATTRIBUTION']
    },
    {
        id: 'MODUL_08_COUNTER_INTEL',
        displayNameSL: 'Counter Intelligence',
        descriptionSL: 'Protiobveščanje',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_COUNTER_INTEL.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['counter-intel', 'mole-detection', 'deception'],
        parentSubcategoryId: 'PODKATEGORIJA_08_COUNTER_INTEL',
        submoduleIds: ['PODMODUL_08_MOLE_DETECTION', 'PODMODUL_08_DECEPTION']
    },
    
    // FORENSICS MODULES
    {
        id: 'MODUL_08_DEVICE_FORENSICS',
        displayNameSL: 'Device Forensics',
        descriptionSL: 'Forenzika naprav',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_DEVICE_FORENSICS.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['device-forensics', 'acquisition', 'analysis'],
        parentSubcategoryId: 'PODKATEGORIJA_08_DEVICE_FORENSICS',
        submoduleIds: ['PODMODUL_08_DISK_FORENSICS', 'PODMODUL_08_MOBILE_FORENSICS']
    },
    {
        id: 'MODUL_08_MEMORY_FORENSICS',
        displayNameSL: 'Memory Forensics',
        descriptionSL: 'Forenzika pomnilnika',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_MEMORY_FORENSICS.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['memory-forensics', 'volatility', 'process-analysis'],
        parentSubcategoryId: 'PODKATEGORIJA_08_MEMORY_FORENSICS',
        submoduleIds: ['PODMODUL_08_MEMORY_ACQUISITION', 'PODMODUL_08_MEMORY_ANALYSIS']
    },
    {
        id: 'MODUL_08_NETWORK_FORENSICS',
        displayNameSL: 'Network Forensics',
        descriptionSL: 'Omrežna forenzika',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_NETWORK_FORENSICS.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['network-forensics', 'pcap', 'traffic-analysis'],
        parentSubcategoryId: 'PODKATEGORIJA_08_NETWORK_FORENSICS',
        submoduleIds: ['PODMODUL_08_PACKET_CAPTURE', 'PODMODUL_08_SESSION_RECONSTRUCTION']
    },
    {
        id: 'MODUL_08_MALWARE_ANALYSIS',
        displayNameSL: 'Malware Analysis',
        descriptionSL: 'Analiza zlonamerne programske opreme',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_MALWARE_ANALYSIS.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['malware', 'static-analysis', 'dynamic-analysis'],
        parentSubcategoryId: 'PODKATEGORIJA_08_FORENSICS',
        submoduleIds: ['PODMODUL_08_STATIC_ANALYSIS', 'PODMODUL_08_DYNAMIC_ANALYSIS', 'PODMODUL_08_CODE_RECONSTRUCTION']
    },
    
    // WARFARE MODULES
    {
        id: 'MODUL_08_CYBER_WARFARE',
        displayNameSL: 'Cyber Warfare',
        descriptionSL: 'Kibernetsko bojevanje',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_CYBER_WARFARE.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['cyber-warfare', 'offensive', 'defensive'],
        parentSubcategoryId: 'PODKATEGORIJA_08_CYBER_WARFARE',
        submoduleIds: ['PODMODUL_08_OFFENSIVE_OPS', 'PODMODUL_08_DEFENSIVE_OPS']
    },
    {
        id: 'MODUL_08_CRITICAL_INFRASTRUCTURE',
        displayNameSL: 'Critical Infrastructure',
        descriptionSL: 'Kritična infrastruktura',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_CRITICAL_INFRASTRUCTURE.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['critical-infrastructure', 'scada', 'ics'],
        parentSubcategoryId: 'PODKATEGORIJA_08_CRITICAL_INFRASTRUCTURE',
        submoduleIds: ['PODMODUL_08_SCADA_SECURITY', 'PODMODUL_08_ICS_SECURITY']
    },
    {
        id: 'MODUL_08_COVERT_OPS',
        displayNameSL: 'Covert Operations',
        descriptionSL: 'Prikrite operacije',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_COVERT_OPS.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['covert', 'stealth', 'anti-forensics'],
        parentSubcategoryId: 'PODKATEGORIJA_08_COVERT_OPS',
        submoduleIds: ['PODMODUL_08_STEALTH', 'PODMODUL_08_ANTI_FORENSICS']
    },
    
    // VISUALIZATION MODULES
    {
        id: 'MODUL_08_VISUALIZATION',
        displayNameSL: 'Visualization',
        descriptionSL: 'Vizualizacija varnostnih podatkov',
        path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_VISUALIZATION.ts',
        domainId: 'DOMENA_08',
        type: 'MODULE',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['visualization', '2d', '3d', 'real-time'],
        parentSubcategoryId: 'PODKATEGORIJA_08_SOC',
        submoduleIds: ['PODMODUL_08_2D_VIZ', 'PODMODUL_08_3D_VIZ']
    }
];

// ============================================================================
// NAPREDNE FUNKCIJE
// ============================================================================

export const ADVANCED_FUNCTIONS: readonly Function[] = [
    // RECONNAISSANCE FUNCTIONS
    {
        id: 'FN_08_PASSIVE_RECON',
        displayNameSL: 'Pasivno izvidništvo',
        descriptionSL: 'Zbiranje informacij brez neposrednega stika s ciljem',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/reconnaissance.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['reconnaissance', 'osint', 'passive'],
        parentSubmoduleId: 'PODMODUL_08_PASSIVE_RECON',
        inputTypes: ['target: string', 'options: ReconOptions'],
        outputType: 'ReconResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_ACTIVE_RECON',
        displayNameSL: 'Aktivno izvidništvo',
        descriptionSL: 'Skeniranje in enumeracija ciljev',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/reconnaissance.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['reconnaissance', 'scanning', 'active'],
        parentSubmoduleId: 'PODMODUL_08_ACTIVE_RECON',
        inputTypes: ['target: string', 'options: ScanOptions'],
        outputType: 'ScanResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_SUBDOMAIN_ENUM',
        displayNameSL: 'Enumeracija poddomen',
        descriptionSL: 'Odkrivanje poddomen ciljne domene',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/reconnaissance.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['reconnaissance', 'subdomain', 'enumeration'],
        parentSubmoduleId: 'PODMODUL_08_ACTIVE_RECON',
        inputTypes: ['domain: string', 'options: EnumOptions'],
        outputType: 'SubdomainResult[]',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // EXPLOITATION FUNCTIONS
    {
        id: 'FN_08_EXPLOIT_DEVELOP',
        displayNameSL: 'Razvoj exploita',
        descriptionSL: 'Razvoj izkoriščanja ranljivosti',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/exploitation.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['exploitation', 'exploit', 'development'],
        parentSubmoduleId: 'PODMODUL_08_EXPLOIT_DEV',
        inputTypes: ['vulnerability: VulnerabilityInfo', 'options: ExploitOptions'],
        outputType: 'Exploit',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_PAYLOAD_GENERATE',
        displayNameSL: 'Generiranje payloada',
        descriptionSL: 'Generiranje zlonamerne vsebine',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/exploitation.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['exploitation', 'payload', 'generation'],
        parentSubmoduleId: 'PODMODUL_08_PAYLOAD_GEN',
        inputTypes: ['type: PayloadType', 'options: PayloadOptions'],
        outputType: 'Payload',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // THREAT DETECTION FUNCTIONS
    {
        id: 'FN_08_DETECT_THREAT',
        displayNameSL: 'Detekcija grožnje',
        descriptionSL: 'Zaznavanje varnostnih groženj',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/detection.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['detection', 'threat', 'alerting'],
        parentSubmoduleId: 'PODMODUL_08_SIGNATURE_DETECTION',
        inputTypes: ['event: SecurityEvent', 'rules: DetectionRule[]'],
        outputType: 'ThreatAlert[]',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_BEHAVIORAL_ANALYSIS',
        displayNameSL: 'Vedenjska analiza',
        descriptionSL: 'Analiza vedenjskih vzorcev za detekcijo anomalij',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/detection.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['detection', 'behavioral', 'anomaly'],
        parentSubmoduleId: 'PODMODUL_08_BEHAVIORAL_DETECTION',
        inputTypes: ['events: SecurityEvent[]', 'baseline: BehaviorBaseline'],
        outputType: 'AnomalyResult[]',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // INCIDENT RESPONSE FUNCTIONS
    {
        id: 'FN_08_TRIAGE_INCIDENT',
        displayNameSL: 'Triažiranje incidenta',
        descriptionSL: 'Začetna ocena in prioritizacija incidenta',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/incident-response.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['incident-response', 'triage', 'assessment'],
        parentSubmoduleId: 'PODMODUL_08_TRIAGE',
        inputTypes: ['incident: Incident', 'context: IncidentContext'],
        outputType: 'TriageResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_CONTAIN_THREAT',
        displayNameSL: 'Zadrževanje grožnje',
        descriptionSL: 'Izolacija in zadrževanje grožnje',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/incident-response.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['incident-response', 'containment', 'isolation'],
        parentSubmoduleId: 'PODMODUL_08_CONTAINMENT',
        inputTypes: ['threat: Threat', 'options: ContainmentOptions'],
        outputType: 'ContainmentResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_ERADICATE_THREAT',
        displayNameSL: 'Odstranitev grožnje',
        descriptionSL: 'Popolna odstranitev grožnje iz sistema',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/incident-response.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['incident-response', 'eradication', 'removal'],
        parentSubmoduleId: 'PODMODUL_08_ERADICATION',
        inputTypes: ['threat: Threat', 'options: EradicationOptions'],
        outputType: 'EradicationResult',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // SIGINT FUNCTIONS
    {
        id: 'FN_08_INTERCEPT_COMMS',
        displayNameSL: 'Prestrezanje komunikacij',
        descriptionSL: 'Prestrezanje in analiza komunikacij',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/sigint.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['sigint', 'intercept', 'communications'],
        parentSubmoduleId: 'PODMODUL_08_COMMS_INTERCEPT',
        inputTypes: ['target: InterceptTarget', 'options: InterceptOptions'],
        outputType: 'InterceptResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_ANALYZE_TRAFFIC',
        displayNameSL: 'Analiza prometa',
        descriptionSL: 'Analiza omrežnega prometa',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/sigint.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['sigint', 'traffic', 'analysis'],
        parentSubmoduleId: 'PODMODUL_08_TRAFFIC_ANALYSIS',
        inputTypes: ['traffic: NetworkTraffic', 'options: AnalysisOptions'],
        outputType: 'TrafficAnalysisResult',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // FININT FUNCTIONS
    {
        id: 'FN_08_DETECT_MONEY_LAUNDERING',
        displayNameSL: 'Detekcija pranja denarja',
        descriptionSL: 'Odkrivanje sumljivih finančnih transakcij',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/finint.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['finint', 'aml', 'money-laundering'],
        parentSubmoduleId: 'PODMODUL_08_AML',
        inputTypes: ['transactions: Transaction[]', 'rules: AMLRule[]'],
        outputType: 'AMLAlert[]',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_DETECT_FRAUD',
        displayNameSL: 'Detekcija goljufij',
        descriptionSL: 'Odkrivanje finančnih goljufij',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/finint.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['finint', 'fraud', 'detection'],
        parentSubmoduleId: 'PODMODUL_08_FRAUD_DETECTION',
        inputTypes: ['transactions: Transaction[]', 'patterns: FraudPattern[]'],
        outputType: 'FraudAlert[]',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // OSINT FUNCTIONS
    {
        id: 'FN_08_MONITOR_SOCIAL_MEDIA',
        displayNameSL: 'Spremljanje družbenih omrežij',
        descriptionSL: 'Spremljanje in analiza družbenih omrežij',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/osint.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['osint', 'social-media', 'monitoring'],
        parentSubmoduleId: 'PODMODUL_08_SOCIAL_MEDIA',
        inputTypes: ['targets: SocialTarget[]', 'options: MonitorOptions'],
        outputType: 'SocialMediaResult[]',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_SEARCH_PUBLIC_RECORDS',
        displayNameSL: 'Iskanje javnih evidenc',
        descriptionSL: 'Iskanje po javno dostopnih evidencah',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/osint.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['osint', 'public-records', 'search'],
        parentSubmoduleId: 'PODMODUL_08_PUBLIC_RECORDS',
        inputTypes: ['query: SearchQuery', 'sources: RecordSource[]'],
        outputType: 'PublicRecordResult[]',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // FORENSICS FUNCTIONS
    {
        id: 'FN_08_ACQUIRE_DISK',
        displayNameSL: 'Pridobitev diska',
        descriptionSL: 'Forenzična pridobitev diska',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/forensics.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'disk', 'acquisition'],
        parentSubmoduleId: 'PODMODUL_08_DISK_FORENSICS',
        inputTypes: ['device: Device', 'options: AcquisitionOptions'],
        outputType: 'DiskImage',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_ACQUIRE_MEMORY',
        displayNameSL: 'Pridobitev pomnilnika',
        descriptionSL: 'Forenzična pridobitev pomnilnika',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/forensics.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'memory', 'acquisition'],
        parentSubmoduleId: 'PODMODUL_08_MEMORY_ACQUISITION',
        inputTypes: ['target: MemoryTarget', 'options: MemoryOptions'],
        outputType: 'MemoryDump',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_ANALYZE_MEMORY',
        displayNameSL: 'Analiza pomnilnika',
        descriptionSL: 'Forenzična analiza pomnilnika',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/forensics.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'memory', 'analysis'],
        parentSubmoduleId: 'PODMODUL_08_MEMORY_ANALYSIS',
        inputTypes: ['dump: MemoryDump', 'options: AnalysisOptions'],
        outputType: 'MemoryAnalysisResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_CAPTURE_PACKETS',
        displayNameSL: 'Zajem paketov',
        descriptionSL: 'Zajem omrežnih paketov',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/forensics.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['forensics', 'network', 'capture'],
        parentSubmoduleId: 'PODMODUL_08_PACKET_CAPTURE',
        inputTypes: ['interface: NetworkInterface', 'filter: CaptureFilter'],
        outputType: 'PacketCapture',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // MALWARE ANALYSIS FUNCTIONS
    {
        id: 'FN_08_STATIC_ANALYSIS',
        displayNameSL: 'Statična analiza',
        descriptionSL: 'Statična analiza zlonamerne programske opreme',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/malware.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['malware', 'static', 'analysis'],
        parentSubmoduleId: 'PODMODUL_08_STATIC_ANALYSIS',
        inputTypes: ['sample: MalwareSample', 'options: StaticOptions'],
        outputType: 'StaticAnalysisResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_DYNAMIC_ANALYSIS',
        displayNameSL: 'Dinamična analiza',
        descriptionSL: 'Dinamična analiza zlonamerne programske opreme',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/malware.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['malware', 'dynamic', 'sandbox'],
        parentSubmoduleId: 'PODMODUL_08_DYNAMIC_ANALYSIS',
        inputTypes: ['sample: MalwareSample', 'sandbox: SandboxConfig'],
        outputType: 'DynamicAnalysisResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_RECONSTRUCT_CODE',
        displayNameSL: 'Rekonstrukcija kode',
        descriptionSL: 'Rekonstrukcija izvorne kode iz binarke',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/malware.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['malware', 'decompilation', 'reconstruction'],
        parentSubmoduleId: 'PODMODUL_08_CODE_RECONSTRUCTION',
        inputTypes: ['binary: Binary', 'options: DecompileOptions'],
        outputType: 'ReconstructedCode',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // CYBER WARFARE FUNCTIONS
    {
        id: 'FN_08_OFFENSIVE_OPERATION',
        displayNameSL: 'Ofenzivna operacija',
        descriptionSL: 'Izvedba ofenzivne kibernetske operacije',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/warfare.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['warfare', 'offensive', 'operation'],
        parentSubmoduleId: 'PODMODUL_08_OFFENSIVE_OPS',
        inputTypes: ['target: WarfareTarget', 'mission: Mission'],
        outputType: 'OperationResult',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_DEFENSIVE_OPERATION',
        displayNameSL: 'Defenzivna operacija',
        descriptionSL: 'Izvedba defenzivne kibernetske operacije',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/warfare.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['warfare', 'defensive', 'operation'],
        parentSubmoduleId: 'PODMODUL_08_DEFENSIVE_OPS',
        inputTypes: ['threat: Threat', 'assets: Asset[]'],
        outputType: 'DefenseResult',
        isMeta: false,
        relatedRuleIds: []
    },
    
    // VISUALIZATION FUNCTIONS
    {
        id: 'FN_08_RENDER_2D',
        displayNameSL: 'Izris 2D vizualizacije',
        descriptionSL: 'Izris 2D varnostne vizualizacije',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/visualization.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['visualization', '2d', 'rendering'],
        parentSubmoduleId: 'PODMODUL_08_2D_VIZ',
        inputTypes: ['data: SecurityData', 'config: Viz2DConfig'],
        outputType: 'Visualization2D',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_RENDER_3D',
        displayNameSL: 'Izris 3D vizualizacije',
        descriptionSL: 'Izris 3D varnostne vizualizacije',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/visualization.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['visualization', '3d', 'rendering'],
        parentSubmoduleId: 'PODMODUL_08_3D_VIZ',
        inputTypes: ['data: SecurityData', 'config: Viz3DConfig'],
        outputType: 'Visualization3D',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_RENDER_NETWORK_TOPOLOGY',
        displayNameSL: 'Izris omrežne topologije',
        descriptionSL: 'Izris 3D omrežne topologije',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/visualization.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['visualization', '3d', 'network', 'topology'],
        parentSubmoduleId: 'PODMODUL_08_3D_VIZ',
        inputTypes: ['network: NetworkData', 'config: TopologyConfig'],
        outputType: 'NetworkTopology3D',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_RENDER_ATTACK_PATH',
        displayNameSL: 'Izris napadne poti',
        descriptionSL: 'Vizualizacija napadne poti',
        path: 'knowbank/domene/DOMENA_08/functions/advanced/visualization.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['visualization', '3d', 'attack-path'],
        parentSubmoduleId: 'PODMODUL_08_3D_VIZ',
        inputTypes: ['attack: AttackPath', 'config: AttackPathConfig'],
        outputType: 'AttackPathVisualization',
        isMeta: false,
        relatedRuleIds: []
    }
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

export function getAdvancedCategoryById(id: string): Category | undefined {
    return ADVANCED_CATEGORIES.find(c => c.id === id);
}

export function getAdvancedModuleById(id: string): Module | undefined {
    return ADVANCED_MODULES.find(m => m.id === id);
}

export function getAdvancedFunctionById(id: string): Function | undefined {
    return ADVANCED_FUNCTIONS.find(f => f.id === id);
}

export function getAdvancedModulesByCategory(categoryId: string): readonly Module[] {
    return ADVANCED_MODULES.filter(m => m.parentSubcategoryId?.startsWith(categoryId.replace('KATEGORIJA', 'PODKATEGORIJA')));
}

export function getAdvancedFunctionsByModule(moduleId: string): readonly Function[] {
    const module = getAdvancedModuleById(moduleId);
    if (!module) return [];
    return ADVANCED_FUNCTIONS.filter(f => module.submoduleIds.some(s => f.parentSubmoduleId === s));
}

export function getAllAdvancedCategoryIds(): readonly string[] {
    return ADVANCED_CATEGORIES.map(c => c.id);
}

export function getAllAdvancedModuleIds(): readonly string[] {
    return ADVANCED_MODULES.map(m => m.id);
}

export function getAllAdvancedFunctionIds(): readonly string[] {
    return ADVANCED_FUNCTIONS.map(f => f.id);
}

export function getAdvancedCategoryCount(): number {
    return ADVANCED_CATEGORIES.length;
}

export function getAdvancedModuleCount(): number {
    return ADVANCED_MODULES.length;
}

export function getAdvancedFunctionCount(): number {
    return ADVANCED_FUNCTIONS.length;
}

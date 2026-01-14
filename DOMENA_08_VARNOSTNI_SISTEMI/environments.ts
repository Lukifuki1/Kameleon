import { Environment } from '../../registry/types';

export const ENVIRONMENTS: readonly Environment[] = [
    {
        id: 'OKOLJE_08_SECURITY_BUILD',
        displayNameSL: 'Varnostno gradbeno okolje',
        descriptionSL: 'Okolje za gradnjo varnostnih sistemov z vsemi potrebnimi orodji za SAST, SBOM generiranje in podpisovanje artefaktov.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/environments',
        domainId: 'DOMENA_08',
        type: 'ENVIRONMENT',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['build', 'security', 'sast', 'sbom'],
        environmentKind: 'CONTAINER',
        baseImage: 'ubuntu:22.04',
        platform: 'linux',
        architecture: 'amd64',
        resourceRequirements: {
            cpuCores: 4,
            memoryMb: 8192,
            diskMb: 51200
        },
        networkPolicy: 'RESTRICTED',
        securityLevel: 'HARDENED'
    },
    {
        id: 'OKOLJE_08_SAST_ANALYSIS',
        displayNameSL: 'SAST analizno okolje',
        descriptionSL: 'Izolirano okolje za staticno analizo varnosti izvorne kode z orodji Semgrep, Gitleaks in drugimi SAST skenerji.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/environments',
        domainId: 'DOMENA_08',
        type: 'ENVIRONMENT',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['sast', 'static', 'analysis', 'semgrep'],
        environmentKind: 'CONTAINER',
        baseImage: 'returntocorp/semgrep:latest',
        platform: 'linux',
        architecture: 'amd64',
        resourceRequirements: {
            cpuCores: 8,
            memoryMb: 16384,
            diskMb: 102400
        },
        networkPolicy: 'RESTRICTED',
        securityLevel: 'HARDENED'
    },
    {
        id: 'OKOLJE_08_DAST_TESTIRANJE',
        displayNameSL: 'DAST testno okolje',
        descriptionSL: 'Okolje za dinamicno analizo varnosti z OWASP ZAP in Nuclei za penetracijske teste na zivem sistemu.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/environments',
        domainId: 'DOMENA_08',
        type: 'ENVIRONMENT',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['dast', 'dynamic', 'zap', 'nuclei', 'pentest'],
        environmentKind: 'CONTAINER',
        baseImage: 'owasp/zap2docker-stable:latest',
        platform: 'linux',
        architecture: 'amd64',
        resourceRequirements: {
            cpuCores: 4,
            memoryMb: 8192,
            diskMb: 51200
        },
        networkPolicy: 'RESTRICTED',
        securityLevel: 'HARDENED'
    },
    {
        id: 'OKOLJE_08_VULNERABILITY_SCAN',
        displayNameSL: 'Okolje za skeniranje ranljivosti',
        descriptionSL: 'Okolje za skeniranje ranljivosti v odvisnostih in kontejnerjih z orodji Trivy, Grype in Syft.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/environments',
        domainId: 'DOMENA_08',
        type: 'ENVIRONMENT',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['vulnerability', 'trivy', 'grype', 'sbom'],
        environmentKind: 'CONTAINER',
        baseImage: 'aquasec/trivy:latest',
        platform: 'linux',
        architecture: 'amd64',
        resourceRequirements: {
            cpuCores: 2,
            memoryMb: 4096,
            diskMb: 20480
        },
        networkPolicy: 'RESTRICTED',
        securityLevel: 'HARDENED'
    },
    {
        id: 'OKOLJE_08_SIGNING',
        displayNameSL: 'Okolje za podpisovanje',
        descriptionSL: 'Varno okolje za kriptografsko podpisovanje artefaktov z Cosign in upravljanje kljucev.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/environments',
        domainId: 'DOMENA_08',
        type: 'ENVIRONMENT',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['signing', 'cosign', 'sigstore', 'keys'],
        environmentKind: 'CONTAINER',
        baseImage: 'gcr.io/projectsigstore/cosign:latest',
        platform: 'linux',
        architecture: 'amd64',
        resourceRequirements: {
            cpuCores: 2,
            memoryMb: 2048,
            diskMb: 10240
        },
        networkPolicy: 'ISOLATED',
        securityLevel: 'CERTIFIED'
    },
    {
        id: 'OKOLJE_08_COMPLIANCE',
        displayNameSL: 'Okolje za preverjanje skladnosti',
        descriptionSL: 'Okolje za preverjanje skladnosti z varnostnimi standardi (OWASP, ISO 27001, SOC 2, NIST) in generiranje porocil.',
        path: 'knowbank/domene/DOMENA_08_VARNOSTNI_SISTEMI/environments',
        domainId: 'DOMENA_08',
        type: 'ENVIRONMENT',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['compliance', 'audit', 'owasp', 'iso27001', 'soc2'],
        environmentKind: 'CONTAINER',
        baseImage: 'ubuntu:22.04',
        platform: 'linux',
        architecture: 'amd64',
        resourceRequirements: {
            cpuCores: 2,
            memoryMb: 4096,
            diskMb: 20480
        },
        networkPolicy: 'RESTRICTED',
        securityLevel: 'HARDENED'
    }
];

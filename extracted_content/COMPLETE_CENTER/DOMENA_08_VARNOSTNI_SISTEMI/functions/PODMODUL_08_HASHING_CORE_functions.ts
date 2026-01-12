import { Function } from '../../../registry/types';

export const FUNCTIONS: readonly Function[] = [
    {
        id: 'FN_08_HASH_SHA256',
        displayNameSL: 'SHA-256 zgoscevanje',
        descriptionSL: 'Zgosti podatke s SHA-256. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_HASHING_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'hashing', 'sha256'],
        parentSubmoduleId: 'PODMODUL_08_HASHING_CORE',
        inputTypes: ['Buffer'],
        outputType: 'Hash',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_HASH_SHA3',
        displayNameSL: 'SHA-3 zgoscevanje',
        descriptionSL: 'Zgosti podatke s SHA-3 (Keccak). Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_HASHING_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'hashing', 'sha3', 'keccak'],
        parentSubmoduleId: 'PODMODUL_08_HASHING_CORE',
        inputTypes: ['Buffer'],
        outputType: 'Hash',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_HASH_BLAKE2',
        displayNameSL: 'BLAKE2 zgoscevanje',
        descriptionSL: 'Zgosti podatke z BLAKE2. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_HASHING_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'hashing', 'blake2'],
        parentSubmoduleId: 'PODMODUL_08_HASHING_CORE',
        inputTypes: ['Buffer'],
        outputType: 'Hash',
        isMeta: false,
        relatedRuleIds: []
    }
];

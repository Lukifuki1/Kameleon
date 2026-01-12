import { Function } from '../../../registry/types';

export const FUNCTIONS: readonly Function[] = [
    {
        id: 'FN_08_KDF_PBKDF2',
        displayNameSL: 'PBKDF2 izpeljava',
        descriptionSL: 'Izpelji kljuc s PBKDF2. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_KEY_DERIVATION_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'kdf', 'pbkdf2'],
        parentSubmoduleId: 'PODMODUL_08_KEY_DERIVATION_CORE',
        inputTypes: ['Password', 'Salt', 'Iterations'],
        outputType: 'DerivedKey',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_KDF_SCRYPT',
        displayNameSL: 'scrypt izpeljava',
        descriptionSL: 'Izpelji kljuc s scrypt. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_KEY_DERIVATION_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'kdf', 'scrypt'],
        parentSubmoduleId: 'PODMODUL_08_KEY_DERIVATION_CORE',
        inputTypes: ['Password', 'Salt', 'ScryptParams'],
        outputType: 'DerivedKey',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_KDF_ARGON2',
        displayNameSL: 'Argon2 izpeljava',
        descriptionSL: 'Izpelji kljuc z Argon2. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_KEY_DERIVATION_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'kdf', 'argon2'],
        parentSubmoduleId: 'PODMODUL_08_KEY_DERIVATION_CORE',
        inputTypes: ['Password', 'Salt', 'Argon2Params'],
        outputType: 'DerivedKey',
        isMeta: false,
        relatedRuleIds: []
    }
];

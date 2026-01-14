import { Function } from '../../../registry/types';

export const FUNCTIONS: readonly Function[] = [
    {
        id: 'FN_08_RANDOM_BYTES',
        displayNameSL: 'Nakljucni bajti',
        descriptionSL: 'Generiraj kriptografsko varne nakljucne bajte. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_SECURE_RANDOM_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'random', 'csprng'],
        parentSubmoduleId: 'PODMODUL_08_SECURE_RANDOM_CORE',
        inputTypes: ['number'],
        outputType: 'Buffer',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_RANDOM_UUID',
        displayNameSL: 'Nakljucni UUID',
        descriptionSL: 'Generiraj kriptografsko varen UUID v4. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_SECURE_RANDOM_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'random', 'uuid'],
        parentSubmoduleId: 'PODMODUL_08_SECURE_RANDOM_CORE',
        inputTypes: [],
        outputType: 'string',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_RANDOM_TOKEN',
        displayNameSL: 'Nakljucni token',
        descriptionSL: 'Generiraj kriptografsko varen token. Varnostno-specificno.',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_SECURE_RANDOM_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ['security-specific', 'random', 'token'],
        parentSubmoduleId: 'PODMODUL_08_SECURE_RANDOM_CORE',
        inputTypes: ['TokenConfig'],
        outputType: 'string',
        isMeta: false,
        relatedRuleIds: []
    }
];

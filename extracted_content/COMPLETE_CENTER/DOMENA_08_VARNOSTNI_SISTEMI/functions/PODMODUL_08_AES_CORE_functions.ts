import { Function } from '../../../registry/types';

export const FUNCTIONS: readonly Function[] = [
    {
        id: 'FN_08_AES_ENCRYPT',
        displayNameSL: 'Sifriraj AES',
        descriptionSL: 'Sifriraj AES',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_AES_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: [],
        parentSubmoduleId: 'PODMODUL_08_AES_CORE',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_AES_DECRYPT',
        displayNameSL: 'Desifriraj AES',
        descriptionSL: 'Desifriraj AES',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_AES_CORE_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION' as const,
        version: '1.0.0',
        hash: '',
        links: [],
        tags: [],
        parentSubmoduleId: 'PODMODUL_08_AES_CORE',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    }
];

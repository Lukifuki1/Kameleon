import { Function } from '../../../registry/types';

export const FUNCTIONS: Function[] = [
    {
        id: 'FN_08_AUTH_JWT_INIT',
        displayNameSL: 'Inicializacija',
        descriptionSL: 'Inicializira AUTH JWT komponento za domeno varnostnih sistemov',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_AUTH_JWT_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ["auth","authentication"],
        parentSubmoduleId: 'PODMODUL_08_AUTH_JWT',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_AUTH_JWT_EXECUTE',
        displayNameSL: 'Izvajanje',
        descriptionSL: 'Izvede AUTH JWT operacijo za domeno varnostnih sistemov',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_AUTH_JWT_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ["auth","authentication"],
        parentSubmoduleId: 'PODMODUL_08_AUTH_JWT',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_AUTH_JWT_VALIDATE',
        displayNameSL: 'Validacija',
        descriptionSL: 'Validira AUTH JWT vhodne podatke za domeno varnostnih sistemov',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_AUTH_JWT_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ["auth","authentication"],
        parentSubmoduleId: 'PODMODUL_08_AUTH_JWT',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    }
];

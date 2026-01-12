import { Function } from '../../../registry/types';

export const FUNCTIONS: Function[] = [
    {
        id: 'FN_08_CICD_DEPLOY_INIT',
        displayNameSL: 'Inicializacija',
        descriptionSL: 'Inicializira CICD DEPLOY komponento za domeno varnostnih sistemov',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_CICD_DEPLOY_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ["ci","cd"],
        parentSubmoduleId: 'PODMODUL_08_CICD_DEPLOY',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_CICD_DEPLOY_EXECUTE',
        displayNameSL: 'Izvajanje',
        descriptionSL: 'Izvede CICD DEPLOY operacijo za domeno varnostnih sistemov',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_CICD_DEPLOY_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ["ci","cd"],
        parentSubmoduleId: 'PODMODUL_08_CICD_DEPLOY',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    },
    {
        id: 'FN_08_CICD_DEPLOY_VALIDATE',
        displayNameSL: 'Validacija',
        descriptionSL: 'Validira CICD DEPLOY vhodne podatke za domeno varnostnih sistemov',
        path: 'knowbank/domene/DOMENA_08/functions/PODMODUL_08_CICD_DEPLOY_functions.ts',
        domainId: 'DOMENA_08',
        type: 'FUNCTION',
        version: '1.0.0',
        hash: '',
        links: [],
        tags: ["ci","cd"],
        parentSubmoduleId: 'PODMODUL_08_CICD_DEPLOY',
        inputTypes: [],
        outputType: 'void',
        isMeta: false,
        relatedRuleIds: []
    }
];

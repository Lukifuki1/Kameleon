import { Submodule } from '../../../registry/types';

export const SUBMODULE: Submodule = {
    id: 'PODMODUL_08_HASHING_CORE',
    displayNameSL: 'Zgoscevanje jedro',
    descriptionSL: 'Jedro za varnostno-specificno zgoscevanje',
    path: 'knowbank/domene/DOMENA_08/submodules/PODMODUL_08_HASHING_CORE.ts',
    domainId: 'DOMENA_08',
    type: 'SUBMODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ['security-specific', 'hashing'],
    parentModuleId: 'MODUL_08_HASHING',
    functionIds: [
        'FN_08_HASH_SHA256',
        'FN_08_HASH_SHA3',
        'FN_08_HASH_BLAKE2'
    ]
};

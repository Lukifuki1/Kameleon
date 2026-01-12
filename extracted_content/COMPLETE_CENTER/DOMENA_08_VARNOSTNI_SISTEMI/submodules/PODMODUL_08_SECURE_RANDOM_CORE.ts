import { Submodule } from '../../../registry/types';

export const SUBMODULE: Submodule = {
    id: 'PODMODUL_08_SECURE_RANDOM_CORE',
    displayNameSL: 'Varna nakljucnost jedro',
    descriptionSL: 'Jedro za varnostno-specificno nakljucnost',
    path: 'knowbank/domene/DOMENA_08/submodules/PODMODUL_08_SECURE_RANDOM_CORE.ts',
    domainId: 'DOMENA_08',
    type: 'SUBMODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ['security-specific', 'random'],
    parentModuleId: 'MODUL_08_SECURE_RANDOM',
    functionIds: [
        'FN_08_RANDOM_BYTES',
        'FN_08_RANDOM_UUID',
        'FN_08_RANDOM_TOKEN'
    ]
};

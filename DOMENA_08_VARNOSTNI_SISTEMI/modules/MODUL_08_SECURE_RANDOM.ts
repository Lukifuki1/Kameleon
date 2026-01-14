import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_SECURE_RANDOM',
    displayNameSL: 'Varna nakljucnost',
    descriptionSL: 'Varnostno-specificna nakljucnost - CSPRNG, entropy sources.',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_SECURE_RANDOM.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ['security-specific', 'random', 'csprng', 'entropy'],
    parentSubcategoryId: 'PODKATEGORIJA_08_SYMMETRIC',
    submoduleIds: ['PODMODUL_08_SECURE_RANDOM_CORE']
};

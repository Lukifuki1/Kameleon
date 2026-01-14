import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_HASHING',
    displayNameSL: 'Zgoscevanje',
    descriptionSL: 'Varnostno-specificno zgoscevanje - SHA-256, SHA-3, BLAKE2, password hashing.',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_HASHING.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ['security-specific', 'hashing', 'sha', 'blake'],
    parentSubcategoryId: 'PODKATEGORIJA_08_SYMMETRIC',
    submoduleIds: ['PODMODUL_08_HASHING_CORE']
};

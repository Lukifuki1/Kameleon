import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_KEY_DERIVATION',
    displayNameSL: 'Izpeljava kljucev',
    descriptionSL: 'Varnostno-specificna izpeljava kljucev - PBKDF2, scrypt, Argon2.',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_KEY_DERIVATION.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ['security-specific', 'kdf', 'pbkdf2', 'argon2'],
    parentSubcategoryId: 'PODKATEGORIJA_08_SYMMETRIC',
    submoduleIds: ['PODMODUL_08_KEY_DERIVATION_CORE']
};

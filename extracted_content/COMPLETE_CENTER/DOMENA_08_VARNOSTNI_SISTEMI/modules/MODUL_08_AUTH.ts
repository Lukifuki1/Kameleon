import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_AUTH',
    displayNameSL: 'Avtentikacija',
    descriptionSL: 'Domensko-specificna avtentikacija uporabnikov in sistemov za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_AUTH.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["auth","authentication","identity","login"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_AUTH_JWT","PODMODUL_08_AUTH_OAUTH","PODMODUL_08_AUTH_SESSION"]
};

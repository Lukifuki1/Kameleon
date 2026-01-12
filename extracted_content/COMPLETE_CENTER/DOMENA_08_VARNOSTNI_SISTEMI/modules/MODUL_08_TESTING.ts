import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_TESTING',
    displayNameSL: 'Testiranje',
    descriptionSL: 'Unit, integration, E2E testiranje za domensko-specificne komponente za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_TESTING.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["test","testing","unit_test","integration","e2e"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_TESTING_UNIT","PODMODUL_08_TESTING_INTEGRATION","PODMODUL_08_TESTING_E2E"]
};

import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_CICD',
    displayNameSL: 'CI/CD Pipeline',
    descriptionSL: 'Continuous integration in deployment za domensko-specificne artefakte za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_CICD.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["ci","cd","pipeline","cicd","deployment"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_CICD_BUILD","PODMODUL_08_CICD_DEPLOY","PODMODUL_08_CICD_RELEASE"]
};

import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_LOGGING',
    displayNameSL: 'Belezenje in sledljivost',
    descriptionSL: 'Strukturirano belezenje dogodkov in operacij za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_LOGGING.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["log","logging","logger","audit"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_LOGGING_STRUCTURED","PODMODUL_08_LOGGING_AUDIT","PODMODUL_08_LOGGING_RETENTION"]
};

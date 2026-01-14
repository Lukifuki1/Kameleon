import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_ERROR_HANDLING',
    displayNameSL: 'Obravnava napak',
    descriptionSL: 'Strukturirana obravnava napak in izjem za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_ERROR_HANDLING.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["error","error_handling","exception","fault"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_ERROR_HANDLING_CAPTURE","PODMODUL_08_ERROR_HANDLING_RECOVERY","PODMODUL_08_ERROR_HANDLING_REPORTING"]
};

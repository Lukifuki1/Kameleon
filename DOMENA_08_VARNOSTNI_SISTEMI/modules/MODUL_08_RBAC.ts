import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_RBAC',
    displayNameSL: 'Avtorizacija in dostopne pravice',
    descriptionSL: 'Role-based access control za domensko-specificne vire za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_RBAC.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["rbac","authorization","permission","access_control","role"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_RBAC_ROLES","PODMODUL_08_RBAC_PERMISSIONS","PODMODUL_08_RBAC_POLICIES"]
};

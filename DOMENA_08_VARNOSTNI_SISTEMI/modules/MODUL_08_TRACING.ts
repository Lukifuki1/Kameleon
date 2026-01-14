import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_TRACING',
    displayNameSL: 'Porazdeljeno sledenje',
    descriptionSL: 'Distributed tracing za domensko-specificne operacije za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_TRACING.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["trace","tracing","span","opentelemetry","distributed"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_TRACING_SPANS","PODMODUL_08_TRACING_CONTEXT","PODMODUL_08_TRACING_EXPORT"]
};

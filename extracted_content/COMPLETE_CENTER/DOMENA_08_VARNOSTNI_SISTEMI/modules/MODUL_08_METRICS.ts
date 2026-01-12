import { Module } from '../../../registry/types';

export const MODULE: Module = {
    id: 'MODUL_08_METRICS',
    displayNameSL: 'Metrike in telemetrija',
    descriptionSL: 'Zbiranje in izvoz domensko-specificnih metrik za domeno varnostnih sistemov',
    path: 'knowbank/domene/DOMENA_08/modules/MODUL_08_METRICS.ts',
    domainId: 'DOMENA_08',
    type: 'MODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ["metric","metrics","prometheus","telemetry","monitoring"],
    parentSubcategoryId: 'PODKATEGORIJA_08_ASYMMETRIC',
    submoduleIds: ["PODMODUL_08_METRICS_COUNTERS","PODMODUL_08_METRICS_GAUGES","PODMODUL_08_METRICS_HISTOGRAMS"]
};

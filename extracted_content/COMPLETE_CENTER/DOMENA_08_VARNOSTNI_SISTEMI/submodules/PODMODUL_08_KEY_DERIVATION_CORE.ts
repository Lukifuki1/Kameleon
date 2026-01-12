import { Submodule } from '../../../registry/types';

export const SUBMODULE: Submodule = {
    id: 'PODMODUL_08_KEY_DERIVATION_CORE',
    displayNameSL: 'Izpeljava kljucev jedro',
    descriptionSL: 'Jedro za varnostno-specificno izpeljavo kljucev',
    path: 'knowbank/domene/DOMENA_08/submodules/PODMODUL_08_KEY_DERIVATION_CORE.ts',
    domainId: 'DOMENA_08',
    type: 'SUBMODULE',
    version: '1.0.0',
    hash: '',
    links: [],
    tags: ['security-specific', 'kdf'],
    parentModuleId: 'MODUL_08_KEY_DERIVATION',
    functionIds: [
        'FN_08_KDF_PBKDF2',
        'FN_08_KDF_SCRYPT',
        'FN_08_KDF_ARGON2'
    ]
};

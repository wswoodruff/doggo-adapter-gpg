'use strict';

const Joi = require('joi');

// const Doggo = require('@xdcreative/doggo');
const Schemas = require('@xdcreative/doggo/lib/schema');

console.log('Schemas', Schemas);

// TODO put all the args in a constants object at the
// bottom and reference them from there
// Put comments next to each set of args explaining what
// they'd do in gpg

const internals = {};

module.exports = {
    name: 'gpg',
    genKeys: (genKeyArgs) => {

        Joi.assert(genKeyArgs, Schemas.api.genKeys.request);
    }
    // deleteKey: async (deleteKeyArgs) => {

    //     Joi.assert(deleteKeyArgs, Schemas.api.deleteKey.request);

    //     const {
    //         searchForKeys,
    //         removeFromImportedKeys
    //     } = internals;

    //     const { search, type } = deleteKeyArgs;

    //     const [keyToDelete] = await searchForKeys({
    //         search,
    //         type
    //     });

    //     removeFromImportedKeys(keyToDelete, type);

    //     return true;
    // },
    // importKey: async (importKeyArgs) => {

    //     Joi.assert(importKeyArgs, Schemas.api.importKey.request);

    //     const { key } = importKeyArgs;

    //     const {
    //         getAllKeyValues,
    //         getKeyBasicInfo,
    //         addToImportedKeys
    //     } = internals;

    //     const {
    //         pubAndSecPubKey,
    //         pubAndSecSecKey,
    //         pubOnlyPubKey,
    //         secOnlyPubKey,
    //         secOnlySecKey
    //     } = await getAllKeyValues();

    //     let matchedKey = {};

    //     switch (key) {
    //         case pubAndSecPubKey:
    //             matchedKey = PUB_SEC;
    //             addToImportedKeys(PUB_SEC, 'pub');
    //             break;
    //         case pubAndSecSecKey:
    //             matchedKey = PUB_SEC;
    //             addToImportedKeys(PUB_SEC, 'sec');
    //             break;
    //         case pubOnlyPubKey:
    //             matchedKey = PUB_ONLY;
    //             addToImportedKeys(PUB_ONLY, 'pub');
    //             break;
    //         case secOnlyPubKey:
    //             matchedKey = SEC_ONLY;
    //             addToImportedKeys(SEC_ONLY, 'pub');
    //             break;
    //         case secOnlySecKey:
    //             matchedKey = SEC_ONLY;
    //             addToImportedKeys(SEC_ONLY, 'sec');
    //             break;
    //         default:
    //             throw new InvalidKeyError();
    //     }

    //     // console.log('matchedKey', matchedKey);

    //     return getKeyBasicInfo(matchedKey);
    // },
    // exportKeys: async (exportKeysArgs) => {

    //     Joi.assert(exportKeysArgs, Schemas.api.exportKeys.request);

    //     const { searchForKeys } = internals;

    //     const { search, type } = exportKeysArgs;

    //     const keys = await searchForKeys({
    //         search,
    //         type,
    //         resolve: true
    //     });

    //     return keys
    //         .map(({
    //             fingerprint,
    //             identifier,
    //             keyValues
    //         }) => ({
    //             fingerprint,
    //             identifier,
    //             // importedKeys represents global state like what we have with a gpg keychain
    //             pub: importedKeys[fingerprint].pub ? keyValues.pub : null,
    //             sec: importedKeys[fingerprint].sec ? keyValues.sec : null
    //         }));
    // },
    // listKeys: async (listKeysArgs = {}) => {

    //     Joi.assert(listKeysArgs, Schemas.api.listKeys.request);

    //     const {
    //         searchForKeys,
    //         pickArr
    //     } = internals;

    //     const { search, type } = listKeysArgs;

    //     return pickArr(['fingerprint', 'identifier', 'pub', 'sec'], await searchForKeys({
    //         search,
    //         type
    //     }))
    //         // Make sure either a sec or pub key has been imported
    //         .filter((key) => (!!importedKeys[key.fingerprint].sec || !!importedKeys[key.fingerprint].pub));
    // },
    // encrypt: async (encryptArgs) => {

    //     Joi.assert(encryptArgs, Schemas.api.encrypt.request);

    //     const { search: encryptFor } = encryptArgs;

    //     const { searchForKeys } = internals;

    //     const keys = await searchForKeys({ search: encryptFor });

    //     if (keys.length > 1) {
    //         throw new Doggo.TooManyKeysError();
    //     }

    //     // Cheating here — we expect pubsec's info to be passed to 'search' —
    //     // if we make it this far...
    //     const [pubSec] = keys;

    //     // This couples the mock-adapter to the test for now
    //     // 'carKeys' here === TestKeyInfo.KEYS.PUB_SEC.encryptedText.carKeys
    //     const { encryptedText: { carKeys } } = pubSec;

    //     // Increment the 'naughtyDogBadBoiNoGoodGlobalEncryptionCounter' so we can
    //     // send different responses because true encryption won't ever
    //     // be the exact same twice.
    //     // This cycles through the items in 'carKeys.encrypted'
    //     return carKeys.encrypted[++naughtyDogBadBoiNoGoodGlobalEncryptionCounter % carKeys.encrypted.length];
    // },
    // decrypt: async (decryptArgs) => {

    //     // TODO make this more robust
    //     // Accommodate async
    //     await true;

    //     Joi.assert(decryptArgs, Schemas.api.decrypt.request);

    //     const { KEYS: { PUB_SEC: { encryptedText: { carKeys: { clearText } } } } } = TestKeyInfo;
    //     return clearText;
    // },
    // genPassword: (genPasswordArgs) => {

    //     Joi.assert(genPasswordArgs, Schemas.api.genPassword.request);
    // },
    // utils: {}
};

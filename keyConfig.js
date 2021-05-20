'use strict';

const Os = require('os');

const Dedent = require('./vendor/dedent/dist/dedent');

const internals = {};

// We <3 ed25519/cv25519
const KEY_TYPE = 'eddsa';
const KEY_CURVE = 'ed25519';
const SUBKEY_TYPE = 'ecdh';
const SUB_KEY_CURVE = 'cv25519';

module.exports = {
    get: ({ name, password, comment, email }) => {

        const {
            lineIfParam,
            removeEmptyLines
        } = internals;

        return removeEmptyLines(Dedent`
            Key-Type: ${KEY_TYPE}
            Key-Curve: ${KEY_CURVE}
            Key-Usage: sign
            Subkey-Type: ${SUBKEY_TYPE}
            Subkey-Curve: ${SUB_KEY_CURVE}
            Subkey-Usage: encrypt
            Passphrase: ${password}
            Expire-Date: 0
            ${lineIfParam(name, `Name-Real: ${name}`)}
            ${lineIfParam(comment, `Name-Comment: Doggo user - ' + ${comment}`)}
            ${email ? ('Name-Email:' + email) : ''}
            %no-ask-passphrase
        `);
    }
};

internals.lineIfParam = (param, line) => {

    return `${param ? Os.EOL : ''}${param ? line : ''}`;
};

internals.removeEmptyLines = (arr) => {

    const res = [].concat(arr).map((str) => str.replace(/\n\n/g, ''));

    return res[0];
};

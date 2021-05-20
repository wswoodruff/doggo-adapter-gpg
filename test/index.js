'use strict';

const Code = require('@hapi/code');
const Lab = require('@hapi/lab');
const Joi = require('joi');
const DoggoGenerator = require('@xdcreative/doggo');
const Schemas = require('@xdcreative/doggo/lib/schema');
const DoggoAdapterTestSuite = require('@xdcreative/doggo/test/adapter-test-suite');

const DoggoGpg = require('../lib');

const Doggo = DoggoGenerator(DoggoGpg);

// Test shortcuts

const labScript = exports.lab = Lab.script();
const { it, describe } = labScript;
const expect = Code.expect;

const TEST_UTILS = {
    expect,
    describe,
    it
};

// TODO clear gpg cache before these tests
// Run 'gpgconf --kill gpg-agent'

const cleanupKeys = async (fingerprints) => {

    Joi.assert(fingerprints, Joi.array().items(Joi.string().min(40).max(40)));

    await Promise.all(fingerprints.map((fingerprint) => {

        return Doggo.api.deleteKey({ fingerprint, type: 'all' });
    }));
};

let genFingerprint = null;

describe('doggo-gpg', () => {

    // TODO do this next
    it('Generates a key', { timeout: 4000 }, async () => {

        const res = await Doggo.api.genKeys({
            keyIdentifier: 'doggo-test',
            password: 'doggo-test'
        });

        Joi.assert(res, Schemas.api.genKeys.response);

        // Will clean this up in the next test
        genFingerprint = res.fingerprint;
    });

    // TODO NOTE
    // NOTE it's SUPER scary running this on my local machine — I _gotta_ dockerize these tests
    it('Deletes a key', async () => {

        const res = await Doggo.api.deleteKey({
            fingerprint: genFingerprint,
            type: 'all',
            password: 'doggo-test'
        });

        Joi.assert(res, Schemas.api.deleteKey.response);

        expect(res).to.equal(true);
    });

    // Doggo
    // Test genKeys and stuff like that here
});

/*
    =========================================
    Run DoggoAdapterTestSuite on doggo-gpg
    =========================================
*/

// new DoggoAdapterTestSuite(DoggoGpg, TEST_UTILS).run();

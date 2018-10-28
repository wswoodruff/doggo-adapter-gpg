'use strict';

const Lab = require('lab');
const Code = require('code');

const DoggoAdapterGpg = require('../lib')({});
const DoggoAdapterTestSuite = require('doggo-core/test/adapterTestSuite');

// Test shortcuts

const labScript = exports.lab = Lab.script();
const { it, describe, before, after } = labScript;
const expect = Code.expect;

describe('doggo-adapter-gpg', () => {

    it('passes with the gpg adapter', async (flags) => {

        const testSuite = new DoggoAdapterTestSuite(DoggoAdapterGpg, {
            expect, lab: { it, describe, before, after }
        });

        testSuite.genTests();
    });
});

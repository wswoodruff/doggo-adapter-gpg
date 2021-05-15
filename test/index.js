'use strict';

const Code = require('@hapi/code');
const Lab = require('@hapi/lab');

const DoggoAdapterGpg = require('../lib');
const DoggoAdapterTestSuite = require('@xdcreative/doggo/test/adapter-test-suite');

// Test shortcuts

const labScript = exports.lab = Lab.script();
const { it, describe, before, after } = labScript;
const expect = Code.expect;

describe('doggo-adapter-gpg', () => {

    it('passes the doggo adapter-test-suite', async (flags) => {

        const testSuite = new DoggoAdapterTestSuite(DoggoAdapterGpg, {
            expect,
            describe,
            it
        });

        // testSuite.run();
    });
});

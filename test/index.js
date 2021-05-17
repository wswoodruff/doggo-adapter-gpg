'use strict';

const Code = require('@hapi/code');
const Lab = require('@hapi/lab');

const DoggoGpg = require('../lib');
const DoggoAdapterTestSuite = require('@xdcreative/doggo/test/adapter-test-suite');

// Test shortcuts

const labScript = exports.lab = Lab.script();
const { it, describe } = labScript;
const expect = Code.expect;

const TEST_UTILS = {
    expect,
    describe,
    it
};

describe('doggo-gpg', () => {

    // Test genKeys and stuff like that here
});

/*
    =========================================
    Run DoggoAdapterTestSuite on doggo-gpg
    =========================================
*/

new DoggoAdapterTestSuite(DoggoGpg, TEST_UTILS).run();

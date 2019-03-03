'use strict';

const Os = require('os');
const Util = require('util');
const Fs = require('fs');
const Path = require('path');
const Spawn = require('child_process').spawn;
const Tmp = require('tmp-promise');
const Stream = require('stream');
const PromptList = require('prompt-list');
const KeyConfig = require('./keyConfig');
const Helpers = require('./helpers');

const Utils = require('./utils');

const FILE_NAME_LENGTH_LIMIT = 200;
const INVALID_ARGS = 'Invalid args';

// TODO put all the args in a constants object at the
// bottom and reference them from there
// Put comments next to each set of args explaining what
// they'd do in gpg

const internals = {};

module.exports = (config) => exports;

exports.name = 'gpg';

exports.getOutput = async (adapterProcess) => {

    const p = Utils.getPromise();

    let out = [];
    let errOut = [];

    adapterProcess.stdout.on('data', (data) => {

        out.push(data.toString('utf8'));
    });

    adapterProcess.stderr.on('data', (data) => {

        errOut.push(data.toString('utf8'));
    });

    adapterProcess.on('exit', (code) => {

        let err = null;

        if (code !== 0) {
            err = new Error(errOut.join(Os.EOL).trim());
        }

        if (out.length === 0) {
            // Gpg possibly redirected stdout to stderr (for verifySignature, import, etc)
            out = errOut;
        }

        out = out.join(Os.EOL).trim();

        return p.resolve([err, out, code]);
    });

    return p.promise;
};

// Accepts file paths for srcStream and destStream
// A string can also be used for srcStream

exports.spawnProcess = async (cliArgs, srcStream, destStream, processOptions) => {

    processOptions = processOptions || {};

    if (srcStream && !Utils.isStream(srcStream)) {

        if (srcStream.length <= FILE_NAME_LENGTH_LIMIT && await internals.fileExists(srcStream)) {

            // If this is a filepath, create a read stream from it
            srcStream = await Util.promisify(Fs.createReadStream)(srcStream);
        }
        else {

            // Create stream from text
            const s = new Stream.Readable();
            s.push(srcStream);
            s.push(null);
            srcStream = s;
        }
    }

    if (processOptions.env) {
        processOptions.env = Object.assign(process.env, processOptions.env);
    }

    // Any stdin from gpg gets forwarded to the parent process

    let stdio0 = 'inherit';

    if (srcStream) {
        stdio0 = 'pipe';
    }

    processOptions = Object.assign(processOptions, {
        stdio: [stdio0, 'pipe', 'pipe']
    });

    const adapterProcess = Spawn('gpg', cliArgs, processOptions);

    if (srcStream) {
        srcStream.pipe(adapterProcess.stdin);
    }

    if (destStream) {
        adapterProcess.stdout.pipe(destStream);
    }

    return await exports.getOutput(adapterProcess);
};

exports.keyExists = (keyIdentifier, keyType) =>
    !!exports.utils.firstKeyForIdentifier(keyIdentifier, keyType);

exports.genKeys = async (keyIdentifier, comment, email, password) => {

    if (!keyIdentifier) {
        return { err: new Error('keyIdentifier is required') };
    }

    // A setting to delete the tmp file in the case of an uncaught exception
    Tmp.setGracefulCleanup();

    const tmpF = await Tmp.file();
    const newKey = KeyConfig.get(keyIdentifier, comment, email, password);

    await Util.promisify(Fs.writeFile)(tmpF.path, newKey);

    const optionalOpts = password ? [] : ['--batch'];

    const [err, output] = await exports.spawnProcess([
        ...optionalOpts,
        '--gen-key',
        tmpF.path
    ]);

    tmpF.cleanup();

    return { err, output };
};

// warning: in gpg you will get an error if you don't delete the secret key
// before the public key

exports.deleteKeys = async (keyIdentifier, keyType) => {

    let cliArgs = [];

    let pubOutput = '';
    let secOutput = '';

    // Unlike listKeys,
    // must explicitly specify 'all' when trying to delete all keys

    if (keyType === 'sec' || keyType === 'all') {

        cliArgs = ['--delete-secret-key'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        let secErr;
        [secErr, secOutput] = await exports.spawnProcess(cliArgs);

        if (secErr) {
            return { err: secErr };
        }
    }

    if (keyType === 'pub' || keyType === 'all') {

        cliArgs = ['--batch', '--yes', '--delete-key'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        let pubErr;
        [pubErr, pubOutput] = await exports.spawnProcess(cliArgs);

        if (pubErr) {
            return { err: pubErr };
        }
    }

    return { output: `${pubOutput}\n\n${secOutput}` };
};

exports.importKey = async (keyPathOrString, keyType, password) => {

    // Remove quotes
    keyPathOrString = keyPathOrString.replace(/['"]+/g, '');

    if (keyType !== 'sec' && keyType !== 'pub') {

        return { err: new Error(INVALID_ARGS) };
    }

    let cliArgs = ['--import'];

    if (keyType === 'sec') {
        if (password) {
            cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
        }

        cliArgs = cliArgs.concat([keyPathOrString]);
    }

    const [err, output] = await exports.spawnProcess(
        cliArgs,
        keyType !== 'sec' && keyPathOrString
    );

    return { err, output };
};

exports.exportKey = async (keyIdentifier, keyType, keySavePath, password) => {

    if (!keyIdentifier || (keyType !== 'sec' && keyType !== 'pub')) {
        return { err: new Error(INVALID_ARGS) };
    }

    let cliArgs = ['--batch', '--yes'];

    if (keySavePath) {
        cliArgs = cliArgs.concat(['-o', keySavePath]);
    }

    if (password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
    }

    if (keyType === 'sec') {
        cliArgs = cliArgs.concat(['--export-secret-key']);
    }
    else {
        cliArgs = cliArgs.concat(['--export']);
    }

    cliArgs = cliArgs.concat(['--armor', keyIdentifier]);

    const [err, output] = await exports.spawnProcess(cliArgs);

    return { err, output };
};

exports.listKeys = async (keyIdentifier, keyType) => {

    let cliArgs = [];

    let pubOutput = '';
    let secOutput = '';

    if (!keyType || keyType === 'pub' || keyType === 'all') {

        cliArgs = ['--list-keys'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        // A gpg error is passed if no key is found
        [, pubOutput] = await exports.spawnProcess(cliArgs);
    }

    if (!keyType || keyType === 'sec' || keyType === 'all') {

        cliArgs = ['--list-secret-keys'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        // A gpg error is passed if no key is found
        [, secOutput] = await exports.spawnProcess(cliArgs);
    }

    // Returns shape { pub, sec, output }
    return { output: Utils.parseKeys(keyType, pubOutput, secOutput) };
};

exports.encrypt = async (keyIdentifier, src, destFile, symmetric) => {

    const cliArgs = [
        '--batch',
        '--yes'
    ];

    if (destFile && await internals.fileExists(destFile)) {
        cliArgs.push(...[
            '--output',
            destFile
        ]);
    }

    if (symmetric) {
        cliArgs.push('--symmetric');
    }

    const [err, output] = await exports.spawnProcess(cliArgs.concat([
        '--encrypt',
        '--armor',
        '--recipient',
        keyIdentifier,
        '--trust-model',
        'always'
    ]), src);

    return { err, output };
};

// NOTE: At this time, I can't figure out how to decrypt a string
// with gpg, giving stdin. For now, src must be a valid
// filepath
exports.decrypt = async (src, destPath, password) => {

    // Throw if file doesn't exist
    try {
        await internals.assertFileExists(src);
    }
    catch (err) {
        return { err };
    }

    let cliArgs = ['--batch', '--yes'];

    if (password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
    }

    if (destPath) {
        cliArgs = cliArgs.concat(['-o', destPath]);
    }

    cliArgs = cliArgs.concat(['--decrypt', src]);

    const [err, output] = await exports.spawnProcess(
        cliArgs,
        null,
        destPath
    );

    return { err, output };
};

exports.utils = {
    keysForIdentifier: (keyIdentifier, keyList) =>
        !Array.isArray(keyList) ? [] : keyList.filter((keyItem) =>
            Object.keys(keyItem).find((val) =>
                keyItem[val].includes(keyIdentifier))),

    firstKeyFromList: (keyIdentifier, keyList) =>
        !Array.isArray(keyList) ? undefined : keyList.find((keyItem) =>
            Object.keys(keyItem).find((val) =>
                keyItem[val].includes(keyIdentifier))),

    firstKeyForIdentifier: (keyIdentifier, keyList) =>
        exports.utils.firstKeyFromList(keyIdentifier, exports.utils.keysForIdentifier(keyIdentifier, keyList))
};

internals.fileExists = async (path, shouldThrow) => {

    if (!path) {
        return false;
    }

    let srcIsFile = false;

    try {
        if (path.length <= FILE_NAME_LENGTH_LIMIT) {
            await Util.promisify(Fs.readFile)(path);
            srcIsFile = true;
        }
    }
    catch (err) {

        if (shouldThrow || err.code !== 'ENOENT') {
            throw err;
        }
    }

    return srcIsFile;
};

internals.assertFileExists = async (path) => {

    return await internals.fileExists(path, true);
};

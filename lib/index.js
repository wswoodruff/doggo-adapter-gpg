'use strict';

const Os = require('os');
const Fs = require('fs');
const Path = require('path');
const Spawn = require('child_process').spawn;
const Tmp = require('tmp-promise');
const Cryptiles = require('cryptiles');
const Stream = require('stream');
const PromptList = require('prompt-list');
const Util = require('util');
const KeyConfig = require('./keyConfig');

const Utils = require('./utils');

// TODO put all the args in a constants object at the
// bottom and reference them from there
// Put comments next to each set of args explaining what
// they'd do in gpg

const internals = {};

module.exports = (config) => exports;

exports.name = 'gpg';

exports.getOutput = (adapterProcess) => {

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
            // Possibly redirected stdout to stderr (for verifySignature, import, etc)
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

        if (Fs.existsSync(srcStream)) {

            // If this is a filepath, create a read stream from it
            srcStream = Fs.createReadStream(srcStream);
        }
        else {

            // Create stream from text

            const s = new Stream.Readable();
            s.push(srcStream);
            s.push(null);
            srcStream = s;
        }
    }

    if (destStream && !Utils.isStream(destStream)) {

        // Dest streams must be filepaths
        if (!Fs.existsSync(destStream)) {
            await Util.promisify(Fs.appendFile)(destStream, '');
        }

        destStream = Fs.createWriteStream(destStream);
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

    return exports.getOutput(adapterProcess);
};

// A key identifier must be a unique way to identify a key.
// An email should only be used if there aren't any other keys using that email
// on your system.

exports.getFingerprint = async (keyIdentifier) => {

    // TODO
    const { keys } = await exports.listKeys(keyIdentifier, 'all');

    // console.log('keys', keys);

    const newRes = keys.toString('utf8').split(Os.EOL);
    const fingerprints = [];

    for (let i = 0; i < newRes.length; ++i) {

        const line = newRes[i];

        if (line.startsWith('pub ') || line.startsWith('sec ')) {

            const nextLine = newRes[i + 1];

            // Remove all the spaces

            const nextLineNoSpaces = nextLine.replace(/\s/g, '');
            const nextNextLine = newRes[i + 2];

            fingerprints.push({
                fingerprint: nextLineNoSpaces,
                userRaw: nextNextLine
            });
        }
    }

    // Dedupe because we're grabbing fingerprints from public and secret keys
    // If a key has a public one it doesn't necessarily have a secret one,
    // and vice versa
    const dedupedFingerprints = fingerprints.filter((f, i) => {

        const { fingerprint } = f;
        const firstIndex = fingerprints.findIndex((fngr) => fngr.fingerprint === fingerprint);
        return firstIndex === i;
    });

    return dedupedFingerprints;
};

exports.keyExists = async (keyIdentifier, keyType) => {

    const { pub, sec } = await exports.listKeys(keyIdentifier, keyType);

    return [
        ...pub,
        ...sec
    ]
    .find((keyInfo) => {

        return Object.keys(keyInfo).reduce((collector, key) => {

            return collector;
        }, {});
    });
};

exports.genKeys = async (identifier, password, comment, email) => {

    // A setting to delete the tmp file in the case of an uncaught exception
    Tmp.setGracefulCleanup();

    const tmpF = await Tmp.file();
    const newKey = KeyConfig.get(identifier, password, comment, email);

    await Util.promisify(Fs.writeFile)(tmpF.path, newKey);

    const optionalOpts = password ? [] : ['--batch'];

    const [err, output] = await exports.spawnProcess([
        ...optionalOpts,
        '--gen-key',
        tmpF.path
    ]);

    tmpF.cleanup();

    return Promise.resolve([err, output]);
};

// warning: you will get an error if you don't delete the secret key
// before the public key

exports.deleteKeys = async (keyType, keyIdentifier) => {

    if (keyType !== 'all' && keyType !== 'pub' && keyType !== 'sec') {
        return Promise.resolve([new Error('keyType must be either "all", "pub", or "sec"')]);
    }

    let cliArgs;
    let errs;

    if (keyType === 'pub') {
        cliArgs = ['--batch', '--yes', '--delete-key', keyIdentifier];
    }
    else if (keyType === 'sec') {
        cliArgs = ['--batch', '--yes', '--delete-secret-key', keyIdentifier];
    }
    else if (keyType === 'all') {

        errs = [];

        const [secretErr] = await exports.deleteKeys('sec', keyIdentifier);

        if (secretErr) {
            errs.push(secretErr);
        }

        const [pubErr] = await exports.deleteKeys('pub', keyIdentifier);

        if (pubErr) {
            errs.push(pubErr);
        }

        return Promise.resolve([errs || err]);
    }

    const [err] = await exports.spawnProcess(cliArgs);

    return Promise.resolve([errs || err]);
};

exports.importKey = async (keyType, keyPathOrString, password) => {

    // Remove quotes
    keyPathOrString = keyPathOrString.replace(/['"]+/g, '');

    if (keyType !== 'sec' && keyType !== 'pub') {

        throw new Error('keyType must be either "pub" or "sec"\n');
    }

    let cliArgs = ['--import'];

    if (keyType === 'sec' && password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password, keyPathOrString]);
    }

    const [err, output] = await exports.spawnProcess(
        cliArgs,
        keyType !== 'sec' && keyPathOrString
    );

    if (err) {
        throw err;
    }

    return { output };
};

exports.exportKey = async (keyType, identifier, keySavePath, password) => {

    if (keyType !== 'sec' && keyType !== 'pub') {
        throw new Error('keyType must be either "pub" or "sec"');
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

    cliArgs = cliArgs.concat(['--armor', identifier]);

    const [err, output] = await exports.spawnProcess(cliArgs);

    if (err) {
        throw err;
    }

    return output;
};

// TODO protect against 'gpg: error reading key: No secret key'
// when listing keys, just return no keys or emptystring or
// something, can't just return an error

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

    return Utils.parseKeys(keyType, pubOutput, secOutput);
};

exports.encrypt = async (identifier, src, destFile, symmetric) => {

    const cliArgs = [
        '--batch',
        '--yes',
        '--output',
        destFile || Path.join(process.cwd(), `${String(src)}.gpg`)
    ];

    if (symmetric) {
        cliArgs.push('--symmetric');
    }

    const [err, output] = await exports.spawnProcess(cliArgs.concat([
        '--encrypt',
        '--armor',
        '--recipient',
        identifier,
        '--trust-model',
        'always',
        src
    ]));

    return output;
};

exports.decrypt = async (src, destPath, password) => {

    destPath = destPath || Path.join(process.cwd(), `${String(src)}.decrypt`);

    let cliArgs = [];

    if (password) {
        cliArgs = cliArgs.concat(['--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', password]);
    }

    cliArgs = cliArgs.concat(['-o', destPath, '--decrypt', src]);

    const [err, output] = await exports.spawnProcess(
        cliArgs,
        null,
        destPath
    );

    return output;
};

exports.utils = {
    keysForIdentifier: (keyList, keyIdentifier) => keyList.filter((keyItem) => {

        return Object.keys(keyItem).find((val) => keyItem[val].includes(keyIdentifier));
    }),
    firstKeyFromList: (keyList, keyIdentifier) => keyList.find((keyItem) => {

        return Object.keys(keyItem).find((val) => keyItem[val].includes(keyIdentifier));
    }),
    firstKeyForIdentifier: (keyList, keyIdentifier) => exports.utils.firstKeyFromList(exports.utils.keysForIdentifier(keyList, keyIdentifier)),
}

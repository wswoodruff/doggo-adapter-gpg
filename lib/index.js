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

exports.keyExists = (keyIdentifier, keyType) =>
    !!exports.utils.firstKeyForIdentifier(keyIdentifier, keyType);

exports.genKeys = async (identifier, comment, email, password) => {

    // A setting to delete the tmp file in the case of an uncaught exception
    Tmp.setGracefulCleanup();

    const tmpF = await Tmp.file();
    const newKey = KeyConfig.get(identifier, comment, email, password);

    await Util.promisify(Fs.writeFile)(tmpF.path, newKey);

    const optionalOpts = password ? [] : ['--batch'];

    const [err, output] = await exports.spawnProcess([
        ...optionalOpts,
        '--gen-key',
        tmpF.path
    ]);

    tmpF.cleanup();

    return { output, err };
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
            throw secErr;
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
            throw pubErr;
        }
    }

    return { output: `${pubOutput}\n\n${secOutput}` };
};

exports.importKey = async (keyPathOrString, keyType, password) => {

    // Remove quotes
    keyPathOrString = keyPathOrString.replace(/['"]+/g, '');

    if (keyType !== 'sec' && keyType !== 'pub') {

        throw new Error('keyType must be either "pub" or "sec"\n');
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

    return { output, err };
};

exports.exportKey = async (keyIdentifier, keyType, keySavePath, password) => {

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

    cliArgs = cliArgs.concat(['--armor', keyIdentifier]);

    const [err, output] = await exports.spawnProcess(cliArgs);

    return { output, err };
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
    return Utils.parseKeys(keyType, pubOutput, secOutput);
};

exports.encrypt = async (keyIdentifier, src, destFile, symmetric) => {

    const cliArgs = [
        '--batch',
        '--yes',
        '--output',
        destFile || Path.resolve(process.cwd(), `${String(src)}.gpg`)
    ];

    if (symmetric) {
        cliArgs.push('--symmetric');
    }

    const [err, output] = await exports.spawnProcess(cliArgs.concat([
        '--encrypt',
        '--armor',
        '--recipient',
        keyIdentifier,
        '--trust-model',
        'always',
        src
    ]));

    return { output };
};

exports.decrypt = async (src, destPath, password) => {

    destPath = destPath || Path.resolve(process.cwd(), `${String(src)}.decrypt`);

    let cliArgs = ['--batch', '--yes'];

    if (password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
    }

    cliArgs = cliArgs.concat(['-o', destPath, '--decrypt', src]);

    const [err, output] = await exports.spawnProcess(
        cliArgs,
        null,
        destPath
    );

    return { output, err };
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
        exports.utils.firstKeyFromList(keyIdentifier, exports.utils.keysForIdentifier(keyIdentifier, keyList)),
};

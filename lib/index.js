'use strict';

const Util = require('util');
const Fs = require('fs');
const Path = require('path');
const Spawn = require('child_process').spawn;
const Tmp = require('tmp-promise');
const Stream = require('stream');
const PromptList = require('prompt-list');
const KeyConfig = require('./keyConfig');

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

    let out = '';
    let errOut = '';

    adapterProcess.stdout.on('data', (data) => {

        out += data.toString('utf8');
    });

    adapterProcess.stderr.on('data', (data) => {

        errOut += data.toString('utf8');
    });

    adapterProcess.on('exit', (code) => {

        // The order of these next 2 if statements is importnat

        if (!out && !!errOut) {
            // Gpg sometimes redirects stdout to stderr (for verifySignature, import, etc.)
            // TODO add specific exceptions for this
            out = errOut;
        }

        if (internals.checkForStdErrException(errOut)) {
            errOut = '';
        }

        const knownErrMatchKey = internals.checkOutForErr(out);

        if (knownErrMatchKey && !errOut) {
            errOut = exports.GPG_ERRORS[knownErrMatchKey];
        }

        let err = null;

        if (!!errOut) {
            err = new Error(errOut);
        }

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

    // Nope, not gonna let a password touch a physical file
    // const newKey = KeyConfig.get(keyIdentifier, comment, email, password);
    const newKey = KeyConfig.get(keyIdentifier, comment, email);

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

    if (!keyIdentifier || !keyType || (keyType !== 'pub' && keyType !== 'sec' && keyType !== 'all')) {
        return { err: new Error(INVALID_ARGS) };
    }

    let cliArgs = [];

    let pubOutput = 'No pub keys deleted';
    let secOutput = 'No sec keys deleted';

    // Unlike listKeys,
    // must explicitly specify 'all' when trying to delete all keys

    if (keyType === 'sec' || keyType === 'all') {

        cliArgs = ['--delete-secret-key'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        let secErr;
        ([secErr, secOutput] = await exports.spawnProcess(cliArgs));

        secOutput = secOutput || 'Success';

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
        ([pubErr, pubOutput] = await exports.spawnProcess(cliArgs));

        // With successful deletion, gpg gives no output
        pubOutput = pubOutput || 'Success';

        if (pubErr) {
            return { err: pubErr };
        }
    }

    return {
        pub: pubOutput,
        sec: secOutput
     };
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

    let pubOutput = 'No public keys';
    let secOutput = 'No secret keys';

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

    // Returns shape { pub, sec }
    return { output: Utils.parseKeys(keyType, pubOutput, secOutput) };
};

exports.encrypt = async (keyIdentifier, src, destFile, symmetric) => {

    // src can be a string or filepath

    if ((!symmetric && !keyIdentifier) || !src) {
        return { err: new Error(INVALID_ARGS) };
    }

    let srcIsFile = false;

    if (await internals.fileExists(src)) {
        srcIsFile = true;
    }

    let cliArgs = [
        '--batch',
        '--yes'
    ];

    let output;
    if (destFile) {
        output = destFile;
    }
    else {
        // Sets output to stdout
        // When not passing to stdin, gpg won't pass back to stdout
        output = '-';
    }

    cliArgs = cliArgs.concat(['--output', output]);

    if (symmetric) {
        cliArgs.push('--symmetric');
    }
    else {
        cliArgs = cliArgs.concat([
            '--encrypt'
        ]);
    }

    cliArgs = cliArgs.concat([
        '--armor'
    ]);

    if (!symmetric && keyIdentifier) {
        cliArgs = cliArgs.concat([
            '--recipient',
            keyIdentifier
        ]);
    }

    cliArgs = cliArgs.concat([
        '--trust-model',
        'always'
    ]);

    // If file, pass as last arg
    if (srcIsFile) {
        cliArgs = cliArgs.concat(src);
    }

    const [err, encryptOutput] = await exports.spawnProcess(
        cliArgs,
        // If src is a string, pass to stdin
        !srcIsFile ? src : undefined
    );

    return { err, output: !err ? encryptOutput || 'Success' : encryptOutput };
};

exports.decrypt = async (src, destFile, password) => {

    if (!src) {
        return { err: new Error(INVALID_ARGS) };
    }

    let srcIsFile = false;

    if (await internals.fileExists(src)) {
        srcIsFile = true;
    }

    let cliArgs = ['--batch', '--yes'];

    if (password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
    }

    if (destFile) {
        cliArgs = cliArgs.concat(['--output', output]);
    }

    cliArgs = cliArgs.concat(['--decrypt']);

    // If file, pass as last arg
    if (srcIsFile) {
        cliArgs = cliArgs.concat(src);
    }

    const [err, decryptOutput] = await exports.spawnProcess(
        cliArgs,
        // If src is a string, pass to stdin
        !srcIsFile ? src : undefined
    );

    return { err, output: decryptOutput };
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

    const toThrow = new Error(`File "${path}" does not exist`);

    if (!path) {
        if (shouldThrow) {
            throw toThrow;
        }
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

    if (!srcIsFile && shouldThrow) {
        throw toThrow;
    }

    return srcIsFile;
};

internals.assertFileExists = async (path) => {

    return await internals.fileExists(path, true);
};

internals.checkOutForErr = (maybeErr) => {

    // Just grab the first match
    const [maybeFoundErr] = internals.objStrFind(exports.GPG_ERRORS, maybeErr) || [];
    return maybeFoundErr;
};

internals.checkForStdErrException = (maybeErr) => {

    // Just grab the first match
    const [maybeFoundException] = internals.objStrFind(exports.KNOWN_STDERR_EXCEPTIONS, maybeErr) || [];
    return maybeFoundException;
};

internals.objStrFind = (obj, str) => {

    const lower = str.toLowerCase();

    return Object.entries(obj).find(([key, val]) =>
        val instanceof RegExp ?
        !!lower.match(val) :
        lower.includes(val.toLowerCase()));
};

exports.GPG_ERRORS = {
    NOT_FOUND: 'No such file or directory',
    NO_GPG_DATA: 'no valid OpenPGP data found',
    NO_SECRET_KEY: 'No secret key'
};

exports.KNOWN_STDERR_EXCEPTIONS = {
    // Last check is for the created date
    ENCRYPT_INFO: /encrypted with.+created \d{4}-\d{2}-\d{2}/
};

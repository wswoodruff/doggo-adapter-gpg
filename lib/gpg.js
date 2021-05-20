'use strict';

const Stream = require('stream');
const ChildProcess = require('child_process');
const Fs = require('fs');

const Utils = require('./utils');
const Joi = require('joi');

const GpgError = require('./errors/GpgError');

const FILE_NAME_LENGTH_LIMIT = 200;
const INVALID_ARGS = 'Invalid args';

const internals = {};

// srcStream accepts a string or file path
// destStream accepts a filepath
exports.run = async (runArgs) => {

    Joi.assert(runArgs, Joi.object({
        cliArgs: Joi.array().items(Joi.string()).required(),
        srcStream: Joi.any(),
        destStream: Joi.any(),
        processOptions: Joi.object()
    }));

    const {
        cliArgs,
        destStream
    } = runArgs;

    let {
        processOptions,
        srcStream
    } = runArgs;

    processOptions = processOptions || {};

    if (srcStream && !Utils.isStream(srcStream)) {
        // First check to see if this is a filepath
        if (srcStream.length <= FILE_NAME_LENGTH_LIMIT && await internals.fileExists(srcStream)) {
            // If this is a filepath, create a read stream from it
            srcStream = Fs.createReadStream(srcStream);
        }
        else {
            // Otherwise create a stream from text
            const s = new Stream.Readable();
            s.push(srcStream);
            s.push(null);
            srcStream = s;
        }
    }

    // Any stdin from gpg gets forwarded to the parent process

    let stdio0 = 'inherit';

    if (srcStream) {
        stdio0 = 'pipe';
    }

    processOptions = Object.assign(processOptions, {
        stdio: [stdio0, 'pipe', 'pipe']
    });

    const adapterProcess = ChildProcess.spawn('gpg', cliArgs, processOptions);

    // TODO — change to exec?
    // ChildProcess.exec('find . -type f | wc -l', (err, stdout, stderr) => {

    //     if (err) {
    //         console.error(`exec error: ${err}`);
    //         return;
    //     }

    //     console.log(`Number of files ${stdout}`);
    // });

    if (srcStream) {
        srcStream.pipe(adapterProcess.stdin);
    }

    if (destStream) {
        adapterProcess.stdout.pipe(destStream);
    }

    return await exports.getOutput(adapterProcess);
};

exports.keyExists = (keyIdentifier, type) => {

    return !!exports.utils.firstKeyForIdentifier(keyIdentifier, type);
};

exports.genKeys = async (args) => {

    const { keyIdentifier, comment, email, password } = args;

    // Looks like ' ()'
    const emptyComment = /\s\(\)/;
    // Looks like ' <>'
    const emptyEmail = /\s<>/;

    const createInfo = `${keyIdentifier} (${comment || ''}) <${email || ''}>`
        .replace(emptyComment, '')
        .replace(emptyEmail, '');

    console.log('createInfo', createInfo);

    return await exports.run({
        cliArgs: [
            '--batch',
            '--passphrase',
            password,
            '--quick-generate-key',
            createInfo,
            'ed25519'
        ]
    });
};

// Gpg will error if you don't delete the secret key before the public key
exports.deleteKeys = async (args) => {

    const { fingerprint, type, password } = args;

    // Unlike listKeys, must explicitly specify 'all' when trying to delete all keys
    if (!fingerprint || !type || (type !== 'pub' && type !== 'sec' && type !== 'all')) {
        return { error: new Error(INVALID_ARGS) };
    }

    if (type === 'sec' || type === 'all') {
        await exports.run({
            cliArgs: [
                '--batch',
                '--yes',
                '--passphrase',
                password,
                '--delete-secret-key',
                fingerprint
            ]
        });
    }

    // 'type' must be either 'pub' or 'all' since it must be one of the 3, so we'll delete 'pub' next
    await exports.run({
        cliArgs: [
            '--batch',
            '--yes',
            '--delete-key',
            fingerprint
        ]
    });

    return true;
};

exports.importKey = async (keyPathOrString, type, password) => {

    // Remove quotes
    keyPathOrString = keyPathOrString.replace(/['"]+/g, '');

    if (type !== 'sec' && type !== 'pub') {
        return { error: new Error(INVALID_ARGS) };
    }

    let cliArgs = ['--import'];

    if (type === 'sec') {
        if (password) {
            cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
        }

        cliArgs = cliArgs.concat([keyPathOrString]);
    }

    const [error, output] = await exports.run(
        cliArgs,
        type !== 'sec' && keyPathOrString
    );

    return { error, output };
};

exports.exportKey = async (keyIdentifier, type, keySavePath, password) => {

    // To protect against null being passed in as type
    type = type || 'pub';

    if (!keyIdentifier || (type !== 'sec' && type !== 'pub')) {
        return { error: new Error(INVALID_ARGS) };
    }

    let cliArgs = ['--batch', '--yes'];

    if (keySavePath) {
        cliArgs = cliArgs.concat(['-o', keySavePath]);
    }

    if (password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
    }

    if (type === 'sec') {
        cliArgs = cliArgs.concat(['--export-secret-key']);
    }
    else {
        cliArgs = cliArgs.concat(['--export']);
    }

    cliArgs = cliArgs.concat(['--armor', keyIdentifier]);

    const [error, output] = await exports.run(cliArgs);

    return { error, output };
};

exports.listKeys = async (keyIdentifier, type) => {

    let cliArgs = [];

    let pubOutput = 'No public keys';
    let secOutput = 'No secret keys';

    if (!type || type === 'pub' || type === 'all') {

        cliArgs = ['--list-keys'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        // A gpg error is passed if no key is found
        [, pubOutput] = await exports.run(cliArgs);
    }

    if (!type || type === 'sec' || type === 'all') {

        cliArgs = ['--list-secret-keys'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        // A gpg error is passed if no key is found
        [, secOutput] = await exports.run(cliArgs);
    }

    // Returns shape { pub, sec }
    return { output: Utils.parseKeys(type, pubOutput, secOutput) };
};

exports.encrypt = async (keyIdentifier, src, destFile, symmetric) => {

    // src can be a string or filepath

    if ((!symmetric && !keyIdentifier) || !src) {
        return { error: new Error(INVALID_ARGS) };
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

    const [error, encryptOutput] = await exports.run(
        cliArgs,
        // If src is a string, pass to stdin
        !srcIsFile ? src : undefined
    );

    return { error, output: !error ? encryptOutput || 'Success' : encryptOutput };
};

exports.decrypt = async (src, destFile, password) => {

    if (!src) {
        return { error: new Error(INVALID_ARGS) };
    }

    let srcIsFile = false;

    if (await internals.fileExists(src)) {
        srcIsFile = true;
    }

    let cliArgs = ['--pinentry-mode', 'loopback'];

    if (password) {
        cliArgs = cliArgs.concat(['--passphrase', password]);
    }

    if (destFile) {
        cliArgs = cliArgs.concat(['--output', destFile]);
    }

    cliArgs = cliArgs.concat(['--decrypt']);

    // If file, pass as last arg
    if (srcIsFile) {
        cliArgs = cliArgs.concat(src);
    }

    const [error, decryptOutput] = await exports.run(
        cliArgs,
        // If src is a string, pass to stdin
        !srcIsFile ? src : undefined
    );

    return { error, output: decryptOutput };
};

exports.utils = {
    keysForIdentifier: (keyIdentifier, keyList) => {

        return !Array.isArray(keyList) ? [] : keyList.filter((keyItem) => {

            return Object.keys(keyItem).find((val) => {

                return keyItem[val].includes(keyIdentifier);
            });
        });
    },
    firstKeyFromList: (keyIdentifier, keyList) => {

        return !Array.isArray(keyList) ? undefined : keyList.find((keyItem) => {

            return Object.keys(keyItem).find((val) => keyItem[val].includes(keyIdentifier));
        });
    },
    firstKeyForIdentifier: (keyIdentifier, keyList) => {

        exports.utils.firstKeyFromList(keyIdentifier, exports.utils.keysForIdentifier(keyIdentifier, keyList));
    }
};

exports.getOutput = async (adapterProcess) => {

    const { promise, resolve, reject } = Utils.getPromise();

    if (adapterProcess.exitCode !== null) {
        return Promise.resolve(adapterProcess.exitCode);
    }

    let out = '';

    adapterProcess.on('exit', (code) => {

        return resolve(out);
    });

    adapterProcess.on('close', (code) => {

        return resolve(out);
    });

    adapterProcess.stdout.on('data', (data) => {

        const parsed = data.toString('utf8');
        if (internals.checkStdOutException(parsed)) {
            return reject(new GpgError(`${out}\n${parsed}`));
        }

        out += parsed;
    });

    // TODO update to account for multiple rounds of data
    // like with a debounce or something before the reject?
    // /shrug dunno
    adapterProcess.stderr.on('data', (data) => {

        // TODO account for known GPG operations that are known to write to 'stderr', and resolve here instead
        // Ex: GPG sometimes redirects stdout to stderr (for verifySignature, import, etc.)
        const parsed = data.toString('utf8');
        if (internals.checkStdErrException(parsed)) {
            out += parsed;
            return;
        }

        return reject(new GpgError(parsed));
    });

    return await promise;
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
            await Fs.promises.readFile(path);
            srcIsFile = true;
        }
    }
    catch (error) {
        if (shouldThrow || error.code !== 'ENOENT') {
            throw error;
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

internals.checkStdOutException = (maybeOutput) => {

    const knownExceptions = [
        'No such file or directory',
        'no valid OpenPGP data found',
        'No secret key',
        '[don\'t know]: invalid packet'
    ];

    // If any of these match, we want to put towards stderr instead
    return !!knownExceptions.find((compare) => maybeOutput.match(compare));
};

internals.checkStdErrException = (maybeErr) => {

    const knownExceptions = [
        // This outputs after encrypting something
        /encrypted with.+created \d{4}-\d{2}-\d{2}/,
        // General output after generating a key
        'gpg (GnuPG) 2.2.26; Copyright (C) 2020 Free Software Foundation, Inc.',
        'This is free software: you are free to change and redistribute it.',
        'There is NO WARRANTY, to the extent permitted by law.',
        'usage: gpg',
        'marked as ultimately trusted',
        'revocation certificate stored as'
    ];

    // If any of these match, we want to put towards stdout instead
    return !!knownExceptions.find((compare) => maybeErr.match(compare));
};

internals.objStrFind = (obj, str) => {

    const lower = str.toLowerCase();

    return Object.entries(obj).find(([key, val]) => {

        return val instanceof RegExp
            ? !!lower.match(val)
            : lower.includes(val.toLowerCase());
    });
};

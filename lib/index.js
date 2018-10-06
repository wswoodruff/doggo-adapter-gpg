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

// TODO put all the args in a constants object at the
// bottom and reference them from there
// Put comments next to each set of args explaining what
// they'd do in gpg

const internals = {};

module.exports = (config) => exports;

exports.name = 'gpg';

exports.getOutput = (adapterProcess) => {

    const p = internals.getPromise();

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

    if (srcStream && !internals.isStream(srcStream)) {

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

    if (destStream && !internals.isStream(destStream)) {

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

    const output = await exports.listKeys('all', keyIdentifier);
    const newRes = output.toString('utf8').split(Os.EOL);
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

exports.keyExists = async (keyType, keyIdentifier) => {

    let keysToList = 'all'; // for 'all' and 'any'

    if(keyType === 'public' || keyType === 'secret') {
        keysToList = keyType;
    }

    let listKeysRes = '';

    try {
        listKeysRes = await exports.listKeys(keysToList, keyIdentifier);
    }
    catch(err) {}

    return listKeysRes.includes(keyIdentifier);
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

    if (keyType !== 'all' && keyType !== 'public' && keyType !== 'secret') {
        return Promise.resolve([new Error('keyType must be either "all", "public", or "secret"')]);
    }

    let cliArgs;
    let errs;

    if (keyType === 'public') {
        cliArgs = ['--batch', '--yes', '--delete-key', keyIdentifier];
    }
    else if (keyType === 'secret') {
        cliArgs = ['--batch', '--yes', '--delete-secret-key', keyIdentifier];
    }
    else if (keyType === 'all') {

        errs = [];

        const [secretErr] = await exports.deleteKeys('secret', keyIdentifier);

        if (secretErr) {
            errs.push(secretErr);
        }

        const [pubErr] = await exports.deleteKeys('public', keyIdentifier);

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

    if (keyType !== 'secret' && keyType !== 'public') {

        throw new Error('keyType must be either "public" or "secret"\n');
    }

    let cliArgs = ['--import'];

    if (keyType === 'secret' && password) {
        cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password, keyPathOrString]);
    }

    const [err, output] = await exports.spawnProcess(
        cliArgs,
        keyType !== 'secret' && keyPathOrString
    );

    if (err) {
        throw err;
    }

    return output;
};

exports.exportKey = async (keyType, fingerprint, keySavePath) => {

    if (keyType !== 'secret' && keyType !== 'public') {

        return Promise.resolve([new Error('keyType must be either "public" or "secret"')]);
    }

    const cmd = keyType === 'secret' ? '--export-secret-key' : '--export';

    const cliArgs = [cmd].concat([
        '--armor',
        fingerprint
    ]);

    const [err, output] = await exports.spawnProcess(cliArgs);

    if (keySavePath) {
        Fs.writeFileSync(keySavePath, output);
    }

    return Promise.resolve([err, output]);
};

exports.listKeys = async (keyType, keyIdentifier) => {

    let cliArgs = [];

    let keys = '';

    if (keyType !== 'all' &&
        keyType !== 'public' &&
        keyType !== 'secret') {

        throw new Error('keyType must be "all", "public", or "secret"');
    }

    if (keyType === 'public' || keyType === 'all') {

        cliArgs.push('--list-keys');

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        keys += `${Os.EOL}--------- Public keys ---------${Os.EOL}${Os.EOL}`;

        const [pubErr, pubOutput] = await exports.spawnProcess(cliArgs);

        keys += pubOutput;

        if (pubErr) {
            throw pubErr;
        }
    }

    if (keyType === 'secret' || keyType === 'all') {

        cliArgs.push('--list-secret-keys');

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        keys += `${Os.EOL}${Os.EOL}${Os.EOL}--------- Secret keys ---------${Os.EOL}${Os.EOL}`;

        const [secErr, secretOutput] = await exports.spawnProcess(cliArgs);

        keys += secretOutput;

        if (secErr) {
            throw secErr;
        }
    }

    return keys;
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

internals.isStream = (stream) => {

    // Duck type a stream. Function adapted from node-gpg
    return stream && typeof stream === 'object' && typeof stream.pipe === 'function';
};

internals.getStringBetween = (str, marker1, marker2) => {

    return str.substring(str.indexOf(marker1) + 1, str.indexOf(marker2));
};

internals.parseGpgUser = (userRaw) => {

    // Emails are in arrow brackets
    // Comments are in parens
    // The username is trickier. It's after the [trust-level] (Normally will be [ultimate])

    const email = internals.getStringBetween(userRaw, '<', '>');
    const comment = internals.getStringBetween(userRaw, '(', ')');
    let username = internals.getStringBetween(userRaw, ']', '(');

    // No comment exists, so stop at the email
    if (username === '') {
        username = internals.getStringBetween(userRaw, ']', '<');
    }

    // No email exists, so take the rest of the string
    if (username === '') {
        username = userRaw.slice(userRaw.indexOf(']') + 1);
    }

    username = username.trim();

    return {
        email: email,
        comment: comment,
        username: username
    };
};

internals.getPromise = () => {

    let res;
    let rej;

    const promise = new Promise((resolve, reject) => {

        res = resolve;
        rej = reject;
    });

    return {
        promise: promise,
        resolve: res,
        reject: rej
    };
};

internals.log = (msg) => {

    !config.silent && console.log(msg);
};

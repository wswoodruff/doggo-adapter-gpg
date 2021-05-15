'use strict';

const Util = require('util');
const ChildProcess = require('child_process');
const { promises: Fs } = require('fs');

const Utils = require('./utils');
const Tmp = require('tmp-promise');
const Stream = require('stream');
// const PromptList = require('prompt-list');

const FILE_NAME_LENGTH_LIMIT = 200;
const INVALID_ARGS = 'Invalid args';

const internals = {};

// srcStream accepts a string or file path
// destStream accepts a filepath

exports.run = async (runArgs) => {

    const {
        cliArgs,
        srcStream,
        destStream,
        processOptions
    } = runArgs;

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

    const adapterProcess = ChildProcess.spawn('gpg', cliArgs, processOptions);

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
        return { error: new Error('keyIdentifier is required') };
    }

    // A setting to delete the tmp file in the case of an uncaught exception
    Tmp.setGracefulCleanup();

    const tmpF = await Tmp.file();

    // Nope, not gonna let a password touch a physical file
    // const newKey = KeyConfig.get(keyIdentifier, comment, email, password);
    const newKey = KeyConfig.get(keyIdentifier, comment, email);

    await Util.promisify(Fs.writeFile)(tmpF.path, newKey);

    const optionalOpts = password ? [] : ['--batch'];

    const [error, output] = await exports.run([
        ...optionalOpts,
        '--gen-key',
        tmpF.path
    ]);

    tmpF.cleanup();

    return { error, output };
};

// warning: in gpg you will get an error if you don't delete the secret key
// before the public key

exports.deleteKeys = async (keyIdentifier, keyType) => {

    if (!keyIdentifier || !keyType || (keyType !== 'pub' && keyType !== 'sec' && keyType !== 'all')) {
        return { error: new Error(INVALID_ARGS) };
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
        ([secErr, secOutput] = await exports.run(cliArgs));

        secOutput = secOutput || 'Success';

        if (secErr) {
            return { error: secErr };
        }
    }

    if (keyType === 'pub' || keyType === 'all') {

        cliArgs = ['--batch', '--yes', '--delete-key'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        let pubErr;
        ([pubErr, pubOutput] = await exports.run(cliArgs));

        // With successful deletion, gpg gives no output
        pubOutput = pubOutput || 'Success';

        if (pubErr) {
            return { error: pubErr };
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
        return { error: new Error(INVALID_ARGS) };
    }

    let cliArgs = ['--import'];

    if (keyType === 'sec') {
        if (password) {
            cliArgs = cliArgs.concat(['--pinentry-mode', 'loopback', '--passphrase', password]);
        }

        cliArgs = cliArgs.concat([keyPathOrString]);
    }

    const [error, output] = await exports.run(
        cliArgs,
        keyType !== 'sec' && keyPathOrString
    );

    return { error, output };
};

exports.exportKey = async (keyIdentifier, keyType, keySavePath, password) => {

    // To protect against null being passed in as keyType
    keyType = keyType || 'pub';

    if (!keyIdentifier || (keyType !== 'sec' && keyType !== 'pub')) {
        return { error: new Error(INVALID_ARGS) };
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

    const [error, output] = await exports.run(cliArgs);

    return { error, output };
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
        [, pubOutput] = await exports.run(cliArgs);
    }

    if (!keyType || keyType === 'sec' || keyType === 'all') {

        cliArgs = ['--list-secret-keys'];

        if (keyIdentifier) {
            cliArgs.push(keyIdentifier);
        }

        // A gpg error is passed if no key is found
        [, secOutput] = await exports.run(cliArgs);
    }

    // Returns shape { pub, sec }
    return { output: Utils.parseKeys(keyType, pubOutput, secOutput) };
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
        cliArgs = cliArgs.concat(['--output', output]);
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
    NO_SECRET_KEY: 'No secret key',
    DONT_KNOW: '[don\'t know]: invalid packet'
};

exports.KNOWN_STDERR_EXCEPTIONS = {
    // Last check is for the created date
    ENCRYPT_INFO: /encrypted with.+created \d{4}-\d{2}-\d{2}/
};

internals.getOutput = async (adapterProcess) => {

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

        // The order of these next 2 if statements is important

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

        let error = null;

        if (!!errOut) {
            error = new Error(errOut);
        }

        return p.resolve([error, out, code]);
    });

    return p.promise;
};


const internals = {};

exports.isStream = (stream) => {

    // Duck type a stream. Function adapted from node-gpg
    return stream && typeof stream === 'object' && typeof stream.pipe === 'function';
};

exports.getStringBetween = (str, marker1, marker2) => {

    return str.substring(str.indexOf(marker1) + 1, str.indexOf(marker2));
};

exports.parseGpgUser = (userRaw) => {

    // Emails are in arrow brackets
    // Comments are in parens
    // The username is trickier. It's after the [trust-level] (Normally will be [ultimate])

    const email = exports.getStringBetween(userRaw, '<', '>');
    const comment = exports.getStringBetween(userRaw, '(', ')');
    let username = exports.getStringBetween(userRaw, ']', '(');

    // No comment exists, so stop at the email
    if (username === '') {
        username = exports.getStringBetween(userRaw, ']', '<');
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

exports.getPromise = () => {

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

exports.log = (...msg) => {
    console.log(...msg);
};

exports.regex = {
    keyStart: /^pub|^sec/,
    fingerprint: /\w{40}/,
    uid: /^uid/,
    subKey: /^sub|^ssb/
};

exports.matchFromStr = (str, regex) => {

    str = str || '';

    const newlineSplit = str.split('\n');
    const fIndex = newlineSplit.findIndex((s) => s.match(regex));

    return fIndex > -1 && newlineSplit[fIndex].match(regex);
};

exports.parseKeys = (keyType, pubOutput, secOutput) => {

    // TODO turn these 'sec' and 'pub' into constants/index.js

    switch (keyType) {

        case 'pub':
            return internals.parseKeysFromGpgOutput(pubOutput);

        case 'sec':
            return internals.parseKeysFromGpgOutput(secOutput);

        default:
            return {
                pub: internals.parseKeysFromGpgOutput(pubOutput),
                sec: internals.parseKeysFromGpgOutput(secOutput)
            };
    }
};

exports.trimObjectValues = (obj) => internals.funcObjValues(obj, (val) => (val || '').trim());

internals.funcObjValues = (obj, func) => {

    return internals.objectKeyMap(obj)
        .reduce((collector, [val, key]) => ({
            ...collector,
            [key]: func(val)
        }), {});
};

internals.objectKeyMap = (obj) => Object.keys(obj).map((key) => [obj[key], key]);

internals.findRegex = (arr, regex) => arr.find((str) => {

    const strMatch = str.match(regex);
    return strMatch && strMatch[0];
});

internals.parseKeysFromGpgOutput = (str) => {

    if (!str) {
        return [];
    }

    const { keyStart, fingerprint, uid, subKey } = exports.regex;

    const splitByLines = str.split('\n');

    const keyStartIndices = splitByLines.reduce((collector, line, i) => {

        if (line.match(keyStart)) {
            collector.push(i);
        }

        return collector;
    }, []);

    // In gpg v2, keys are 4 lines long
    // TODO improve key detection to be better than this

    const keyLineLength = 4;

    return keyStartIndices.map((keyStartIndex) => {

        const splitByLinesClone = [...splitByLines];

        const keyLines = splitByLinesClone.splice(keyStartIndex, keyLineLength);
        const findFromKeyLines = internals.findRegex.bind(this, keyLines);

        const results = {
            primaryKey: findFromKeyLines(keyStart),
            fingerprint: findFromKeyLines(fingerprint),
            id: findFromKeyLines(uid),
            subKey: findFromKeyLines(subKey)
        };

        return exports.trimObjectValues(results);
    });
};

'use strict';

exports.assert = (bool, err) => {

    if (![].concat(bool).every((b) => !!b)) {
        if (err instanceof Error) {
            throw err;
        }

        throw new Error(String(err));
    }
};

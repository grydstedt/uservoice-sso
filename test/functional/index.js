var test        = require('tap').test,
    uservoice-sso    = require(__dirname + '/../lib/index.js');

uservoice-sso(function (err, obj) {
    test('functional', function (t) {
        t.equal(err, null, 'error object is null');
        t.end();
    });
});
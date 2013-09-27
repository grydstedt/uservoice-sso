/**
 * Creates SSO token s for your UserVoice account
 *
 * @package uservoice-sso
 * @author Gustav Rydstedt <gustav.rydstedt@gmail.com>
 */

var crypto = require('crypto'); 
var _ = require('underscore');

var UserVoiceSSO;

module.exports = UserVoiceSSO;

// UserVoice documentation does not state which AES is used
// but assume it is AES-256?
var cryptoMode = 'AES-128-CBC';

/**
 * UserVoice SSO Contstructor
 * @param {String} subdomain Subdomain name
 * @param {String} ssoKey SSO key
 */
function UserVoiceSSO(subdomain, ssoKey) {

  // For UserVoice, the subdomain is used as password
  // and the ssoKey is used as salt
  this.subdomain = subdomain;
  this.ssoKey = ssoKey;

  if(!this.subdomain) {
    throw new Error('No UserVoice subdomain given');
  }

  if(!this.ssoKey) {
    throw new Error('No SSO key given. Find it ');
  }

  this.defaults = {};
};

/**
 * Sets default for the UserVoice object
 * @param {String} key   Key to set
 * @param {Strubg} value Value to set key to
 *
 * also accepts an object as first parameter
 * e.g userVoice.setDefault({updates: true});
 * 
 */
UserVoiceSSO.prototype.setDefault = function(key, value) {
  if(_.isObject(key)) {
    // Given an object
    this.defaults = _.extend(this.defaults, key);
  } else {
    // Given key and value
    this.defaults[key] = value;
  }
};

/**
 * Creates a token from a uservoice 
 *
 * @param {Object} user  User options  
 * 
 * guid (String)  yes         (Required) A unique identifier for the user (ex: the user_id in your system).
 * expires (Date)             Expiry time of the token in format YYYY-MM-DD HH:MM:SS and is in GMT. Defaults to never expiring.
 * email (String)             If not set the user will not get any activity or update emails. **(strongly recommended)**.
 * display_name (String)      If not set the user will be shown as ‘anonymous’.
 * locale  (String)           ar, bg, cn, cz, da, de, en, es, et, fi, fr, fr-CA, he, hr, it, ja, lv, nl, no_NB, pl, pt, pt_BR, ro, ru, sk, sl, sr, sr-Latn, sv-SE, tr, zh-TW  Set this users locale (language).
 * trusted (Boolan)           false true, false Defaults to false. True indicates that the email you’re using is trusted, which lets you SSO into admin users and revoke adminship of users. trusted=false can’t log you into an admin unless you pass admin:accept
 * owner (String)             accept, deny  Make this user an owner of your UserVoice account giving them access to adding admins, changing plans and billing info.
 * admin (String)             accept, deny  Grant the user account admin access. NOTE: admin:deny requires trusted:true
 * allow_forums (Array)       Exclusive list of Forum ids user has access to (doesn’t restrict admins).
 * deny_forums (Array)        List of Forum ids user does not have access to (doesn’t restrict admins).
 * url (URL)                  Sets all user profile links to this URL. Only set if you don’t want people to see each other’s UserVoice profiles and use your own URL.
 * avatar_url (URL)           Dimensions are 50px by 50px. If left blank an avatar will be pulled from Gravatar
 * updates (Boolean)          Whether the user will receive updates on suggestions (on create only)
 * comment_updates (Boolean)  Whether the user will receive updates on suggestion comments (on create only)
 */
UserVoiceSSO.prototype.createToken = function(user) {

  var iv, password, saltedHash, token, cipher, padLen;

  // User needs to be an object
  if(!_.isObject(user)) {
    return callback('Given user is not an object.');
  }

  // GUID is required for UserVoice SSO
  if(!_.isString(user.guid)) {
    return callback('User object did not have a guid');
  }

  // Set user defaults
  user = _.defaults(user, this.defaults);

  user = new Buffer(JSON.stringify(user));


  // IV that uservoice uses is apparently 'OpenSSL for Ruby'
  iv = new Buffer('OpenSSL for Ruby');

  // XOR the IV into the data to be encrypted
  _.range(0, 16).forEach(function(i) {
    user[i] = user[i] ^ iv[i];
  });

  // Constuct the password by SHA1 hashing the concatenation
  // of the password and the salt
  saltedHash =
    crypto.createHash('sha1')
     .update((this.ssoKey + this.subdomain), 'utf-8')
     .digest()
     .slice(0, 16);

  // Pad the data!
  padLen = 16 - user.length % 16;

  _.range(0, padLen).forEach(function(i) {
    user += String.fromCharCode(padLen);
  });

  // Encrypt user data using hashed password and iv
  cipher = crypto.createCipheriv(cryptoMode, saltedHash, iv);
  cipher.setAutoPadding(false);
  token = cipher.update(new Buffer(user, 'utf-8'), 'utf-8');

  // Escape the token to be used in URLs
  return encodeURIComponent(token.toString('base64'));
};
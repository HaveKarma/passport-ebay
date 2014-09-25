/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , debug = require('debug')('passport-ebay:strategy')
  , BadRequestError = require('./errors/badrequesterror');


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify, ebayClient) {
  // if (typeof options == 'function') {
  //   verify = options;
  //   options = {};
  // }
  // if (!verify) throw new Error('local authentication strategy requires a verify function');

  // this._usernameField = options.usernameField || 'username';
  // this._passwordField = options.passwordField || 'password';

  if (!ebayClient)
    ebayClient = require('ebay-api');

  this._ebayClient = ebayClient;
  this._verify = verify;

  passport.Strategy.call(this);
  this.name = 'ebay';
  // this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {

  var self = this;

  if (req.query && req.query['tknexp'] && req.query['username']) {
    debug("Passport-ebay authenticate, received token");

    var tknexp = req.query.tknexp;
    var username = req.session.username = req.query.username;
    var sessionID = req.session.sessionID;

    debug("Received params tknexp : %s, username : %s", tknexp, username);
    debug("Session ID from session : " + sessionID);

    var input = {
      serviceName : 'Trading',
      opType : 'FetchToken',

      devName: req.app.get('ebay-auth-devName'),
      cert: req.app.get('ebay-auth-cert'),
      appName: req.app.get('ebay-auth-appName'),

      sandbox: req.app.get('ebay-auth-sandbox'),

      params: {
        'authToken': req.app.get('ebay-auth-ownertoken'),
        // 'RuName': ruName,
        'SessionID': sessionID
      }
    };

    debug("Passport-ebay authenticate, input : %s", util.inspect(input));

    //require('ebay-api')
    self._ebayClient.ebayApiPostXmlRequest(input, function(error, results) {
      if (error) {
        debug("Passport-ebay FetchToken callback error");
        debug(util.inspect(error));
        process.exit(1);
      }

      debug("Passport-ebay FetchToken callback");

      debug(util.inspect(results));
      var eBayAuthToken = req.session.eBayAuthToken = results.eBayAuthToken;

      debug("eBayAuthToken : " + eBayAuthToken);

      // var url = ebay.buildRequestUrl('Signin', {RuName : ruName, SessID : sessionID}, null, sandbox);
      // url = util.format("https://signin.sandbox.ebay.com/ws/eBayISAPI.dll?SignIn&RuName=%s&SessID=%s", ruName, sessionID );

      // console.log(url);
      // req.res.redirect("/");

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }

      var profile = self.userProfile(self, req, eBayAuthToken, username, function(err, profile) {
        self._verify(eBayAuthToken, profile, verified);
      });

    });
  }
  else {
    debug("Passport-ebay authenticate, generating session and redirecting to ebay auth");

    var input = {
      serviceName : 'Trading',
      opType : 'GetSessionID',

      devName: req.app.get('ebay-auth-devName'),
      cert: req.app.get('ebay-auth-cert'),
      appName: req.app.get('ebay-auth-appName'),

      sandbox: req.app.get('ebay-auth-sandbox'),

      params: {
        'authToken': req.app.get('ebay-auth-ownertoken'),
        'RuName': req.app.get('ebay-auth-ruName')
      }

    };

    debug("Passport-ebay authenticate, input : %s", util.inspect(input));

    self._ebayClient.ebayApiPostXmlRequest(input, function(error, results) {
      if (error) {
        debug("Passport-ebay GetSessionID callback error");
        debug(util.inspect(error));
        process.exit(1);
      }

      debug("Passport-ebay GetSessionID callback");

      debug(util.inspect(results));
      var sessionID = req.session.sessionID = results.SessionID;

      debug("Session ID : " + sessionID);

      var url = require('ebay-api').buildRequestUrl('Signin', {RuName : req.app.get('ebay-auth-ruName'), SessID : sessionID}, null, req.app.get('ebay-auth-sand'));
      url = util.format("https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&RuName=%s&SessID=%s&ruparams=signup", req.app.get('ebay-auth-ruName'), sessionID );

      debug("Redirecting to : " + url);
      req.res.redirect(url);
    });
  }

  // options = options || {};
  // var username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
  // var password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);

  // if (!username || !password) {
  //   return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
  // }

  // var self = this;

  // function verified(err, user, info) {
  //   if (err) { return self.error(err); }
  //   if (!user) { return self.fail(info); }
  //   self.success(user, info);
  // }

  // if (self._passReqToCallback) {
  //   this._verify(req, username, password, verified);
  // } else {
  //   this._verify(username, password, verified);
  // }

  // function lookup(obj, field) {
  //   if (!obj) { return null; }
  //   var chain = field.split(']').join('').split('[');
  //   for (var i = 0, len = chain.length; i < len; i++) {
  //     var prop = obj[chain[i]];
  //     if (typeof(prop) === 'undefined') { return null; }
  //     if (typeof(prop) !== 'object') { return prop; }
  //     obj = prop;
  //   }
  //   return null;
  // }
}

Strategy.prototype.userProfile = function(self, req, token, username, done) {

  debug("userProfile, token : %s, username : %s", username, token);

  // if (!this._skipExtendedUserProfile) {

  var input = {
    serviceName : 'Trading',
    opType : 'GetUser',

    devName: req.app.get('ebay-auth-devName'),
    cert: req.app.get('ebay-auth-cert'),
    appName: req.app.get('ebay-auth-appName'),

    sandbox: req.app.get('ebay-auth-sandbox'),

    params: {
      'authToken': token,
    }

  };

  self._ebayClient.ebayApiPostXmlRequest(input, function(error, results) {
    if (error) {
      debug("Passport-ebay GetUser callback error");
      debug(util.inspect(error));
      process.exit(1);
    }

    debug("Passport-ebay GetUser callback");
    debug(util.inspect(results));

    var email = results.User.Email;

    debug("email : " + email);

    var profile = { provider: 'ebay', username : username, email : email, displayName : username };
    profile._json = results.User;

    done(null, profile);

  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

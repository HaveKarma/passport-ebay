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
  this._devName = options.devName;
  this._cert = options.cert;
  this._appName = options.appName;
  this._ruName = options.ruName;
  this._sandbox = options.sandbox;
  if (!ebayClient)
    ebayClient = require('ebay-api');

  this._ebayClient = ebayClient;
  this._verify = verify;

  passport.Strategy.call(this, options, verify);
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
    console.log('OPTIONS: -----> '.rainbow + JSON.stringify(options));
  var self = this;

  if (req.query && req.query['tknexp'] && req.query['username']) {
    console.log("Passport-ebay authenticate, received token");

    var tknexp = req.query.tknexp;
    var username = req.session.username = req.query.username;
    var sessionID = req.session.sessionID;

    console.log("Received params tknexp : %s, username : %s", tknexp, username);
    console.log("Session ID from session : " + sessionID);

    var input = {
      serviceName : 'Trading',
      opType : 'FetchToken',

      devName: this._devName,
      cert: this._cert,
      appName: this._appName,

      sandbox: this._sandbox,

      params: {
        'SessionID': sessionID
      }
    };

    console.log("Passport-ebay authenticate, input : %s", util.inspect(input));

    //require('ebay-api')
    self._ebayClient.ebayApiPostXmlRequest(input, function(error, results) {
      if (error) {
        console.log("Passport-ebay FetchToken callback error");
        console.log(util.inspect(error));
        process.exit(1);
      }

      console.log("Passport-ebay FetchToken callback".rainbow);

      console.log(util.inspect(results));
      var eBayAuthToken = req.session.eBayAuthToken = results.FetchTokenResponse.eBayAuthToken;

      console.log("eBayAuthToken : ".rainbow + eBayAuthToken);

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }

      var profile = self.userProfile(self, req, eBayAuthToken, username, function(req, accessToken, refreshToken, profile, done) {
        self._verify(req, accessToken, refreshToken, profile, verified);
        //done(req, token, null, profile);
      });

    });
  }
  else {
    console.log("Passport-ebay authenticate, generating session and redirecting to ebay auth");

    var input = {
      serviceName : 'Trading',
      opType : 'GetSessionID',

      devName: this._devName,
      cert: this._cert,
      appName: this._appName,

      sandbox: this._sandbox,

      params: {
        'RuName': this._ruName
      }

    };

    console.log("Passport-ebay authenticate, input : %s".blue, util.inspect(input));

    var self = this;
    self._ebayClient.ebayApiPostXmlRequest(input, function(error, results) {
      if (error || (results && results.eBay && results.eBay.Errors)) {
        console.log("Passport-ebay GetSessionID callback error");
        console.log(util.inspect(error));
        console.log(JSON.stringify(results, null, 4));
        // process.exit(1);
        req.res.redirect('/debug');
        return;
      }

      console.log("Passport-ebay GetSessionID callback SUCCESS ".rainbow);
      console.log('error: ' + JSON.stringify(error, null, 4));
      console.log('results: ' + JSON.stringify(results, null, 4));
      var sessionID = req.session.sessionID = results.GetSessionIDResponse.SessionID;

      console.log("Session ID : " + sessionID);

      var url = require('ebay-api').buildRequestUrl('Signin', {RuName : +self._ruName, SessID : sessionID}, null, self._sandbox);
      url = util.format("https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&RuName=%s&SessID=%s", self._ruName, sessionID ); //&ruparams=signup

      console.log("Redirecting to : " + url);
      req.res.redirect(url);

    });
  }
}

Strategy.prototype.userProfile = function(self, req, token, username, done) {
    console.log('self: '.red + self);
    console.log('req: '.blue + req);
    console.log('token: '.green + token);
    console.log('username: '.yellow + username);
    console.log('done: '.red + done);
  console.log("\n\n\nuserProfile, token : %s, username : %s", token, username);
  console.log('-----> ' + this._devName);
  // if (!this._skipExtendedUserProfile) {

  var input = {
    serviceName : 'Trading',
    opType : 'GetUser',

    devName: this._devName,
    cert: this._cert,
    appName: this._appName,

    sandbox: this._sandbox,

    params: {
      'authToken': token,
    }

  };

  self._ebayClient.ebayApiPostXmlRequest(input, function(error, results) {
    if (error) {
      console.log("Passport-ebay GetUser callback error");
      console.log(util.inspect(error));
      process.exit(1);
    }

    console.log("Passport-ebay GetUser callback");
    console.log(util.inspect(results));

    console.log(JSON.stringify(results.GetUserResponse.User[0], null, 4));
    var email = results.GetUserResponse.User[0].Email;

    console.log("email : " + email);

    // var profile = {
    //     provider: 'ebay',
    //     username : username,
    //     email : email,
    //     displayName : username,
    //     id: username
    // };
    // profile._json = results.GetUserResponse.User[0];

    var profile = { provider: 'ebay' };

    profile.id = username;
    profile._raw = JSON.stringify(results.GetUserResponse.User[0]);
    profile._json = results.GetUserResponse.User[0];
    // @TODO this is a fucking mess... but I'm working with someone else's code...
    console.log('WTF VERIFY'.zebra + self._verify);
    // self._verify(req, token, null, profile, done);
    done(req, token, null, profile);
    // done(null, 'helloworld');

  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

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
  console.log('FUCK YOU OPTIONS: -----> ' + JSON.stringify(options));
  this._devName = options.devName;
  this._cert = options.cert;
  this._appName = options.appName;
  this._ruName = options.ruName;
  this._sandbox = options.sandbox;
  if (!ebayClient)
    ebayClient = require('ebay-api');

  this._ebayClient = ebayClient;
  this._verify = verify;

  passport.Strategy.call(this, options);
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
    console.log('OPTIONS: -----> ' + JSON.stringify(options));
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
        'authToken': 'AgAAAA**AQAAAA**aAAAAA**XUcjVA**nY+sHZ2PrBmdj6wVnY+sEZ2PrA2dj6wJnYOkAJeEpgWdj6x9nY+seQ**IHkCAA**AAMAAA**ww2C/7H0edNwdf+GSRrNcDlmaMwVoW0DlahL11twvCAxZtKiqo7Wyu8lvq7WNfUpJC2SUFtlQ4QSzT3CBeslnDPV1wL8GKabFO87FwW9iAbgfMDYAXHxSEYI9qMIuU1oRQqcU7517mjpx8bTrnUA/9SKAmyIcJV0+oeo6UCi+yjlHYdQ54/TFadbNTw3HZgGNp1m4eMJtc1McIpkqdU8XIlaRkJ+RbnIWkqNO7Jjts/LzfOm0GvtF4Ad3VriYYcYBke5zKrmNVGAaCr7X7biu2vyu2P8rLjqxWJEIpl5uk5dBroPnNYWwy+fUabI4X1tM0g9YuuumT2+K8BN/UI9vy0kjCuf797HfpZ94wKHDgupSCPengmm8y9KuqVaTRWRlakJka/tmY2MXZwTkYzewS+8U5m+mctg9rWpX01F/2GS7bBmshBcCdlkq6L1BhmlpYiUiSFaOWW8MzsU64Pd9b7XB3b4slUOdxYFRHmJ0sI/6IgO5nmEeXY0rZpQUCfiQvkyonLlEkFqrEPp+Ig6hBv/JFK1r+jDdiOAjjjxA1wk6VA55ZNPkSPZjSmoOCoNOOsiVmPCm1/yDwHKi4w3uCY8gJGaPWnEU18MT7zbIGVGSHPBBgr/IW79p4VjL9b6AiOHCPjBFJhkpOj1DBuf4ty2/G7KwgY9OwgUNFZ3PkA9EfamIAiQtFW8JEGM6/EcOB4nmqdPY3PUymJ+Tl3LWS1sqTAm+h61Mby+CKQu0ll+53qc5o3df9FhK0xSAzRp',
        'RuName': this._ruName,
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

      console.log("Passport-ebay FetchToken callback");

      console.log(util.inspect(results));
      var eBayAuthToken = req.session.eBayAuthToken = results.eBayAuthToken;

      console.log("eBayAuthToken : " + eBayAuthToken);

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
    console.log("Passport-ebay authenticate, generating session and redirecting to ebay auth");

    var input = {
      serviceName : 'Trading',
      opType : 'GetSessionID',

      devName: this._devName,
      cert: this._cert,
      appName: this._appName,

      sandbox: this._sandbox,

      params: {
        // 'authToken': 'AgAAAA**AQAAAA**aAAAAA**XUcjVA**nY+sHZ2PrBmdj6wVnY+sEZ2PrA2dj6wJnYOkAJeEpgWdj6x9nY+seQ**IHkCAA**AAMAAA**ww2C/7H0edNwdf+GSRrNcDlmaMwVoW0DlahL11twvCAxZtKiqo7Wyu8lvq7WNfUpJC2SUFtlQ4QSzT3CBeslnDPV1wL8GKabFO87FwW9iAbgfMDYAXHxSEYI9qMIuU1oRQqcU7517mjpx8bTrnUA/9SKAmyIcJV0+oeo6UCi+yjlHYdQ54/TFadbNTw3HZgGNp1m4eMJtc1McIpkqdU8XIlaRkJ+RbnIWkqNO7Jjts/LzfOm0GvtF4Ad3VriYYcYBke5zKrmNVGAaCr7X7biu2vyu2P8rLjqxWJEIpl5uk5dBroPnNYWwy+fUabI4X1tM0g9YuuumT2+K8BN/UI9vy0kjCuf797HfpZ94wKHDgupSCPengmm8y9KuqVaTRWRlakJka/tmY2MXZwTkYzewS+8U5m+mctg9rWpX01F/2GS7bBmshBcCdlkq6L1BhmlpYiUiSFaOWW8MzsU64Pd9b7XB3b4slUOdxYFRHmJ0sI/6IgO5nmEeXY0rZpQUCfiQvkyonLlEkFqrEPp+Ig6hBv/JFK1r+jDdiOAjjjxA1wk6VA55ZNPkSPZjSmoOCoNOOsiVmPCm1/yDwHKi4w3uCY8gJGaPWnEU18MT7zbIGVGSHPBBgr/IW79p4VjL9b6AiOHCPjBFJhkpOj1DBuf4ty2/G7KwgY9OwgUNFZ3PkA9EfamIAiQtFW8JEGM6/EcOB4nmqdPY3PUymJ+Tl3LWS1sqTAm+h61Mby+CKQu0ll+53qc5o3df9FhK0xSAzRp',
        'RuName': this._ruName,
        'WarningLevel': 'High'
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

  console.log("userProfile, token : %s, username : %s", username, token);
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

    var email = results.User.Email;

    console.log("email : " + email);

    var profile = { provider: 'ebay', username : username, email : email, displayName : username };
    profile._json = results.User;

    done(null, profile);

  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

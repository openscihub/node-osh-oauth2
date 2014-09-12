var crypto = require('crypto');
var auth = require('basic-auth');
var log = require('osh-util/logger')('OAuth2');
var bcrypt = require('bcrypt');
var extend = require('xtend/mutable');
var merge = require('xtend/immutable');
var Class = require('osh-class');
var series = require('osh-util/series');
var parseForm = require('body-parser').urlencoded({extended: false});
var url = require('url');
var tick = process.nextTick;



var OAuth2Error = Class(Error, function(opts) {
  extend(this, opts);
  this.message = opts.code + ': ' + (opts.desc || '');
  //this._super(opts.desc);
});

function error(msg) {
  return new Error('OSH OAuth2: ' + msg);
}

function implement(method) {
  return function(req, res, next) {
    next(
      error('must implement ' + method)
    );
  };
}

function pass(req, res, next) {
  next();
}

function generateToken(callback) {
  crypto.randomBytes(256, function(ex, buffer) {
    if (ex) {
      return callback(new Error(
        'Error generating random bytes for token'
      ));
    }
    callback(null,
      crypto.createHash('sha1')
      .update(buffer)
      .digest('hex')
    );
  });
}

function implementModelMethod(methodName) {
  return function() {
    var err = new Error('Implement ' + this.name + '.' + methodName);
    var callback = arguments.length && arguments[arguments.length - 1];
    if ('function' == typeof callback) {
      process.nextTick(function() {
        callback(err);
      });
    }
    else throw err;
  }
}


var DefaultModel = {
  save: implementModelMethod('save(model, callback)'),
  load: implementModelMethod('load(id, callback)'),
  del: implementModelMethod('del(id, callback)'),
  validateId: implementModelMethod('validateId(id)')
};

var DefaultAuthorizationCode = merge(DefaultModel, {
  name: 'AuthorizationCode',
  id: function(client, user, scope, callback) {
    generateToken(callback);
  },
  lifetime: implementModelMethod(
    'lifetime: {String|Function(client, user, scope, callback)}'
  )
});


var DefaultClient = merge(DefaultModel, {
  name: 'Client',
  validateId: function(id) {
    return /[0-9a-z_]+/.test(id);
  },
  validateRedirectUri: implementModelMethod(
    'validateRedirectUri(uri, client)'
  )
});

var DefaultUser = merge(DefaultModel, {
  name: 'User'
});

var DefaultAccessToken = merge(DefaultModel, {
  name: 'AccessToken',
  lifetime: implementModelMethod(
    'lifetime: {String|Function(client, user, scope, callback)}'
  )
});

var DefaultRefreshToken = merge(DefaultModel, {
  name: 'RefreshToken',
  lifetime: implementModelMethod(
    'lifetime: {String|Function(client, user, scope, callback)}'
  )
});


/**
 *  Default methods.
 */

var OAuth2Request = Class(function(opts) {
  this.req = opts.req;
  this.res = opts.res;
});

extend(OAuth2Request.prototype, {
  grants: [],

  authorizationScope: 'authorization',

  allowGrant: function(grant, client) {
    return this.grants.indexOf(grant) > -1;
  }
});



var OAuth2 = Class(function(opts) {
  this.OAuth2Request = Class(OAuth2Request, function(opts) {
    this._super(opts);
  });

  extend(this.OAuth2Request.prototype, opts, {
    User: merge(DefaultUser, opts.User),
    Client: merge(DefaultClient, opts.Client),
    AccessToken: merge(DefaultAccessToken, opts.AccessToken),
    RefreshToken: merge(DefaultRefreshToken, opts.RefreshToken),
    AuthorizationCode: merge(DefaultAuthorizationCode, opts.AuthorizationCode)
  });

});




OAuth2.FLOWS = {
  TOKEN: [
    'init',
    'validateTokenRequest',
    'branchTokenRequest'
  ],

  /**
   *  For requesting an access token via resource owner password.
   *  
   */

  PASSWORD_TOKEN: [
    'validatePasswordTokenRequest',
    'loadClient',
    'authenticateClient',
    'allowPasswordToken',
    'readUserCredentials',
    'loadUser',
    'authenticateUser',
    'newAccessToken',
    'saveAccessToken',
    'sendToken'
  ],

  /**
   *  For requesting an access token where the client is the
   *  resource owner. This is a flow
   */

  CLIENT_TOKEN: [
    'validateClientTokenRequest',
    'userFromClient',
    'loadUser',
    'authenticateUser',
    'newAccessToken',
    'saveAccessToken',
    'sendToken'
  ],

  CODE_TOKEN: [
    'init',
    'validateTokenRequest',
    'validateCodeTokenRequest',
    'loadClient',
    'authenticateClient',
    'validateRedirectUri',
    'loadAuthorizationCode',
    'checkCodeExpiration',
    'newAccessToken',
    'newRefreshToken',
    'saveAccessToken',
    'saveRefreshToken',
    'deleteAuthorizationCode',
    'sendToken'
  ],

  /**
   *  This is a data endpoint. No form is rendered. It exchanges a well-formed
   *  authorization request (all query parameters exist and redirect_uri
   *  matches that registered by client) for a 200 OK response or a 4xx
   *  response if the validation fails.  This middleware can be used behind the
   *  scenes when rendering server-side, or can be queried using AJAX from the
   *  user-agent before presenting the resource owner with an authorization
   *  form.
   */

  CODE_AUTH: [
    'init',
    'readAuthClientId',
    'validateClientId',
    'loadClient',
    'readAuthRedirectUri',
    'validateRedirectUri',
    'readAuthResponseType',
    'validateResponseType',
    'ok'
  ],


  /**
   *  From the authorization form, a decision is sent here.
   */


  IMPLICIT: [
    'init',
    'validateAuthRequest',
    'readAuthClientId',
    'validateClientId',
    'loadClient',
    'readAuthRedirectUri',
    'validateRedirectUri',
    'readAuthResponseType',
    'validateResponseType',
    'ok'
  ],

  /**
   *  Steps required before the authorization of a resource request.  These
   *  include parsing the access token from the request header, loading the
   *  access token attributes (scope, resource owner, expires, ...) from the
   *  database, and checking its expiration date.
   */

  SCOPE: [
    'readAccessToken',
    'loadAccessToken',
    'checkAccessExpiration'
  ]
};

/**
 *  Utility for setting expiration Date from lifetime in
 *  seconds.
 */

OAuth2.expirationFromLifetime = function(now, lifetime) {
  var expires = new Date(now);
  expires.setSeconds(expires.getSeconds() + lifetime);
  return expires;
};

extend(OAuth2, {

  /**
   *  Middleware
   */


  newAuthorizationCode: function(req, res, next) {
    var oauth2 = req.oauth2;
    OAuth2.generateToken(function(err, code) {
      if (err) next(err);
      else {
        res.code = {
          code: code,
          state: req.body.state
        };
        next();
      }
    });
  },

  saveAuthorizationCode: implement('saveAuthorizationCode'),

  loadAuthorizationCode: implement('loadAuthorizationCode'),

  deleteAuthorizationCode: implement('deleteAuthorizationCode'),


  redirect: function(req, res, next) {
    var oauth2 = req.oauth2;
    var code = res.code;
    var codeUri = url.parse(oauth2.redirect_uri, true);
    extend(codeUri.query, {
      code: code.code,
      state: code.state
    });
    res.redirect(
      url.format(codeUri)
    );
  },

  validateAuthRequest: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.response_type = req.query.response_type;
    if (!oauth2.response_type) {
      return OAuth2Error(
        'invalid_request',
        'Missing a response_type.'
      );
    }

    oauth2.client_id = req.query.client_id;
    if (!oauth2.client_id) {
      return OAuth2Error(
        'invalid_request',
        'Missing a client_id.'
      );
    }

    oauth2.redirect_uri = req.query.redirect_uri;
    oauth2.scope = req.query.scope;
    oauth2.state = req.query.state;

    log('Authorization request is valid.');

    next();
  },



  validateClientId: pass,

  readAuthRedirectUri: function(req, res, next) {
    log('Read redirect_uri');
    var oauth2 = req.oauth2;
    oauth2.redirect_uri = req.query.redirect_uri;
    if (!oauth2.redirect_uri) {
      return OAuth2Error(
        'invalid_request',
        'Missing redirect_uri in authorization request.'
      );
    }
    else next();
  },

  readDecisionRedirectUri: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.redirect_uri = req.body.redirect_uri;
    if (!oauth2.redirect_uri) {
      return OAuth2Error(
        'invalid_request',
        'Missing redirect_uri in decision post.'
      );
    }
    else next();
  },


  readAuthResponseType: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.response_type = req.query.response_type;
    if (!oauth2.response_type) {
      OAuth2ErrorRedirect(
        'invalid_request',
        'Missing response_type in authorization request.'
      );
    }
    else next();
  },

  readDecisionResponseType: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.response_type = req.body.response_type;
    if (!oauth2.response_type) {
      OAuth2ErrorRedirect(
        'invalid_request',
        'Missing response_type in decision post.'
      );
    }
    else next();
  },

  validateResponseType: function(req, res, next) {
    var oauth2 = req.oauth2;
    if (oauth2.opts.responseTypes.indexOf(oauth2.response_type) < 0) {
      OAuth2ErrorRedirect('unsupported_response_type');
    }
    else next();
  },

  ok: function(req, res, next) {
    res.status(200);
    res.send({message: 'Much success.'});
  },

  validateTokenRequest: function(req, res, next) {
    if (!req.is('application/x-www-form-urlencoded') || req.method !== 'POST') {
      return OAuth2Error(
        'invalid_request',
        'You must POST a request with content-type: ' +
        'application/x-www-form-urlencoded'
      );
    }
    var oauth2 = req.oauth2;
    oauth2.grant_type = req.body.grant_type;
    if (!oauth2.grant_type) {
      return OAuth2Error(
        'invalid_request',
        'Need to provide a grant_type'
      );
    }
    next();
  },

  branchTokenRequest: function(req, res, next) {
    var flow = req.oauth2.flows[req.oauth2.grant_type];
    if (!flow) {
      OAuth2Error(
        'unsupported_grant_type'
      );
    }
    else OAuth2.runFlow(flow, req, res, next);
  },

  validatePasswordTokenRequest: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.username = req.body.username;
    if (!oauth2.username) {
      return OAuth2Error(
        'invalid_request',
        'No username given'
      );
    }

    oauth2.password = req.body.password;
    if (!oauth2.password) {
      return OAuth2Error(
        'invalid_request',
        'No password given'
      );
    }

    oauth2.scope = req.body.scope;

    var creds = auth(req);

    if (creds) {
      oauth2.client_id = creds.name;
      oauth2.client_secret = creds.pass;
    }

    next();
  },

  allowPasswordToken: function(req, res, next) {
    next();
  },

  validateCodeTokenRequest: function(req, res, next) {
    var body = req.body;
    var oauth2 = req.oauth2;

    oauth2.code = body.code;
    if (!oauth2.code) {
      return OAuth2Error(
        'invalid_request',
        'Authorization code token request is missing a code'
      );
    }

    oauth2.redirect_uri = body.redirect_uri;

    var creds = auth(req);

    if (creds && body.client_id) {
      return OAuth2Error(
        'invalid_request',
        'Client was given in Authorization header and request body'
      );
    }
    else if (!creds && !body.client_id) {
      return OAuth2Error(
        'invalid_request',
        'Auth code token request. Missing client credentials'
      );
    }

    oauth2.client_id = body.client_id || creds.name;

    if (creds) {
      oauth2.client_secret = creds.pass;
    }

    next();
  },

  validateClientTokenRequest: function(req, res, next) {
    var oauth2 = req.oauth2;
    var creds = auth(req);

    if (!creds) {
      return OAuth2Error(
        'invalid_request',
        'No client credentials in Authorization header'
      );
    }

    oauth2.client_id = creds.name;
    oauth2.client_secret = creds.pass;

    oauth2.scope = req.body.scope;

    next();
  },

  /**
   *  Happens only on token endpoint.
   */

  authenticateClient: function(req, res, next) {
    var oauth2 = req.oauth2;
    log('Authenticate client', oauth2.client_id);
    var client = req.client;
    if (!client) {
      OAuth2Error(
        'invalid_client',
        'No client to authenticate. Boo hoo!'
      );
    }
    else if (oauth2.client_secret && !client.client_secret_hash) {
      OAuth2Error(
        'invalid_client',
        'Client is public but got client_secret in request.'
      );
    }
    else if (client.client_secret_hash && !oauth2.client_secret) {
      OAuth2Error(
        'invalid_client',
        'Client is confidential. Provide credentials in ' +
        'Authorization header.'
      );
    }
    else if (oauth2.client_secret && client.client_secret_hash) {
      OAuth2.validateSecret(
        oauth2.client_secret,
        client.client_secret_hash,
        function(err, success) {
          if (err) next(err);
          else if (!success) {
            res.status(401);
            res.set('WWW-Authenticate', 'Basic');
            res.send({
              error: 'invalid_client',
              error_description: 'Client authentication failed.'
            });
          }
          else next();
        }
      );
    }
    else next();
  },


  /**
   *  Used in password token flow and auth code decision flow. Required
   *  in both cases.
   *
   */

  readUserCredentials: function(req, res, next) {
    log('Read user credentials');
    var oauth2 = req.oauth2;
    oauth2.username = req.body.username;
    oauth2.password = req.body.password;
    next();
  },

  /**
   *  Only occurs in client flow.
   */

  userFromClient: function(req, res, next) {
    log('Set user credentials from client credentials');
    var oauth2 = req.oauth2;
    oauth2.username = oauth2.client_id;
    oauth2.password = oauth2.client_secret;
    next();
  },

  loadUser: implement('loadUser'),

  /**
   *  Happens on /login, /decision, /authorize (implicit
   *  flow) and /token (password flow) endpoints.
   *
   *  Relies on presence of req.user.
   *
   *  Always returns 400 {error: 'invalid_request',
   *  error_description: 'Bad password'} when user authentication fails.
   */

  authenticateUser: function(req, res, next) {
    var user = req.user;
    var oauth2 = req.oauth2;
    if (!user) {
      next(
        error(
          'User was not loaded to req.user. If user is not found in a ' +
          'database, return a 4xx in loadUser().'
        )
      );
    }
    log('Authenticate user', user.username);
    if (!user.password_hash) {
      next(
        error(
          'Default authenticateUser requires req.user.password_hash ' +
          'from loadUser().'
        )
      )
    }
    else {
      OAuth2.validateSecret(
        oauth2.password,
        user.password_hash,
        function(err, success) {
          if (err) next(err);
          else if (!success) {
            OAuth2Error(
              'invalid_request',
              'Bad user password.'
            );
          }
          else next();
        }
      );
    }
  },

  loadRefreshToken: implement('loadRefreshToken'),

  checkRefreshToken: function(req, res, next) {
    if (req.refreshToken.expires < req.began) {
      OAuth2Error({
        error: 'invalid_grant',
        desc: 'The refresh token has expired'
      });
    } else {
      next();
    }
  },

  newAccessToken: function(req, res, next) {
    var oauth2 = req.oauth2;
    OAuth2.generateToken(function(err, access_token) {
      if (err) next(err);
      else {
        var expires_in = oauth2.opts.expires_in || 3600;
        var expires = new Date(req.began);
        expires.setSeconds(expires.getSeconds() + expires_in);
        res.token = {
          access_token: access_token,
          expires_in: expires_in,
          expires: expires,
          token_type: oauth2.opts.token_type,
          scope: oauth2.scope
        };
        next();
      }
    });
  },

  newRefreshToken: function(req, res, next) {
    OAuth2.generateToken(function(err, token) {
      if (err) next(err);
      else {
        res.token.refresh_token = token;
        next();
      }
    });
  },

  saveAccessToken: implement('saveAccessToken'),

  saveRefreshToken: implement('saveRefreshToken'),

  sendToken: function(req, res, next) {
    if (!res.token) {
      next(
        error(
          'A new access token was not created. Check newAccessToken ' +
          'implementation.'
        )
      )
    }
    res.status(200);
    res.send(res.token);
  },


  /**
   * Get bearer token from request header. It must exist.
   * 
   *
   * Extract token from request according to RFC6750
   *
   * @param  {Function} done
   * @this   OAuth
   */

  readAccessToken: function(req, res, next) {
    var header = req.get('Authorization');
    
    // Header: http://tools.ietf.org/html/rfc6750#section-2.1
    if (header) {
      var matches = header.match(/Bearer\s(\S+)/);
      if (!matches) {
        return res.send(401, 'Malformed auth header');
      }
      req.access_token = matches[1];
      next();
    } else {
      res.status(401);
      res.send('Nonexistent auth header');
    }
  },

  loadAccessToken: implement('loadAccessToken'),

  checkScope: function(req, res, next) {
    var scope = req.scope.split(' ');
    for (var i = 0; i < scope.length; i++) {
      if (scope[i] === res.scope) {
        return next();
      }
    }
    res.send(401,
      'Access denied. Token has scope: [' +
      req.scope + '], but resource requires scope: ' +
      res.scope
    );
  },

  checkAccessExpiration: function(req, res, next) {
    if (req.expires < req.began) {
      res.send(401, 'Access token has expired');
    }
    else next();
  },

  checkRefreshExpiration: function(req, res, next) {
    next();
  },

  /**
   *  Static utility functions used by default middleware.
   */


  validateParams: function(params, obj, msg, req, res, next) {
    var param;
    for (var name in params) {
      param = params[name];
      if (!obj[name] && param.required) {
        OAuth2Error(
          'invalid_request',
          msg.replace('%param', name)
        );
        return true;
      }
      req[name] = obj[name];
    }
    next && next();
  },

  hashSecret: bcrypt.hash,

  validateSecret: bcrypt.compare,

  runFlow: function(flow, req, res, next) {
    series(
      flow.map(function(middleware) {
        return middleware.bind(null, req, res);
      }),
      next
    );
  }

});

/**
 *  The most generic middleware. Used by most flows.
 */

OAuth2.middleware = {

  /**
   *  Begins all flows (after branching).
   */

  init: function(req, res, next) {
    req.began = req.began || new Date();
    next();
  },

  /**
   *  Used at end of all flows.
   */

  error: function(err, req, res, next) {
    if (err instanceof OAuth2Error) {
      var msg = {
        error: err.code || 'invalid_request',
        error_description: err.desc || '',
        error_uri: err.uri || ''
      };
  
      var redirectUri = req.oauth2.redirectUri;
  
      if (redirectUri && req.oauth2.redirectValidated) {
        if (err.code === 'server_error' && req.oauth2.debug) {
          next(err.error);
        }
        else {
          var errorUri = url.parse(redirectUri, true);
          extend(errorUri.query, msg);
          if (req.oauth2.state) {
            errorUri.query.state = req.oauth2.state;
          }
          res.redirect(
            url.format(errorUri)
          );
        }
      }
      else {
        res.status(400);
        res.send(msg);
      }
    }
    else next(err);
  },

  validateClientId: function(req, res, next) {
    var err;
    var id = req.oauth2.clientId;

    if (!id) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Client did not provide id.'
      });
    }
    else if (!req.oauth2.Client.validateId(id)) {
      err = OAuth2Error({
        error: 'invalid_request',
        desc: 'Invalid client_id.'
      });
    }
    next(err);
  },

  /**
   *  Expects req.oauth2.clientId.
   */

  loadClient: function(req, res, next) {
    var id = req.oauth2.clientId;
    req.oauth2.Client.load(id, function(err, client) {
      console.log(err, client);
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      req.client = client;
      next(err);
    });
  },

  /**
   *  Expects
   *
   *    - req.client
   *    - req.oauth2.redirectUri
   *
   *  Sets
   *
   *    - req.oauth2.redirectValidated (only if true)
   */

  validateRedirectUri: function(req, res, next) {
    var oauth2 = req.oauth2;
    var redirectUri = req.oauth2.redirectUri;
    var Client = oauth2.Client;
    var err;
    if (!redirectUri) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Client did not supply a redirect_uri'
      });
    }
    else if (!Client.validateRedirectUri(redirectUri, req.client)) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Invalid redirect_uri'
      });
    }
    else oauth2.redirectValidated = true;
    next(err);
  },

  readAccessTokenId: function(req, res, next) {
    req.oauth2.accessTokenId = req.get('x-access-token');
    next();
  },

  loadAccessToken: function(req, res, next) {
    var id = req.oauth2.accessTokenId;
    if (!id) return next();
    req.oauth2.AccessToken.load(id, function(err, accessToken) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      req.oauth2.accessToken = token;
      next(err);
    });
  },

  requireAccessToken: function(req, res, next) {
    var err;
    if (!req.oauth2.accessToken) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: 'An access token is required'
      });
    }
    next(err);
  },

  checkAccessTokenExpiration: function(req, res, next) {
    var err;
    if (req.began > req.oauth2.accessToken.expires) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: 'Access token has expired'
      });
    }
    next(err);
  },

  /**
   *  A user can be read, validated, and loaded given a request in
   *  so many ways. Leave this open-ended?
   *
   *  No, a user is always loaded from an access token.
   *
   *  This middleware errors only if the User model fails
   *  miserably. If the User model cannot find the user, then
   */

  loadUser: function(req, res, next) {
    var accessToken = req.oauth2.accessToken;
    if (!accessToken) return next();

    var username = accessToken.username;
    if (!username) return next();

    req.oauth2.User.load(username, function(err, user) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      req.user = user;
      next(err);
    });
  },

  requireUser: function(req, res, next) {
    var err;
    if (!req.user) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: 'User not found'
      });
    }
    next(err);
  }
};

/**
 *  Middleware common to all authorization requests.
 */

OAuth2.middleware.auth = {

  /**
   *  Simple check for existence.
   */

  requireResponseType: function(req, res, next) {
    var responseType = req.query.response_type;
    var err;
    if (!responseType) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Missing a response_type'
      });
    }
    next(err);
  }
};

/**
 *  Middleware common to code request and code authorization endpoints.
 */

OAuth2.middleware.code = {
  readClientId: function(req, res, next) {
    req.oauth2.clientId = req.query.client_id;
    next();
  },

  readRedirectUri: function(req, res, next) {
    req.oauth2.redirectUri = req.query.redirect_uri;
    next();
  },

  validateResponseType: function(req, res, next) {
    var err;
    if (!req.oauth2.allowGrant('authorization_code', req.client)) {
      err = OAuth2Error({
        code: 'unsupported_response_type'
      });
    }
    next(err);
  }
};


OAuth2.middleware.codeRequest = {
  respond: function(req, res, next) {
    res.status(200).send({
      user: req.user || null
    });
  }
};


OAuth2.middleware.codeAuthorization = {

  requireAuthorizationScope: function(req, res, next) {
    var err;
    var scope = req.oauth2.accessToken.scope.split(' ');
    var authorizationScope = req.oauth2.authorizationScope;
    if (scope.indexOf(authorizationScope) < 0) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: (
          'Need ' + authorizationScope + ' to give out ' +
          'authorization codes to clients.'
        )
      });
    }
    next(err);
  },

  readAcceptedScope: function(req, res, next) {
    var err;
    req.oauth2.acceptedScope = req.body.scope;
    if (!req.oauth2.acceptedScope) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: 'User denied the authorization request.'
      });
    }
    next(err);
  },

  newAuthorizationCode: function(req, res, next) {
    var oauth2 = req.oauth2;
    var AuthorizationCode = oauth2.AuthorizationCode;

    AuthorizationCode.id(function(err, id) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      else {
        var code = oauth2.code = {
          id: id,
          scope: oauth2.acceptedScope,
          user_id: req.user.id,
          client_id: req.client.id
        };

        if ('function' == typeof AuthorizationCode.lifetime) {
          code.lifetime = AuthorizationCode.lifetime(
            req.client,
            req.user,
            code.scope
          );
        }
        else {
          code.lifetime = AuthorizationCode.lifetime;
        }

        code.expires = OAuth2.expirationFromLifetime(
          req.began,
          code.lifetime
        );
      }
      next(err);
    });
  },

  saveAuthorizationCode: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.AuthorizationCode.save(
      oauth2.code,
      function(err) {
        if (err) {
          err = OAuth2Error({
            code: 'server_error',
            error: err
          });
        }
        next(err);
      }
    );
  },

  respond: function(req, res, next) {
    var code = req.oauth2.code;
    res.status(200).send({
      code: code.id,
      scope: code.scope
    });
  }
};



/**
 *  Make a flow given an array of strings or functions. Use default
 *  middleware from OAuth2 class unless new middleware was set on this
 *  instance or given on the constructor options object.
 *
 *  @param {String|Array<String|Function>} actions
 */

function Flow(actions, _debug) {
  var flow = [];

  function push(fn, name) {
    _debug && flow.push(function(req, res, next) {
      log(name);
      next();
    });
    flow.push(fn);
  }

  actions.forEach(function(action) {
    if ('function' == typeof action) push(action, 'unnamed');
    else {
      var err = new Error('Need action ' + action + ' for flow.');
      var ids = action.split('.');
      var fn = OAuth2.middleware;
      var i = 0;
      try {
        while (fn && i < ids.length) {
          fn = fn[ids[i++]];
        }
      }
      catch (e) {
        throw err;
      }
      if (!fn) throw err;
      push(fn, action);
    }
  });
  return flow;
};


OAuth2.flows = {};

OAuth2.flows.validateCode = Flow([
  'init',
  'code.readClientId',
  'validateClientId',
  'loadClient',
  'code.readRedirectUri',
  'validateRedirectUri',
  'auth.requireResponseType',
  'code.validateResponseType',
  'readAccessTokenId',
  'loadAccessToken',
  'loadUser'
], true);

OAuth2.flows.codeRequest = OAuth2.flows.validateCode.concat([
  OAuth2.middleware.codeRequest.respond
]);

OAuth2.flows.codeAuthorization = OAuth2.flows.validateCode.concat([
  OAuth2.middleware.requireAccessToken,
  OAuth2.middleware.checkAccessTokenExpiration,
  OAuth2.middleware.codeAuthorization.requireAuthorizationScope,
  OAuth2.middleware.requireUser,
  OAuth2.middleware.codeAuthorization.readAcceptedScope,
  OAuth2.middleware.codeAuthorization.newAuthorizationCode,
  OAuth2.middleware.codeAuthorization.saveAuthorizationCode,
  OAuth2.middleware.codeAuthorization.respond
]);


OAuth2.flows.codeToken = [
  OAuth2.middleware.init,
  OAuth2.middleware.validateTokenRequest,
  OAuth2.middleware.validateCodeTokenRequest,
  OAuth2.middleware.loadClient,
  OAuth2.middleware.authenticateClient,
  OAuth2.middleware.validateRedirectUri,
  OAuth2.middleware.loadAuthorizationCode,
  OAuth2.middleware.checkCodeExpiration,
  OAuth2.middleware.newAccessToken,
  OAuth2.middleware.newRefreshToken,
  OAuth2.middleware.saveAccessToken,
  OAuth2.middleware.saveRefreshToken,
  OAuth2.middleware.deleteAuthorizationCode,
  OAuth2.middleware.sendToken
];


/**
 *  For the html server.
 */

OAuth2.middleware.authorize = {


};

OAuth2.flows.authorize = [


];

OAuth2.Authorize = function(opts) {
  
  return function(req, res, next) {
    request.get(opts.token)

  };
};


OAuth2.prototype.token = function(flows) {
//  var flow = [attach].concat(this.flow('TOKEN'));

  // Set flows we may branch to depending on grant_type.
  // Keys are grant_type values.

  var oauth2 = merge(this.oauth2);
  var passwordFlow = this.flow('PASSWORD_TOKEN');
  var clientFlow = this.flow('CLIENT_TOKEN');
  var codeFlow = this.flow('CODE_TOKEN');

  return branch;

  function branch(req, res, next) {
    req.oauth2 = oauth2;

    if (!req.body) {
      parseForm(req, res, function(err) {
        if (err) next(err);
        else finish();
      });
    }
    else finish();

    function finish() {
      var flow;
      switch (req.body.grant_type) {
        case 'password':
          flow = passwordFlow;
          break;
        case 'client_credentials':
          flow = clientFlow;
          break;
        default: // 'authorization_code'
          flow = codeFlow;
      }
      OAuth2.runFlow(flow, req, res, next);
    }
  }
};


/**
 *  Authorize resource requests.
 *
 *  Middleware that limits resource access by scope only. Consider this a
 *  first line of defense; the owner of the resource being requested still
 *  needs to be matched with the resource owner that granted the access token.
 *
 *  Call this middleware before returning a protected resource. Like so,
 *
 *  app.get(
 *    '/account',
 *    app.scope('accounts'),
 *    function(req, res, next) {
 *    
 *    }
 *  );
 *
 *  @param {string} scope The scope permission required to access the
 *  resource.
 */

OAuth2.prototype.scope = function(scope) {
  return [attachScope].concat(this.flow('SCOPE'));

  function attachScope(req, res, next) {
    res.scope = scope;
    next();
  }
};


OAuth2.prototype.authorize = function() {
  //var flow = [attach].concat(this.flow('AUTH'));

  // Set flows we may branch to depending on response_type.
  // Keys are response_type values.

  //var oauth2 = merge(this.oauth2);
  var OAuth2Request = this.OAuth2Request;

  //var oauth2 = merge(this.oauth2, {
  //  flows: {
  //    code: this.flow('CODE_AUTH'),
  //    token: this.flow('IMPLICIT')
  //  }
  //});

  return branch;

  // Never return an error response from branch. All that is handled by
  // the exposed middleware. This function should never fail.

  function branch(req, res, next) {
    req.oauth2 = OAuth2Request(req, res);
    var flow;
    if (req.method === 'GET') {
      log('~~≈≈ Authorization code request ≈≈~~');
      flow = OAuth2.flows.codeRequest;
    }
    else if (req.method === 'POST') {
      // Decision endpoint.
      log('~~≈≈ Authorization code issuance ≈≈~~');
      flow = OAuth2.flows.codeAuthorization;
    }

    if (!flow) next();
    else {
      OAuth2.runFlow(flow, req, res, next);
    }
  }
};


OAuth2.prototype.decision = function() {

};


module.exports = OAuth2;

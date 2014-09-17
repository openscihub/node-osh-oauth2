var crypto = require('crypto');
var auth = require('basic-auth');
var log = require('osh-util/logger')('OAuth2');
var extend = require('xtend/mutable');
var merge = require('xtend/immutable');
var Class = require('osh-class');
var parseForm = require('body-parser').urlencoded({extended: false});
var url = require('url');
var tick = process.nextTick;


var VSCHAR = /^[\u0020-\u007E]+$/;

var OAuth2Error = Class(Error, function(opts) {
  extend(this, opts);
  this.message = opts.code + ': ' + (opts.desc || '');
  //this._super(opts.desc);
});

function error(msg) {
  return new Error('OSH OAuth2: ' + msg);
}


var OAuth2;

var DefaultModel = {
  save: implementModelMethod('save(model, callback)'),
  load: implementModelMethod('load(id, callback)'),
  del: implementModelMethod('del(id, callback)')
};

var DefaultAuthorizationCode = merge(DefaultModel, {
  name: 'AuthorizationCode',
  generateId: function(client, user, scope, callback) {
    generateToken(callback);
  },
  lifetime: implementModelMethod(
    'lifetime: Number|Function(scope, client, user)<Number>'
  )
});


var DefaultClient = merge(DefaultModel, {
  name: 'Client',
  secretHash: 'secret_hash',
  validateId: function(id) {
    return VSCHAR.test(id);
  },
  validateRedirectUri: implementModelMethod(
    'validateRedirectUri(uri, client)'
  ),
  //authenticate: function(secret, client, callback) {
    //OAuth2.validateSecret(secret, client[this.secretHash], callback);
  //},
  authenticate: implementModelMethod(
    'authenticate(secret, client, callback)'
  ),
  allowGrant: implementModelMethod(
    'allowGrant: Array<String>|Function(grant, client)<Boolean>'
  )
});

var DefaultUser = merge(DefaultModel, {
  name: 'User'
});

var DefaultAccessToken = merge(DefaultModel, {
  name: 'AccessToken',
  generateId: function(callback) {
    OAuth2.generateToken(callback);
  },
  lifetime: implementModelMethod(
    'lifetime: Number|Function(scope, client, user)<Number>'
  ),
  authorizationScope: 'authorization',
  defaultScope: implementModelMethod(
    'defaultScope: String|Function(client, user, callback)'
  ),
  revokeScope: implementModelMethod(
    'revokeScope: String|Function(scope, client, user, callback)'
  ),
  allowRefresh: implementModelMethod(
    'allowRefresh: Boolean|Function(accessToken, client, user)<Boolean>'
  )
});

var DefaultRefreshToken = merge(DefaultModel, {
  name: 'RefreshToken',
  generateId: function(callback) {
    OAuth2.generateToken(callback);
  },
  lifetime: implementModelMethod(
    'lifetime: Number|Function(scope, client, user)<Number>'
  )
});



OAuth2 = Class(function(opts) {
  this.flows = {};
  for (var name in OAuth2.flows) {
    this.flows[name] = Flow(OAuth2.flows[name], opts.debug);
  }

  this.OAuth2Request = Class(function(opts) {
    this.req = opts.req;
    this.res = opts.res;
  });

  var Client = merge(DefaultClient, opts.Client);
  if (Array.isArray(Client.allowGrant)) {
    var grants = Client.allowGrant;
    Client.allowGrant = function(grant) {
      return grants.indexOf(grant) >= 0;
    };
  }

  extend(this.OAuth2Request.prototype, opts, {
    User: merge(DefaultUser, opts.User),
    Client: Client,
    AccessToken: merge(DefaultAccessToken, opts.AccessToken),
    RefreshToken: merge(DefaultRefreshToken, opts.RefreshToken),
    AuthorizationCode: merge(DefaultAuthorizationCode, opts.AuthorizationCode)
  });

});



/**
 *  Utility functions.
 */

extend(OAuth2, {

  extendUriQuery: function(uri, query) {
    uri = url.parse(uri, true);
    extend(uri.query, query);
    return url.format(uri);
  },

  runFlow: runFlow,

  generateToken: generateToken,

  scopeArray: function(scope) {
    return 'string' == typeof scope ? scope.split(' ') : scope.concat();
  },

  scopeString: function(scope) {
    return 'string' == typeof scope ? scope : scope.join(' ');
  },

  removeScope: removeScope,

  hasScope: function(scope, contains) {
    contains = OAuth2.scopeArray(contains);
    scope = OAuth2.scopeArray(scope);
    for (var i = 0, len = contains.length; i < len; i++) {
      if (scope.indexOf(contains[i]) >= 0) return true;
    }
  },

  expirationFromLifetime: function(now, lifetime) {
    var expires = new Date(now);
    expires.setSeconds(expires.getSeconds() + lifetime);
    return expires;
  }
});


/**
 *  OAuth2 instance methods. These create middleware functions
 *  that then run middleware flows.
 */

OAuth2.prototype.token = function(flows) {
  //var oauth2 = merge(this.oauth2);
  var OAuth2Request = this.OAuth2Request;
  var flow = this.flows.token;
  var subFlows = {
    client_credentials: this.flows.clientToken,
    password: this.flows.password,
    authorization_code: this.flows.codeToken
  };

  return function(req, res, next) {
    log('~~≈≈ Token ≈≈~~');
    req.oauth2 = OAuth2Request(req, res);
    req.oauth2.flows = subFlows;
    OAuth2.runFlow(flow, req, res, next);
  };
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
 *    oauth2.allow('accounts'),
 *    function(req, res, next) {
 *    
 *    }
 *  );
 *
 *  @param {string} scope The scope permission required to access the
 *  resource.
 */


OAuth2.prototype.allow = function(scope) {
  if (!scope || !OAuth2.scopeArray(scope).length) {
    throw new Error(
      'oauth2.allow() needs a scope. If you just want to load a ' +
      '(possibly existing) access token + user and client models, ' +
      'use oauth2.load() instead.'
    );
  }
  scope = OAuth2.scopeString(scope);

  var OAuth2Request = this.OAuth2Request;
  var flow = this.flows.allow;

  return function(req, res, next) {
    req.oauth2 = OAuth2Request(req, res);
    req.oauth2.scope = scope;
    OAuth2.runFlow(flow, req, res, next);
  };
};


/**
 *  Make middleware that reads an access token from the request,
 *  and loads the client and user associated with the token into
 *  req.oauth2.client and req.oauth2.user, respectively.
 *
 *  This does not fail when an access token does not exist.
 */

OAuth2.prototype.load = function() {
  var OAuth2Request = this.OAuth2Request;
  var flow = this.flows.load;

  return function(req, res, next) {
    req.oauth2 = OAuth2Request(req, res);
    OAuth2.runFlow(flow, req, res, next);
  };
};

/**
 *  The authorization endpoint. This provides both a GET and
 *  POST response, so it should be mounted like:
 *
 *    var app = express();
 *    app.use('/authorize', oauth2.authorize());
 *
 */

OAuth2.prototype.authorize = function() {
  var OAuth2Request = this.OAuth2Request;
  var flow = this.flows.code;
  var subFlows = {
    request: this.flows.codeRequest,
    authorization: this.flows.codeAuthorization
  };
  var debug = this.opts.debug;

  return function(req, res, next) {
    debug && log('~~≈≈ Authorization code ≈≈~~');
    req.oauth2 = OAuth2Request(req, res);
    req.oauth2.flows = subFlows;
    OAuth2.runFlow(flow, req, res, next);
  };
};


module.exports = OAuth2;

/**
 *  Endpoint flows. Each array is an ordered list of middleware
 *  functions to run. The functions are found under the
 *  OAuth2.middleware namespace, which follows this definition.
 */

OAuth2.flows = {
  code: [
    'init',
    'maybeReadQueryClientId',
    'requireAndValidateClientId',
    'maybeLoadClient',
    'requireClient',
    'maybeReadQueryRedirectUri',
    'validateRedirectUriWithClient',
    'allowResponseType',
    'maybeReadAccessTokenId',
    'maybeLoadAccessToken',
    'maybeReadAccessTokenUserId',
    'maybeLoadUser',
    'branchCodeAuthorizationRequest',
    'authError'
  ],

  codeRequest: [
    'okCodeRequest',
    'authError'
  ],

  codeAuthorization: [
    'parseForm',
    'requireUser', // effectively requires accessToken. see 'code' flow.
    'checkAccessTokenExpiration',
    'requireAuthorizationScopeInAccessToken',
    'readAuthorizedScope',
    'removeAuthorizationScope',
    'revokeScope',
    'newAuthorizationCode',
    'saveAuthorizationCode',
    'sendCode',
    'authError'
  ],

  token: [
    'init',
    'parseForm',
    'validateTokenRequest',
    'requireBasicClientCredentials',
    'maybeLoadClient',
    'requireClient',
    'authenticateClient',
    'allowGrantType',
    'branchTokenRequest',
    'tokenError'
  ],

  clientToken: [
    'setUserIdFromClientId',
    'maybeLoadUser',
    'requireUser',
    'setDefaultScope',
    'readBodyScope',
    'revokeScope',
    'newAccessToken',
    'newRefreshToken',
    'saveAccessToken',
    'saveRefreshToken',
    'sendToken',
    'tokenError'
  ],

  codeToken: [
    'requireBodyAuthorizationCode',
    'maybeLoadAuthorizationCode',
    'requireAuthorizationCode',
    'checkCodeExpiration',
    'validateRedirectUriWithCode',
    'readCodeScope',
    'readCodeUserId',
    'maybeLoadUser',
    'requireUser',
    'newAccessToken',
    'newRefreshToken',
    'saveAccessToken',
    'saveRefreshToken',
    'deleteAuthorizationCode',
    'sendToken',
    'tokenError'
  ],

  /**
   *  Protect an API resource with scope.
   *
   *  Requires
   *
   *    - req.oauth2.scope
   *
   *  to be set in runner middleware setup by
   *  OAuth2.prototype.scope.
   */

  allow: [
    'init',
    'maybeReadAccessTokenId',
    'maybeLoadAccessToken',
    'requireAccessToken',
    'checkAccessTokenExpiration',
    'checkAccessTokenScope',
    'maybeReadAccessTokenUserId',
    'maybeLoadUser',
    'requireUser',
    'maybeReadAccessTokenClientId',
    'maybeLoadClient',
    'requireClient',
    'accessError'
  ],

  /**
   *  Read an access token, and load user and client if
   *  found. Does not error if none found.
   */

  load: [
    'init',
    'maybeReadAccessTokenId',
    'maybeLoadAccessToken',
    'maybeReadAccessTokenClientId',
    'maybeLoadClient',
    'maybeReadAccessTokenUserId',
    'maybeLoadUser'
  ]

};


/**
 *  A mapping between response types and grant types.
 */

OAuth2.responseTypeGrantTypes = {
  code: 'authorization_code',
  token: 'implicit'
};


/**
 *  Middleware!
 */

OAuth2.middleware = {

  /**
   *  Begins all flows.
   */

  init: function(req, res, next) {
    req.began = req.began || new Date();
    next();
  },

  parseForm: function(req, res, next) {
    if (req.body) next();
    else parseForm(req, res, next);
  },

  validateTokenRequest: function(req, res, next) {
    var err;
    if (!req.is('application/x-www-form-urlencoded') || req.method !== 'POST') {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: (
          'You must POST a request with content-type: ' +
          'application/x-www-form-urlencoded'
        )
      });
    }
    next(err);
  },

  /**
   *  Requires
   *
   *    - req.oauth2.client
   */

  allowGrantType: function(req, res, next) {
    var err;
    var grantType = req.oauth2.grantType = req.body.grant_type;
    var Client = req.oauth2.Client;
    if (!grantType) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Missing grant_type'
      });
    }
    else if (!Client.allowGrant(grantType, req.oauth2.client)) {
      err = OAuth2Error({
        code: 'unauthorized_client',
        desc: 'Client can not use given grant type'
      });
    }
    next(err);
  },

  /**
   *  Check for existence plus confirmation from the Client
   *  model that the associated grant type is allowed.
   *
   *    - req.oauth2.client
   */

  allowResponseType: function(req, res, next) {
    var responseType = req.query.response_type;
    var Client = req.oauth2.Client;
    var client = req.oauth2.client;
    var grantType;
    var err;

    if (!responseType) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Missing a response_type'
      });
      return next(err);
    }

    grantType = OAuth2.responseTypeGrantTypes[responseType];

    if (!grantType || !Client.allowGrant(grantType, client)) {
      err = OAuth2Error({
        code: 'unsupported_response_type'
      });
    }

    next(err);
  },

  maybeReadQueryClientId: function(req, res, next) {
    req.oauth2.clientId = req.query.client_id;
    next();
  },

  requireBasicClientCredentials: function(req, res, next) {
    var oauth2 = req.oauth2;
    var creds = auth(req);
    var err;

    if (!creds) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'No client credentials in Authorization header'
      });
    }
    else {
      oauth2.clientId = creds.name;
      oauth2.clientSecret = creds.pass;
    }

    next(err);
  },

  requireAndValidateClientId: function(req, res, next) {
    var err;
    var id = req.oauth2.clientId;

    if (!id) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Missing client id'
      });
    }
    else if (!req.oauth2.Client.validateId(id)) {
      err = OAuth2Error({
        error: 'invalid_request',
        desc: 'Invalid client id.'
      });
    }
    next(err);
  },

  /**
   *  Expects req.oauth2.clientId.
   */

  maybeLoadClient: function(req, res, next) {
    var id = req.oauth2.clientId;
    if (!id) return next();
    req.oauth2.Client.load(id, function(err, client) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      req.oauth2.client = client;
      next(err);
    });
  },

  requireClient: function(req, res, next) {
    var err;
    if (!req.oauth2.client) {
      err = OAuth2Error({
        code: 'invalid_client',
        desc: 'Client was not found'
      });
    }
    next(err);
  },

  maybeReadQueryRedirectUri: function(req, res, next) {
    req.oauth2.redirectUri = req.query.redirect_uri;
    next();
  },

  /**
   *  Validates a redirect_uri with a client. A client could have
   *  many valid redirect uris.
   *
   *  Requires
   *
   *    - req.oauth2.client
   *    - req.oauth2.redirectUri
   *
   *  Sets
   *
   *    - req.oauth2.redirectValidated (only if true)
   *
   *  for error reporting.
   */

  validateRedirectUriWithClient: function(req, res, next) {
    var oauth2 = req.oauth2;
    var redirectUri = oauth2.redirectUri;
    var Client = oauth2.Client;
    var err;
    if (!redirectUri) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Client did not supply a redirect_uri'
      });
    }
    else if (!Client.validateRedirectUri(redirectUri, oauth2.client)) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Invalid redirect_uri'
      });
    }
    else oauth2.redirectValidated = true;
    next(err);
  },

  /**
   *  Expects
   *
   *    - req.oauth2.clientId
   *    - req.oauth2.clientSecret
   *    - req.oauth2.client
   */

  authenticateClient: function(req, res, next) {
    var oauth2 = req.oauth2;
    log('Authenticate client', oauth2.clientId);
    var client = oauth2.client;
    if (!client) {
      var err = OAuth2Error({
        code: 'invalid_client',
        desc: 'No client to authenticate? No token for you!'
      });
      next(err);
    }
    else {
      oauth2.Client.authenticate(
        oauth2.clientSecret,
        client,
        function(err, success) {
          if (err) {
            err = OAuth2Error({
              code: 'server_error',
              error: err
            });
            next(err);
          }
          else if (!success) {
            res.status(401);
            res.set('WWW-Authenticate', 'Basic');
            res.send({
              error: 'invalid_client',
              error_description: 'Client authentication failed. No token for you!'
            });
          }
          else next();
        }
      );
    }
  },

  setDefaultScope: function(req, res, next) {
    var AccessToken = req.oauth2.AccessToken;
    if ('string' == typeof AccessToken.defaultScope) {
      req.oauth2.scope = AccessToken.defaultScope;
      next();
    }
    else {
      var client = req.oauth2.client;
      var user = req.oauth2.user;
      AccessToken.defaultScope(client, user, function(err, scope) {
        if (err) {
          err = OAuth2Error({
            code: 'server_error',
            error: err
          });
        }
        req.oauth2.scope = scope;
        next(err);
      });
    }
  },

  readCodeScope: function(req, res, next) {
    var scope = req.oauth2.code.scope;
    if (scope) {
      req.oauth2.scope = scope;
    }
    next();
  },

  readCodeUserId: function(req, res, next) {
    req.oauth2.userId = req.oauth2.code.user_id;
    next();
  },

  readBodyScope: function(req, res, next) {
    var scope = req.body.scope;
    if (scope) {
      req.oauth2.scope = scope;
    }
    next();
  },

  /**
   *  Expects
   *
   *    - req.oauth2.scope
   *    - req.oauth2.user
   *    - req.oauth2.client
   */

  revokeScope: function(req, res, next) {
    var AccessToken = req.oauth2.AccessToken;
    if (!AccessToken.revokeScope) next();
    else {
      var client = req.oauth2.client;
      var user = req.oauth2.user;
      var scope = req.oauth2.scope.split(' ');
      AccessToken.revokeScope(scope, client, user, function(err, scope) {
        if (err) {
          err = OAuth2Error({
            code: 'server_error',
            error: err
          });
        }
        else req.oauth2.scope = OAuth2.scopeString(scope);
        next(err);
      });
    }
  },

  /**
   *  Get bearer token from request header. It must exist.
   *
   *  TODO: Extract token from request according to RFC6750
   */

  maybeReadAccessTokenId: function(req, res, next) {
    req.oauth2.accessTokenId = req.get('x-access-token');
    next();

    //var header = req.get('Authorization');
    //
    //// Header: http://tools.ietf.org/html/rfc6750#section-2.1
    //if (header) {
    //  var matches = header.match(/Bearer\s(\S+)/);
    //  if (!matches) {
    //    return res.send(401, 'Malformed auth header');
    //  }
    //  req.access_token = matches[1];
    //  next();
    //} else {
    //  res.status(401);
    //  res.send('Nonexistent auth header');
    //}
  },

  /**
   *  Expects
   *
   *    - req.oauth2.accessTokenId
   */

  maybeLoadAccessToken: function(req, res, next) {
    var id = req.oauth2.accessTokenId;
    if (!id) return next();
    req.oauth2.AccessToken.load(id, function(err, accessToken) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      req.oauth2.accessToken = accessToken;
      next(err);
    });
  },

  maybeReadAccessTokenUserId: function(req, res, next) {
    var accessToken = req.oauth2.accessToken;
    req.oauth2.userId = accessToken && accessToken.user_id;
    next();
  },

  maybeReadAccessTokenClientId: function(req, res, next) {
    var accessToken = req.oauth2.accessToken;
    req.oauth2.clientId = accessToken && accessToken.client_id;
    next();
  },

  /**
   *  Expects
   *
   *    - req.oauth2.accessToken
   *    - req.oauth2.AccessToken.authorizationScope
   */

  requireAuthorizationScopeInAccessToken: function(req, res, next) {
    var err;
    var oauth2 = req.oauth2;
    var scopeArray = OAuth2.scopeArray(oauth2.accessToken.scope);
    var authorizationScope = oauth2.AccessToken.authorizationScope;
    if (scopeArray.indexOf(authorizationScope) < 0) {
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

  /**
   *  Intersects req.query.scope with req.body.scope.
   */

  readAuthorizedScope: function(req, res, next) {
    var err;
    var authorizedScope = OAuth2.scopeArray(req.body.authorized_scope || '');
    var requestedScope = OAuth2.scopeArray(req.query.scope || '');
    var scope = [];
    authorizedScope.forEach(function(token) {
      if (requestedScope.indexOf(token) >= 0) {
        scope.push(token);
      }
    });
    if (!scope.length) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: 'User denied the authorization request.'
      });
    }
    else {
      req.oauth2.scope = OAuth2.scopeString(scope);
    }
    next(err);
  },

  removeAuthorizationScope: function(req, res, next) {
    var oauth2 = req.oauth2;
    oauth2.scope = OAuth2.removeScope(
      oauth2.AccessToken.authorizationScope,
      oauth2.scope
    );
    next();
  },

  /**
   *  Builds an auth code from:
   *
   *    - req.oauth2.user
   *    - req.oauth2.client
   *    - req.oauth2.scope
   *
   */

  newAuthorizationCode: function(req, res, next) {
    var oauth2 = req.oauth2;
    var AuthorizationCode = oauth2.AuthorizationCode;
    var user = oauth2.user;
    var client = oauth2.client;
    var scope = oauth2.scope;

    AuthorizationCode.generateId(client, user, scope, function(err, id) {
      if (err || !id) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      else {
        var code = oauth2.code = {
          id: id,
          scope: scope,
          user_id: oauth2.userId,
          client_id: oauth2.clientId,
          redirect_uri: oauth2.redirectUri
        };

        if ('function' == typeof AuthorizationCode.lifetime) {
          code.lifetime = AuthorizationCode.lifetime(scope, client, user);
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

  sendCode: function(req, res, next) {
    var code = req.oauth2.code;
    var body = {
      code: code.id,
      scope: code.scope
    };
    if (req.query.state) {
      body.state = req.query.state;
    }
    body.redirect = OAuth2.extendUriQuery(
      req.oauth2.redirectUri,
      body
    );
    res.status(200).send(body);
  },

  okCodeRequest: function(req, res, next) {
    res.status(200).send({
      user: req.oauth2.user || null
    });
  },

  requireBodyAuthorizationCode: function(req, res, next) {
    var err;
    var codeId = req.oauth2.codeId = req.body.code;
    if (!codeId) {
      err = OAuth2Error({
        code: 'invalid_request',
        desc: 'Missing code parameter'
      });
    }
    next(err);
  },

  /**
   *  Expects
   *
   *    - req.oauth2.codeId
   */

  maybeLoadAuthorizationCode: function(req, res, next) {
    var err;
    var codeId = req.oauth2.codeId;
    if (!codeId) next();
    else {
      var AuthorizationCode = req.oauth2.AuthorizationCode;
      AuthorizationCode.load(codeId, function(err, code) {
        if (err) {
          err = OAuth2Error({
            code: 'server_error',
            desc: 'Error loading authorization code',
            error: err
          });
        }
        req.oauth2.code = code;
        next(err);
      });
    }
  },

  requireAuthorizationCode: function(req, res, next) {
    var err;
    if (!req.oauth2.code) {
      err = OAuth2Error({
        code: 'invalid_grant',
        desc: 'Invalid authorization code'
      });
    }
    next(err);
  },

  checkCodeExpiration: function(req, res, next) {
    var err;
    if (req.began > req.oauth2.code.expires) {
      err = OAuth2Error({
        code: 'invalid_grant',
        desc: 'Authorization code has expired'
      });
    }
    next(err);
  },

  /**
   *  Redirect uri must be re-sent in authorization code token
   *  request. Must match exactly with the one stored with the
   *  code model.
   */

  validateRedirectUriWithCode: function(req, res, next) {
    var err;
    if (req.oauth2.code.redirect_uri !== req.body.redirect_uri) {
      err = OAuth2Error({
        code: 'invalid_grant',
        desc: 'Redirect uri mismatch'
      });
    }
    next(err);
  },

  /**
   *  Expects
   *
   *    - req.oauth2.codeId
   */

  deleteAuthorizationCode: function(req, res, next) {
    var codeId = req.oauth2.codeId;
    if (!codeId) next();
    else {
      var AuthorizationCode = req.oauth2.AuthorizationCode;
      AuthorizationCode.del(codeId, function(err) {
        if (err) {
          err = OAuth2Error({
            code: 'server_error',
            desc: 'Could not delete authorization code',
            error: err
          });
        }
        next(err);
      });
    }
  },

  /**
   *  Requires
   *
   *    - req.oauth2.user
   *    - req.oauth2.client
   *    - req.oauth2.scope
   */

  newAccessToken: function(req, res, next) {
    var oauth2 = req.oauth2;
    var AccessToken = oauth2.AccessToken;
    var user = oauth2.user;
    var client = oauth2.client;
    var scope = oauth2.scope;
    AccessToken.generateId(function(err, id) {
      if (err || !id) {
        err = OAuth2Error({
          code: 'server_error',
          desc: 'Error generating access token',
          error: err
        });
      }
      else {
        var token = oauth2.accessToken = {
          id: id,
          scope: scope,
          user_id: oauth2.userId,
          client_id: oauth2.clientId
        };

        token.lifetime = (
          'function' == typeof AccessToken.lifetime ?
          AccessToken.lifetime(scope, client, user) :
          AccessToken.lifetime
        );

        token.expires = OAuth2.expirationFromLifetime(
          req.began,
          token.lifetime
        );
      }
      next(err);
    });
  },

  /**
   *  Expects
   *
   *    - req.oauth2.accessToken
   */

  saveAccessToken: function(req, res, next) {
    var accessToken = req.oauth2.accessToken;
    var AccessToken = req.oauth2.AccessToken;
    AccessToken.save(accessToken, function(err) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          desc: 'Could not save access token'
        });
      }
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
   *  Check the access token scope against the current scope
   *  set on req.oauth2.scope.
   *
   *  Requires
   *
   *    - req.oauth2.accessToken
   *    - req.oauth2.scope
   */

  checkAccessTokenScope: function(req, res, next) {
    var oauth2 = req.oauth2;
    var tokenScope = OAuth2.scopeArray(oauth2.accessToken.scope);
    var authorizedScope = OAuth2.scopeArray(oauth2.scope);
    for (var i = 0; i < tokenScope.length; i++) {
      if (authorizedScope.indexOf(tokenScope[i]) >= 0) {
        return next();
      }
    }
    res.status(401).send({
      error: 'Access denied. Token needs scope "' + oauth2.scope + '"'
    });
  },

  /**
   *  Requires
   *
   *    - req.oauth2.user
   *    - req.oauth2.client
   *    - req.oauth2.accessToken
   */

  newRefreshToken: function(req, res, next) {
    var oauth2 = req.oauth2;
    var RefreshToken = oauth2.RefreshToken;
    var AccessToken = oauth2.AccessToken;
    var user = oauth2.user;
    var client = oauth2.client;
    var accessToken = oauth2.accessToken; // The new access token

    var allow = (
      (
        ('function' == typeof AccessToken.allowRefresh) &&
        AccessToken.allowRefresh(accessToken, client, user)
      ) ||
      AccessToken.allowRefresh
    );

    if (!allow) return next();

    RefreshToken.generateId(function(err, id) {
      if (err || !id) {
        err = OAuth2Error({
          code: 'server_error',
          desc: 'Error generating refresh token',
          error: err
        });
      }
      else {
        var token = oauth2.refreshToken = {
          id: id,
          scope: accessToken.scope,
          user_id: oauth2.userId,
          client_id: oauth2.clientId
        };

        token.lifetime = (
          'function' == typeof RefreshToken.lifetime ?
          RefreshToken.lifetime(accessToken, client, user) :
          RefreshToken.lifetime
        );

        token.expires = OAuth2.expirationFromLifetime(
          req.began,
          token.lifetime
        );
      }
      next(err);
    });
  },

  saveRefreshToken: function(req, res, next) {
    var refreshToken = req.oauth2.refreshToken;
    var RefreshToken = req.oauth2.RefreshToken;
    if (!refreshToken) return next();
    RefreshToken.save(refreshToken, function(err) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          desc: 'Could not save refresh token',
          error: err
        });
      }
      next(err);
    });
  },

  /**
   *  Expects
   *
   *    - req.oauth2.accessToken
   *    - req.oauth2.refreshToken (if sending)
   *
   */

  sendToken: function(req, res, next) {
    var accessToken = req.oauth2.accessToken;
    var body = {
      access_token: accessToken.id,
      expires_in: accessToken.lifetime,
      token_type: accessToken.type,
      scope: accessToken.scope
    };

    var refreshToken = req.oauth2.refreshToken;
    if (refreshToken) {
      body.refresh_token = refreshToken.id;
    }

    res.status(200)
    .set('Cache-Control', 'no-store')
    .set('Pragma', 'no-cache')
    .send(body);
  },

  setUserIdFromClientId: function(req, res, next) {
    req.oauth2.userId = req.oauth2.clientId;
    next();
  },

  /**
   *  Requires:
   *
   *    - req.oauth2.userId
   *
   *  Saves user object to req.oauth2.user
   *
   *  If no user id exists, just skips to the next middleware.
   *
   */

  maybeLoadUser: function(req, res, next) {
    var userId = req.oauth2.userId;
    if (!userId) return next();
    req.oauth2.User.load(userId, function(err, user) {
      if (err) {
        err = OAuth2Error({
          code: 'server_error',
          error: err
        });
      }
      req.oauth2.user = user;
      next(err);
    });
  },

  requireUser: function(req, res, next) {
    var err;
    if (!req.oauth2.user) {
      err = OAuth2Error({
        code: 'access_denied',
        desc: 'User not found'
      });
    }
    next(err);
  },

  branchTokenRequest: function(req, res, next) {
    var grantType = req.body.grant_type;
    var flow = req.oauth2.flows[grantType];
    if (!flow) {
      err = OAuth2Error({
        code: 'unsupported_grant_type'
      });
      next(err);
    }
    else next(flow);
  },

  branchCodeAuthorizationRequest: function(req, res, next) {
    var flows = req.oauth2.flows;
    if (req.method === 'GET') next(flows.request);
    else if (req.method === 'POST') next(flows.authorization);
    else next();
  },

  authError: function(err, req, res, next) {
    if (err instanceof OAuth2Error) {
      var msg = {
        error: err.code || 'invalid_request',
        error_description: err.desc || '',
        error_uri: err.uri || ''
      };

      if (err.code === 'server_error' && req.oauth2.debug) {
        return next(err.error);
      }
  
      var redirectUri = req.oauth2.redirectUri;
      if (redirectUri && req.oauth2.redirectValidated) {
        if (req.oauth2.state) {
          msg.state = req.oauth2.state;
        }
        msg.redirect = OAuth2.extendUriQuery(redirectUri, msg);
      }

      res.status(400);
      res.send(msg);
    }
    else next(err);
  },

  tokenError: function(err, req, res, next) {
    if (err instanceof OAuth2Error) {
      var msg = {
        error: err.code || 'invalid_request',
        error_description: err.desc || '',
        error_uri: err.uri || ''
      };

      if (err.code === 'server_error' && req.oauth2.debug) {
        return next(err.error);
      }
      else {
        res.status(400);
        res.send(msg);
      }
    }
    else next(err);
  },

  accessError: function(err, req, res, next) {
    if (err instanceof OAuth2Error) {
      var msg = {
        error: err.code || 'invalid_request',
        error_description: err.desc || '',
        error_uri: err.uri || ''
      };

      if (err.code === 'server_error' && req.oauth2.debug) {
        return next(err.error);
      }

      var status;
      switch (err.code) {
        case 'access_denied': status = 401; break;
        case 'server_error': status = 500; break;
        default: status = 400;
      }

      res.status(status).send(msg);
    }
    else next(err);
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
    if (_debug) {
      if (fn.length == 3) {
        flow.push(function(req, res, next) {
          log(name);
          next();
        });
      }
      else if (fn.length == 4) {
        flow.push(function(err, req, res, next) {
          log(name);
          next(err);
        });
      }
    }
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
}

/**
 *  Runs an array of express-like middleware functions just like
 *  express does but adds the ability to pass an array of middleware
 *  functions to next() within each middleware function. This allows
 *  branching within an express request based on attributes other than
 *  the url pathname.
 */

function runFlow(flow, req, res, done) {
  (function run(pos, err) {
    if (Array.isArray(err)) runFlow(err, req, res, done);
    else if (pos === flow.length) done(err);
    else {
      var fn = flow[pos];
      var next = run.bind(null, pos + 1);
      if (err && fn.length === 4) fn(err, req, res, next);
      else if (!err && fn.length === 3) fn(req, res, next);
      else next(err); // skip the middleware
    }
  })(0);
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

function removeScope(remove, scope) {
  var newScope = OAuth2.scopeArray(scope);
  OAuth2.scopeArray(remove).forEach(function(string) {
    var index = newScope.indexOf(string);
    if (index >= 0) newScope.splice(index, 1);
  });
  return OAuth2.scopeString(newScope);
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

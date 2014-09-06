var crypto = require('crypto');
var auth = require('basic-auth');
var log = require('osh-util/logger')('OAuth2');
var bcrypt = require('bcrypt');
var extend = require('xtend/mutable');
var merge = require('xtend/immutable');
var Class = require('osh-class');
var series = require('osh-util/series');
var parseForm = require('body-parser').urlencoded({extended: false});

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



var OAuth2 = Class(function(opts) {
  this.oauth2 = extend(
    {
      expires_in: 3600,
      token_type: 'bearer'
    },
    opts
  );
});

/**
 *  Make a flow given an array of strings or functions.
 *
 *  Make a flow. This places a middleware at the beginning of the
 *  given stack that attaches this OAuth2 instance to the request
 *  object as req.oauth2.
 *
 *  @param {String|Array<String|Function>} actions
 */

OAuth2.prototype.flow = function(actions) {
  actions = (
    'string' == typeof actions ?
    OAuth2.FLOWS[actions] : actions
  );

  var oauth2 = this;
  var flow = [];

  actions.forEach(function(action) {
    if ('function' == typeof action) flow.push(action);
    else {
      action = (
        oauth2.opts[action] ||
        oauth2[action] ||
        OAuth2[action]
      );

      if (!action) {
        throw new Error(
          'Need action ' + action + ' for flow.'
        );
      }
      else if (Array.isArray(action)) {
        flow = flow.concat(action);
      }
      else flow.push(action);
    }
  });

  return flow;
};


/**
 *  Mapping between grant_type and token flow id for the token endpoint.
 */

OAuth2.TOKEN_FLOWS = {
  'authorization_code': 'code',
  'password': 'password',
  'client_credentials': 'client'
};

/**
 *  Mapping between response_type and auth flow id for the authorization
 *  endpoint.
 */

OAuth2.AUTH_FLOWS = {
  'authorization_code': OAuth2.TOKEN_FLOWS['authorization_code'],
  'token': 'implicit'
};

/**
 *  The ordered array of callbacks for the token endpoint.
 */


OAuth2.TOKEN_FLOW = [
  'setOptions',
  'attachErrorHandler',
  'validateTokenRequest',
  'readGrantType',
  'readClientCredentials',
  'loadClient',
  'authenticateClient',
  'readUserCredentials',
  'loadUser',
  'authenticateUser',
  'readScope',
  'newAccessToken',
  'newRefreshToken',
  'saveAccessToken',
  'saveRefreshToken',
  'sendToken'
];

OAuth2.BASE_TOKEN_FLOW = [
  'setOptions',
  'attachErrorHandler',
  'validateTokenRequest'
];

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
    'readClientCredentials',
    'loadClient',
    'authenticateClient',
    'allowClientPasswordToken',
    'readUserCredentials',
    'loadUser',
    'authenticateUser',
    'readScope',
    'newAccessToken',
    'newRefreshToken',
    'saveAccessToken',
    'saveRefreshToken',
    'sendToken'
  ],

  /**
   *  For requesting an access token where the client is the
   *  resource owner. This is a flow
   */

  CLIENT_TOKEN: [
    'validateClientTokenRequest',
    'readClientCredentials',
    'userFromClient',
    'loadUser',
    'authenticateUser',
    'readScope',
    'newAccessToken',
    'saveAccessToken',
    'sendToken'
  ],

  CODE_TOKEN: [
    'validateCodeTokenRequest',
    'readClientCredentials',
    'loadClient',
    'authenticateClient',
    'readAuthorizationCode',
    'loadAuthorizationCode',
    'validateRedirectUri',
    'scopeFromCode',
    'newAccessToken',
    'newRefreshToken',
    'saveAccessToken',
    'saveRefreshToken',
    'sendToken'
  ],

  AUTH: [
    'init',
    'validateAuthRequest',
    'branchAuthRequest'
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
    'loadClient',
    'validateRedirectUri'
  ],

  /**
   *  From the authorization form, a decision is sent here.
   */

  DECISION: [
    'readUserCredentials',
    'loadUser',
    'authenticateUser',
    'newAuthorizationCode',
    'saveAuthorizationCode',
    'redirect'
  ],

  IMPLICIT: [
    'validateRedirectUri'
  ]
};



/**
 *  Steps required before the authorization of a resource request.  These
 *  include parsing the access token from the request header, loading the
 *  access token attributes (scope, resource owner, expires, ...) from the
 *  database, and checking its expiration date.
 */

OAuth2.AUTH_FLOW = [
  'readAccessToken',
  'loadAccessToken',
  'checkExpiration'
];


extend(OAuth2, {
  init: function(req, res, next) {
    req.began = req.began || new Date();
    res.oauth2Error = function(code, desc, uri) {
      res.status(400);
      res.send({
        error: code || 'invalid_request',
        error_description: desc || '',
        error_uri: uri || ''
      });
    }
    log('Error handler registered');
    next();
  },

  AUTH_QUERY_PARAMS: {
    response_type: {
      required: true
    },
    client_id: {
      required: true
    },
    redirect_uri: {
      required: false
    },
    scope: {
      required: false
    },
    state: {
      required: false
    }
  },

  validateAuthRequest: function(req, res, next) {
    var param;
    for (var name in OAuth2.AUTH_QUERY_PARAMS) {
      param = OAuth2.AUTH_QUERY_PARAMS[name];
      if (!req.query[name] && param.required) {
        return res.oauth2Error(
          'invalid_request',
          'Authorization request is missing the ' + name +
          ' parameter'
        );
      }
      req[name] = req.query[name];
    }
    next();
  },

  branchAuthRequest: function(req, res, next) {
    var flow;
    var flows = req.oauth2.flows;
    switch (req.response_type) {
      case 'code':
        flow = flows.code;
        break;
      case 'token':
        flow = flows.implicit;
        break;
    }
    if (!flow) {
      res.oauth2Error(
        'unsupported_response_type'
      );
    }
    else OAuth2.runFlow(flow, req, res, next);
  },

  validateRedirectUri: function(req, res, next) {
    if (req.redirect_uri !== req.client.redirect_uri) {
      res.oauth2Error(
        'invalid_request',
        'Mismatching redirect_uri'
      );
    }
    else next();
  },

  TOKEN_GRANT_TYPE_PARAMS: {
    authorization_code: {
      code: {required: true},
      redirect_uri: {required: false},
      client_id: {required: false}
    },
    password: {
      username: {required: true},
      password: {required: true},
      scope: {required: false}
    },
    client_credentials: {
      scope: {required: false}
    }
  },


  validateTokenRequest: function(req, res, next) {
    if (!req.is('application/x-www-form-urlencoded') || req.method !== 'POST') {
      return res.oauth2Error(
        'invalid_request',
        'You must POST a request with content-type: ' +
        'application/x-www-form-urlencoded'
      );
    }
    if (!req.body) {
      parseForm(req, res, function(err) {
        if (err) next(err);
        else finish();
      });
    }
    else finish();

    function finish() {
      if (!req.body.grant_type) {
        return res.oauth2Error(
          'invalid_request',
          'Need to provide a grant_type'
        );
      }
      req.grant_type = req.body.grant_type;
      var params = OAuth2.TOKEN_GRANT_TYPE_PARAMS[req.grant_type];
      if (!params) {
        return res.oauth2Error(
          'invalid_grant',
          'Unknown grant type'
        );
      }
      var param;
      for (var name in params) {
        param = params[name];
        if (!req.body[name] && param.required) {
          return res.oauth2Error(
            'invalid_request',
            'Token request with grant_type "' + req.grant_type + 
            '" is missing the ' + name + ' parameter.'
          );
        }
        req[name] = req.body[name];
      }
      next();
    }
  },

  TOKEN_GRANT_TYPE_FLOWS: {
    authorization_code: 'code',
    password: 'password',
    client_credentials: 'client'
  },

  branchTokenRequest: function(req, res, next) {
    var id = OAuth2.TOKEN_GRANT_TYPE_FLOWS[req.grant_type];
    var flow = req.oauth2.flows[id];
    if (!flow) {
      res.oauth2Error(
        'unsupported_grant_type'
      );
    }
    else OAuth2.runFlow(flow, req, res, next);
  },

  readClientCredentials: function(req, res, next) {
    // Get client credentials from HTTP basic authentication.
    var creds = auth(req);
    if (!creds) {
      return res.oauth2Error(
        'invalid_client',
        'Need HTTP basic auth credentials for client'
      );
    }
    // Return client in RFC6749 terminology.
    req.client = {
      id: creds.name,
      secret: creds.pass
    };
    log('Load client', req.client.id);
    next();
  },

  loadClient: implement('loadClient()'),

  authenticateClient: function(req, res, next) {
    log('Authenticate client', req.client.id);
    var client = req.client;
    if (!client || !client.secret || !client.secret_hash) {
      return next(
        error(
          'Default client authentication. Missing req.client, ' +
          'req.client.secret, or req.client.secret_hash. Perhaps ' +
          'your loadClient() implementation did not set these?'
        )
      );
    }
    bcrypt.compare(
      client.secret,
      client.secret_hash,
      function(err, success) {
        if (success) next();
        else {
          res.oauth2Error(
            'invalid_client',
            'Invalid secret for client ' + req.client.id
          );
        }
      }
    );
  },

  /**
   *  Used in password token flow and auth code decision flow. This should
   *  try to get the
   *
   */

  readUserCredentials: function(req, res, next) {
    log('Read user credentials');
    req.user = {
      username: req.body.username,
      password: req.body.password
    };
    log('Load user', req.user.username);
    next();
  },

  userFromClient: function(req, res, next) {
    log('Set user credentials from client credentials');
    req.user = {
      username: req.client.id,
      password: req.client.secret
    };
    next();
  },

  loadUser: implement('loadUser'),

  authenticateUser: function(req, res, next) {
    log('Authenticate user', req.user.username);
    var user = req.user;
    if (!user || !user.password || !user.password_hash) {
      return next(
        error(
          'Default user authentication. Missing req.user, ' +
          'req.user.password, or req.user.password_hash. Perhaps ' +
          'your loadUser() implementation did not set these?'
        )
      );
    }
    bcrypt.compare(
      user.password,
      user.password_hash,
      function(err, success) {
        if (err) next(err);
        else if (success) next();
        else {
          res.oauth2Error(
            'invalid_grant',
            'Bad password for ' + user.username
          );
        }
      }
    );
  },

  readScope: function(req, res, next) {
    req.scope = (req.body.scope || req.query.scope || '').split(' ');
    log('Requested scope:', req.scope.join(' '));
    next();
  },

  loadRefreshToken: implement('loadRefreshToken'),

  checkRefreshToken: function(req, res, next) {
    if (req.refreshToken.expires < req.began) {
      res.oauth2Error(
        'invalid_grant',
        'The refresh token has expired'
      );
    } else {
      next();
    }
  },

  newAccessToken: function(req, res, next) {
    OAuth2.generateTokenId(function(err, id) {
      if (err) next(err);
      else {
        var expiresIn = 3600;
        var expires = new Date(req.began);
        expires.setSeconds(expires.getSeconds() + expiresIn);

        res.accessToken = {
          id: id,
          expiresIn: expiresIn,
          expires: expires,
          type: 'bearer',
          scope: req.scope
        };

        next();
      }
    });
  },

  newRefreshToken: function(req, res, next) {
    OAuth2.generateTokenId(function(err, id) {
      if (err) next(err);
      else {
        var expiresIn = 3600;
        var expires = new Date(req.began);
        expires.setSeconds(expires.getSeconds() + expiresIn);

        res.refreshToken = {
          id: id,
          expires: expires
        };

        next();
      }
    });
  },

  saveAccessToken: implement('saveAccessToken'),

  saveRefreshToken: implement('saveRefreshToken'),

  sendToken: function(req, res, next) {
    var body = {
      scope: res.accessToken.scope.join(' '),
      access_token: res.accessToken.id,
      expires_in: res.accessToken.expiresIn,
      token_type: res.accessToken.type
    };
    if (res.refreshToken) {
      body.refresh_token = res.refreshToken.id;
    }
    res.status(200);
    res.send(body);
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
      req.accessToken = {id: matches[1]};
      next();
    } else {
      res.status(401);
      res.send('Nonexistent auth header');
    }
  },

  loadAccessToken: implement('loadAccessToken'),

  checkAccessExpiration: function(req, res, next) {
    if (req.accessToken.expires < req.began) {
      res.send(401, 'Access token has expired');
    }
    else next();
  },

  checkRefreshExpiration: function(req, res, next) {
    if (req.accessToken.expires < req.began) {
      res.send(401, 'Access token has expired');
    }
    else next();
  },

  /**
   *  Static utility functions used by default middleware.
   */

  generateTokenId: function(callback) {
    crypto.randomBytes(256, function(ex, buffer) {
      if (ex) {
        return callback(new Error(
          'Error generating random bytes for access token'
        ));
      }
      callback(null,
        crypto.createHash('sha1')
        .update(buffer)
        .digest('hex')
      );
    });
  },

  runFlow: function(flow, req, res, next) {
    series(
      flow.map(function(middleware) {
        return middleware.bind(null, req, res);
      }),
      next
    );
  }

});



OAuth2.prototype.token = function(flows) {
  var flow = [attach].concat(this.flow('TOKEN'));
  var oauth2 = merge(this.oauth2, {
    flows: {
      password: this.flow('PASSWORD_TOKEN'),
      implicit: this.flow('CLIENT_TOKEN')
    }
  });

  return flow;

  function attach(req, res, next) {
    req.oauth2 = oauth2;
    next();
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
  return this.flow('SCOPE').concat(
    'string' == typeof scope ?
    checkScope : scope
  );

  // A scope possessed by the access token must match
  function checkScope(req, res, next) {
    var tokenScope = req.accessToken.scope;
    for (var i = 0; i < tokenScope.length; i++) {
      if (tokenScope[i] === scope) {
        return next();
      }
    }
    res.send(401,
      'Access denied. Token has scope: [' +
      tokenScope.join(', ') + '], but resource requires scope: ' +
      scope
    );
  }
};


OAuth2.prototype.authorize = function() {
  var flow = [attach].concat(this.flow('AUTH'));
  var oauth2 = merge(this.oauth2, {
    flows: {
      code: this.flow('CODE_AUTH'),
      implicit: this.flow('IMPLICIT_AUTH')
    }
  });

  return flow;

  function attach(req, res, next) {
    req.oauth2 = oauth2;
    next();
  }
};


OAuth2.prototype.decision = function() {

};


module.exports = OAuth2;

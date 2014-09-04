var crypto = require('crypto');
var auth = require('basic-auth');
var log = require('../util/logger')('OAuth2 Token');
var bcrypt = require('bcrypt');
var async = require('async');
var extend = require('xtend/mutable');


function implement(method) {
  return function(req, res, next) {
    next(
      new Error('OSH OAuth2: must implement ' + method)
    );
  };
}




var OAuth2 = Class(function(opts) {
  this._tokenFlow = flow(OAuth2.TOKEN_FLOW);
  this._resourceFlow = flow(OAuth2.AUTH_FLOW);

  function flow(actions) {
    var _flow = [];
    actions.forEach(function(action) {
      action = (
        action in opts ?
        opts[action] :
        OAuth2[action]
      );
      if (Array.isArray(action)) {
        _flow = _flow.concat(action);
      }
      else _flow.push(action);
    });
    return _flow;
  }
});


OAuth2.TOKEN_FLOW = [
  'setOptions',
  'attachErrorHandler',
  'validateTokenRequest',
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
  setOptions: function(req, res, next) {
    req.began = req.began || new Date();
    req.oauth2 = {
      accessToken: {
        expiresIn: 3600,
        type: 'bearer'
      },
      refreshToken: {
        expiresIn: 3600
      }
    };
    next();
  },

  // Register error handler on request object.
  attachErrorHandler: function(req, res, next) {
    log('Error handler registered');
    res.oAuth2Error = function(code, desc) {
      res.send(400, {
        error: code,
        error_description: desc
      });
    }
    next();
  },

  validateTokenRequest: function(req, res, next) {
    if (!req.is('application/x-www-form-urlencoded')) {
      res.oAuth2Error(
        'invalid_request',
        'You must POST a request with content-type: ' +
        'application/x-www-form-urlencoded'
      );
    }
    else if (!req.body.grant_type) {
      return res.send(400, {
        error: 'invalid_request',
        error_description: 'Need to provide a grant_type'
      });
    }
    else {
      log('Request is well-formed.');
      next();
    }
  },

  readClientCredentials: function(req, res, next) {
    // Get client credentials from HTTP basic authentication.
    var creds = auth(req);

    if (!creds) {
      return res.oAuth2Error(
        'invalid_client',
        'Need HTTP basic auth credentials for client'
      );
    }

    // Return client in RFC6749 terminology.
    req.client = {
      id: creds.name,
      secret: creds.pass
    };

    log('oauth client is:', req.client.id);
    next();
  },

  loadClient: implement('loadClient()'),

  authenticateClient: function(req, res, next) {
    var client = req.client;
    bcrypt.compare(
      client.secret,
      client.secret_hash,
      function(err, success) {
        if (success) {
          next();
        } else {
          res.oAuth2Error(
            'invalid_client',
            'Invalid secret for client ' + req.client.id
          );
        }
      }
    );
  },

  readUserCredentials: function(req, res, next) {
    log('password flow');

    req.user = {
      username: req.body.username,
      password: req.body.password
    };

    next();
  },

  loadUser: implement('loadUser'),

  authenticateUser: function(req, res, next) {
    var user = req.user;
    bcrypt.compare(user.password, user.pwhash, function(err, success) {
      if (err) {
        next(err);
      } else if (success) {
        next();
      } else {
        res.oAuth2Error(
          'invalid_grant',
          'Bad password for ' + user.username
        );
      }
    });
  },

  readScope: function(req, res, next) {
    req.scope = (req.body.scope || 'public').split(' ');
    next();
  },

  loadRefreshToken: implement('loadRefreshToken'),

  checkRefreshToken: function(req, res, next) {
    if (req.refreshToken.expires < req.began) {
      res.oAuth2Error(
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

        req.accessToken = {
          id: id,
          expiresIn: expiresIn,
          expires: expires,
          type: 'bearer'
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

        req.refreshToken = {
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
    res.send({
      scope: req.scope.join(' '),
      access_token: req.accessToken.id,
      refresh_token: req.refreshToken.id,
      expires_in: req.accessToken.expiresIn,
      token_type: req.accessToken.type
    });
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
      res.send(401, 'Nonexistent auth header');
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
  }

});


/**
 *  Create a single middleware function that runs a series of other
 *  middleware functions.
 */

function runner(middlewares) {
  return function(req, res, next) {
    series(
      middlewares.map(function(middleware) {
        return middleware.bind(null, req, res);
      }),
      next
    );
  };
}


OAuth2.prototype.token = function(flows) {
  return runner(this._tokenFlow);
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
  var actions = this._resourceFlow.concat(
    'string' == typeof scope ?
    checkScope : scope
  );

  return runner(actions);

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







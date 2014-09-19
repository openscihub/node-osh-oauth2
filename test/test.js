var OAuth2 = require('..');
var expect = require('expect.js');
var supertest = require('supertest');
var bcrypt = require('bcrypt');
var express = require('express');
var bodyParser = require('body-parser');
var log = require('osh-util/logger')('OAuth2 test');
var extend = require('xtend/mutable');
var merge = require('xtend');
var series = require('osh-util/series');

// In-memory persistence.
var accessTokens = {};
var refreshTokens = {};
var authorizationCodes = {};
var users = {
  'tony': {
    id: 'tony',
    realname: 'Tony'
  }
};
var clients = {
  'g00gle': {
    id: 'g00gle',
    secret_hash: bcrypt.hashSync('!evil', 8),
    redirect_uri: 'https://g00gle.com/callback'
  },
  'tony': {
    id: 'tony',
    secret_hash: bcrypt.hashSync('hey', 8)
  },
  'public': {
    id: 'public'
  }
};

function Model(store) {
  return {
    save: function(model, done) {
      store[model.id] = model;
      done();
    },
    load: function(id, done) {
      done(null, store[id]);
    },
    del: function(id, done) {
      delete store[id];
      done();
    }
  };
}

var Client = Model(clients);
Client.validateRedirectUri = function(uri, client) {
  return uri === client.redirect_uri;
};
Client.authenticate = function(secret, client, callback) {
  bcrypt.compare(secret, client.secret_hash, callback);
};

var AuthorizationCode = Model(authorizationCodes);
AuthorizationCode.lifetime = 600;

var AccessToken = Model(accessTokens);
AccessToken.lifetime = 3600;
AccessToken.allowRefresh = false;
AccessToken.revokeScope = false;
AccessToken.defaultScope = 'public';

var RefreshToken = Model(refreshTokens);
var User = Model(users);

function TestOAuth2(opts) {
  var oauth2 = OAuth2(
    merge(opts, {debug: true})
  );
  var app = express();
  app.use('/authorize', oauth2.authorize());
  app.post('/token', oauth2.token());
  return supertest(app);
}


describe('osh-oauth2', function() {
  describe('code authorization', function() {
    var request = TestOAuth2({
      Client: merge(Client, {allowGrant: ['authorization_code']}),
      AuthorizationCode: AuthorizationCode
    });

    describe('request', function() {
      it('should validate', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'code',
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callback'
        })
        .expect(200)
        .expect(/"user":null/i, done);
      });

      it('should 400 with mismatching redirect_uri', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'code',
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callbark'
        })
        .expect(400, /invalid redirect_uri/i, done);
      });

      it('should 400 with missing client_id', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'code',
          redirect_uri: 'https://g00gle.com/callbark'
        })
        .expect(400, /missing client id/i, done);
      });

      it('should redirect with missing response_type', function(done) {
        request.get('/authorize')
        .query({
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callback'
        })
        .expect(400, /"redirect"/)
        .expect(/missing/i, done);
      });

      it('should redirect with unrecognized response_type', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'geode',
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callback'
        })
        .expect(400, /"redirect"/)
        .expect(/unsupported_response_type/, done);
      });
    });
  });


  describe('client token', function() {
    it('should return requested scope, no refresh token', function(done) {
      TestOAuth2({
        User: User,
        Client: merge(Client, {
          allowGrant: ['client_credentials']
        }),
        AccessToken: merge(AccessToken, {
          defaultScope: 'public',
          revokeScope: false
        })
      })
      .post('/token')
      .type('form')
      .auth('tony', 'hey')
      .send({
        grant_type: 'client_credentials',
        scope: 'everything'
      })
      .expect(200)
      .expect(function(res) {
        if (/"refresh_token"/.test(res.body)) return 'got refresh_token';
      })
      .expect(/"scope":"everything"/, done);
    });

    it('should return refresh token', function(done) {
      TestOAuth2({
        User: User,
        Client: merge(Client, {
          allowGrant: ['client_credentials']
        }),
        AccessToken: merge(AccessToken, {
          defaultScope: 'public',
          revokeScope: false,
          allowRefresh: true
        }),
        RefreshToken: merge(RefreshToken, {
          lifetime: 3600
        })
      })
      .post('/token')
      .type('form')
      .auth('tony', 'hey')
      .send({
        grant_type: 'client_credentials',
        scope: 'everything'
      })
      .expect(200)
      .expect(/"refresh_token":"[0-9a-z]+"/, done);
    });

    it('should return default scope', function(done) {
      TestOAuth2({
        User: User,
        Client: merge(Client, {
          allowGrant: ['client_credentials']
        }),
        AccessToken: merge(AccessToken, {
          defaultScope: 'public',
          revokeScope: false
        })
      })
      .post('/token')
      .type('form')
      .auth('tony', 'hey')
      .send({
        grant_type: 'client_credentials'
      })
      .expect(200)
      .expect(/"scope":"public"/, done);
    });

    it('should revoke scope', function(done) {
      TestOAuth2({
        User: User,
        Client: merge(Client, {
          allowGrant: ['client_credentials']
        }),
        AccessToken: merge(AccessToken, {
          defaultScope: 'public',
          revokeScope: function(scope, user, client, callback) {
            callback(
              null,
              OAuth2.removeScope('secret', scope)
            );
          }
        })
      })
      .post('/token')
      .type('form')
      .auth('tony', 'hey')
      .send({
        grant_type: 'client_credentials',
        scope: 'public secret'
      })
      .expect(200)
      .expect(/"scope":"public"/, done);
    });
  });

  describe('token()', function() {
    it('should accept access token authentication', function(done) {
      var token;
      var request = TestOAuth2({
        User: User,
        Client: merge(Client, {
          allowGrant: ['client_credentials']
        }),
        AccessToken: merge(AccessToken, {
          defaultScope: 'public',
          revokeScope: false
        })
      });

      // First request gets an authorization token (i.e. logs in).
      request.post('/token')
      .type('form')
      .auth('tony', 'hey')
      .send({
        grant_type: 'client_credentials',
        scope: 'authorization'
      })
      .expect(200)
      .expect(/"scope":"authorization"/)
      .end(function(err, res) {
        if (err) done(err);
        else {
          // Second request uses authorization token as authentication.
          request.post('/token')
          .type('form')
          .set('x-access-token', res.body.access_token)
          .send({
            grant_type: 'client_credentials',
            scope: 'authorization secrets'
          })
          .expect(200)
          .expect(/"scope":"authorization secrets"/, done);
        }
      });
    });
  });

  describe('allow()', function() {
    var request;
    var token;

    function TestAllow(opts) {
      var oauth2 = OAuth2(
        merge({
          debug: true,
          User: User,
          Client: merge(Client, {
            allowGrant: ['client_credentials']
          }),
          AccessToken: merge(AccessToken, {
            defaultScope: 'public',
            allowRefresh: false,
            revokeScope: false
          })
        }, opts)
      );
      var app = express();
      app.post('/token', oauth2.token());
      app.get('/public', ok);
      app.get('/secret', oauth2.allow('secrets'), ok);
      app.get('/account', oauth2.allow('account'), ok);
      app.get('/both', oauth2.allow('public secrets'), ok);
      request = supertest(app);
    }

    function getToken(scope) {
      return function(done) {
        request.post('/token')
        .type('form')
        .auth('tony', 'hey')
        .send({
          grant_type: 'client_credentials',
          scope: scope
        })
        .expect(200, /access_token/)
        .end(function(err, res) {
          if (err) done(err);
          else {
            token = res.body.access_token;
            done();
          }
        });
      };
    }

    beforeEach(TestAllow.bind(null, {}));

    it('should deny access without token', function(done) {
      request.get('/secret')
      .expect(401, /access_denied/, done);
    });

    it('should deny access with wrong scope', function(done) {
      series([getToken('public'), getSecret], done);

      function getSecret(done) {
        request.get('/secret')
        .set('x-access-token', token)
        .expect(401, /Access denied/, done);
      }
    });

    it('should allow access', function(done) {
      series([getToken('secrets'), getSecret], done);

      function getSecret(done) {
        request.get('/secret')
        .set('x-access-token', token)
        .expect(200, /ok/, done);
      }
    });

    it('should allow access through multiple scopes', function(done) {
      series([getToken('secrets'), getBoth], done);

      function getBoth(done) {
        request.get('/both')
        .set('x-access-token', token)
        .expect(200, /ok/, done);
      }
    });

    it('should allow access with multi-scope', function(done) {
      series([getToken('account secrets'), getAccount, getSecret], done);

      function getAccount(done) {
        request.get('/account')
        .set('x-access-token', token)
        .expect(200, /ok/, done);
      }
      function getSecret(done) {
        request.get('/secret')
        .set('x-access-token', token)
        .expect(200, /ok/, done);
      }
    });

    it('should deny expired access token', function(done) {
      TestAllow({
        AccessToken: merge(AccessToken, {
          lifetime: 0
        })
      });

      series([getToken('secrets'), getSecret], done);

      function getSecret(done) {
        request.get('/secret')
        .set('x-access-token', token)
        .expect(401)
        .expect(/access_denied/)
        .expect(/expired/i, done);
      }
    });
  });

  describe('load()', function() {
    var oauth2 = OAuth2({
      debug: true,
      User: User,
      Client: merge(Client, {
        allowGrant: ['client_credentials']
      }),
      AccessToken: AccessToken
    });

    var app = express();
    app.post('/token', oauth2.token());
    app.get('/needtoken', oauth2.load(), function(req, res) {
      if (!req.oauth2.accessToken) res.status(400).send('bad');
      else ok(req, res);
    });
    app.get('/noneedtoken', oauth2.load(), ok);

    var request = supertest(app);

    it('should load access token', function(done) {
      var token;

      series([getToken, get], done);

      function getToken(done) {
        request.post('/token')
        .auth('tony', 'hey')
        .type('form')
        .send({
          grant_type: 'client_credentials',
          scope: 'whatever'
        })
        .end(function(err, res) {
          if (err) done(err);
          else {
            token = res.body.access_token;
            done();
          }
        });
      }

      function get(done) {
        request.get('/needtoken')
        .set('x-access-token', token)
        .expect(200, /ok/, done);
      }
    });

    it('should succeed without access token', function(done) {
      request.get('/noneedtoken')
      .expect(200, /ok/, done);
    });

  });

  /**
   *  Test the full process of validating an auth code request, making a
   *  decision (as the resource owner), and requesting the token (as the
   *  client).
   */

  describe('auth code token', function() {
    
    var oauth2 = OAuth2({
      debug: true,
      AuthorizationCode: AuthorizationCode,
      Client: merge(Client, {
        allowGrant: ['client_credentials', 'authorization_code']
      }),
      User: User,
      AccessToken: merge(AccessToken, {
        defaultScope: 'public',
        revokeScope: false
      })
    });

    var app = express();
    app.use('/authorize', oauth2.authorize());
    app.post('/token', oauth2.token());

    var request = supertest(app);

    it('should work', function(done) {
      var code;
      var access_token;

      var query = {
        response_type: 'code',
        client_id: 'g00gle',
        redirect_uri: 'https://g00gle.com/callback',
        scope: 'accounts secrets',
        state: 'csrf'
      };

      function login(done) {
        request.post('/token')
        .type('form')
        .auth('tony', 'hey')
        .send({
          grant_type: 'client_credentials',
          scope: 'authorization'
        })
        .expect(200, /authorization/)
        .end(function(err, res) {
          if (err) done(err);
          else {
            access_token = res.body.access_token;
            done();
          }
        });
      }

      function validate(done) {
        request.get('/authorize')
        .set('x-access-token', access_token)
        .query(query)
        .expect(200, /Tony/, done);
      }

      function decide(done) {
        request.post('/authorize')
        .type('form')
        .set('x-access-token', access_token)
        .query(query)
        .send(
          {authorized_scope: 'accounts'}
        )
        .expect(200)
        .expect(/"code":/)
        .end(function(err, res) {
          if (err) done(err);
          else {
            code = res.body.code;
            expect(res.body.redirect).to.be.ok();
            done();
          }
        });
      }

      function token(done) {
        request.post('/token')
        .type('form')
        .auth('g00gle', '!evil')
        .send({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: 'https://g00gle.com/callback'
        })
        .expect(200)
        .expect(/access_token/, done);
      }

      series([login, validate, decide, token], done);
    });
  });

  xdescribe('password token', function() {
    var oauth2 = OAuth2({
    });

    var app = express();
    //app.post(
    //  '/token',
    //  oauth2.token()
    //);
    var request = supertest(app);

    it('should return a token', function(done) {
      request.post('/token')
      .auth('g00gle', '!evil')
      .type('form')
      .send({
        grant_type: 'password',
        username: 'tony',
        password: 'hey',
        scope: 'accounts secrets'
      })
      .expect(200)
      .expect(/access_token/, done);
    });

    it('should fail from bad client secret', function(done) {
      request.post('/token')
      .auth('g00gle', '!!evil')
      .type('form')
      .send({
        grant_type: 'password',
        username: 'tony',
        password: 'hey',
        scope: 'accounts secrets'
      })
      .expect(401, done);
    });

    it('should fail from bad user password', function(done) {
      request.post('/token')
      .auth('g00gle', '!evil')
      .type('form')
      .send({
        grant_type: 'password',
        username: 'tony',
        password: 'hey NOPE',
        scope: 'accounts secrets'
      })
      .expect(400, /password/, done);
    });
  });
});



function clearTokens() {
  accessTokens = {};
  refreshTokens = {};
  authorizationCodes = {};
}


function pass(req, res, next) {
  next();
}

function ok(req, res) {
  res.send('ok');
}

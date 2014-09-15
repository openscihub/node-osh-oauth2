var OAuth2 = require('..');
var expect = require('expect.js');
var supertest = require('supertest');
var hash = require('bcrypt').hashSync;
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
    secret_hash: hash('!evil', 8),
    redirect_uri: 'https://g00gle.com/callback'
  },
  'tony': {
    id: 'tony',
    secret_hash: hash('hey', 8)
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

var AuthorizationCode = Model(authorizationCodes);
AuthorizationCode.lifetime = 600;
// lifetime: function(client, user, scope) {
//  if (client.type === 'public') return 3141592;
//  else return 600;
// }

var AccessToken = Model(accessTokens);
AccessToken.lifetime = 3600;
AccessToken.allowRefresh = false;

var RefreshToken = Model(refreshTokens);
var User = Model(users);


function clearTokens() {
  accessTokens = {};
  refreshTokens = {};
  authorizationCodes = {};
}


function pass(req, res, next) {
  next();
}


describe('osh-oauth2', function() {
  describe('code authorization', function() {
    var oauth2 = OAuth2({
      debug: true,
      Client: merge(Client, {grants: ['authorization_code']}),
      AuthorizationCode: AuthorizationCode
    });

    var app = express();
    app.get(
      '/authorize',
      oauth2.authorize()
    );
    var request = supertest(app);

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

  function OAuth2Token(opts) {
    var oauth2 = OAuth2(
      merge(opts, {debug: true})
    );
    var app = express();
    app.post(
      '/token',
      oauth2.token()
    );
    return supertest(app);
  }

  describe('client token', function() {
    it('should return requested scope', function(done) {
      OAuth2Token({
        User: User,
        Client: merge(Client, {
          grants: ['client_credentials']
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
      .expect(/"scope":"everything"/, done);
    });

    it('should return default scope', function(done) {
      OAuth2Token({
        User: User,
        Client: merge(Client, {
          grants: ['client_credentials']
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
      .expect(/access_token/)
      .expect(/expires_in/)
      .expect(/scope/)
      .expect(/public/, done);
    });

    it('should revoke scope', function(done) {
      OAuth2Token({
        User: User,
        Client: merge(Client, {
          grants: ['client_credentials']
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
        grants: ['client_credentials', 'authorization_code']
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
          merge(query, {scope: 'accounts'})
        )
        .end(function(err, res) {
          if (err) done(err);
          else {
            console.log(res.body);
            code = res.body.code;
            expect(res.body.redirect).to.be.ok();
            console.log(code);
            done();
          }
        });
      }

      function token(done) {
        request.post('/token')
        .type('form')
        .auth('g00gle', '!evil')
        .send({
          grant_type: 'bauthorization_code',
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

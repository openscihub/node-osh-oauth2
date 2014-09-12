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
    username: 'tony',
    password_hash: hash('hey', 8)
  }
};
var clients = {
  'g00gle': {
    client_id: 'g00gle',
    client_secret_hash: hash('!evil', 8),
    redirect_uri: 'https://g00gle.com/callback'
  },
  'public': {
    client_id: 'public'
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
var RefreshToken = Model(refreshTokens);


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
      grants: ['authorization_code'],
      Client: Client,
      AuthorizationCode: AuthorizationCode
    });

    var app = express();
    app.get(
      '/authorize',
      oauth2.authorize()
    );
    var request = supertest(app);

    describe.only('request', function() {
      it('should validate', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'code',
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callback'
        })
        .expect(200)
        .expect(/user/i, done);
      });

      it('should 400 with mismatching redirect_uri', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'code',
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callbark'
        })
        .expect(400, /mismatch/, done);
      });

      it('should 400 with missing client_id', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'code',
          redirect_uri: 'https://g00gle.com/callbark'
        })
        .expect(400, /missing client_id/i, done);
      });

      xit('should redirect with unrecognized response_type', function(done) {
        request.get('/authorize')
        .query({
          response_type: 'geode',
          client_id: 'g00gle',
          redirect_uri: 'https://g00gle.com/callback'
        })
        .redirects(0)
        .expect(302)
        .expect('Location', /unsupported_response_type/, done);
      });
    });
  });

  /**
   *  Test the full process of validating an auth code request, making a
   *  decision (as the resource owner), and requesting the token (as the
   *  client).
   */

  describe('auth code token', function() {
    
    var oauth2 = OAuth2({
      AuthorizationCode: AuthorizationCode
    });

    var app = express();
    app.use('/authorize', oauth2.authorize());
    //app.post('/token', oauth2.token());

    var request = supertest(app);

    it('should work', function(done) {
      // Authorization code returned from decision endpoint.
      var code;

      var query = {
        response_type: 'code',
        client_id: 'g00gle',
        redirect_uri: 'https://g00gle.com/callback',
        scope: 'accounts secrets',
        state: 'csrf'
      };

      function validate(done) {
        request.get('/authorize')
        .query(query)
        .expect(200, done);
      }

      function decide(done) {
        request.post('/authorize')
        .type('form')
        .auth('tony', 'hey')
        .send(
          merge(query, {scope: 'accounts'})
        )
        .redirects(0)
        //.end(function(err, res) {
        //  console.log(res.text);
        //  done(err);
        //});
        .expect(302)
        .expect('Location', /g00gle/)
        .expect('Location', /code=/)
        .expect('Location', /state=csrf/)
        .end(function(err, res) {
          if (err) done(err);
          else {
            code = /code=(\w+)/.exec(res.header['location'])[1];
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
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: 'https://g00gle.com/callback'
        })
        .expect(200)
        .expect(/access_token/, done);
      }

      series([validate, decide, token], done);
    });
  });

  describe('password token', function() {
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

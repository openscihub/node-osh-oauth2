var OAuth2 = require('..');
var bcrypt = require('bcrypt');
var supertest = require('supertest');
var express = require('express');

var oauth2 = OAuth2({
  User: {
    load: function(id, callback) {
      // There can only be one...
      callback(null, {
        name: 'Homer'
      });
    }
  },

  Client: {
    load: function(id, callback) {
      // There can only be one...
      callback(null, {
        secret_hash: bcrypt.hashSync('d0nutz', 10)
      });
    },
    authenticate: function(secret, client, callback) {
      bcrypt.compare(secret, client.secret_hash, callback);
    },
    allowGrant: ['client_credentials']
  },

  AccessToken: {
    lifetime: 3600,
    defaultScope: 'public',
    revokeScope: false,
    allowRefresh: false,
    save: function(token, callback) {
      callback(); // don't really save it.
    }
  }
});

var api = express();

api.post(
  '/token',
  oauth2.token()
);

var request = supertest(api);

request.post('/token')
.type('form')
.auth('homer', 'd0nutz')
.send({
  grant_type: 'client_credentials',
  scope: 'secrets'
})
.expect(200, /access_token/)
.end(function(err, res) {
  console.log(res.body);
});

var OAuth2 = require('..');
var expect = require('expect.js');
var supertest = require('supertest');
var hash = require('bcrypt').hashSync;
var express = require('express');
var bodyParser = require('body-parser');
var log = require('osh-util/logger')('OAuth2 test');

// In-memory persistence.
var accessTokens = {};
var refreshTokens = {};
var users = {
  'tony': {
    username: 'tony',
    password: 'hey',
    password_hash: hash('hey', 8)
  }
};
var clients = {
  'g00gle': {
    id: 'g00gle',
    secret: '!evil',
    secret_hash: hash('!evil', 8)
  }
};

// The minimal configuration.
var oauth2 = OAuth2({
  saveAccessToken: function(req, res, next) {
    accessTokens[res.accessToken.id] = res.accessToken;
    next();
  },
  loadAccessToken: function(req, res, next) {
    req.accessToken = accessTokens[req.accessToken.id];
    next();
  },
  saveRefreshToken: function(req, res, next) {
    refreshTokens[res.refreshToken.id] = res.refreshToken;
    next();
  },
  loadRefreshToken: function(req, res, next) {
    req.refreshToken = refreshTokens[req.refreshToken.id];
    next();
  },
  loadUser: function(req, res, next) {
    req.user = users[req.user.username];
    next();
  },
  loadClient: function(req, res, next) {
    req.client = clients[req.client.id];
    next();
  }
});

var app = express();

app.use(bodyParser.urlencoded({extended: false}));

app.post(
  '/oauth2/token',
  function(req, res, next) {
    console.log(req.body);
    next();
  },
  oauth2.token('password')
);

app.get(
  '/user/:username',
  oauth2.scope('account'),
  function(req, res) {
    res.send(users[req.params.username]);
  }
);


describe('osh-oauth2', function() {
  before(function(done) {
    app.listen(3333, done);
  });

  it('should work', function(done) {
    var request = supertest(app);
    request.post('/oauth2/token')
    .auth('g00gle', '!evil')
    .type('form')
    .send({
      grant_type: 'password',
      username: 'tony',
      password: 'hey',
      scope: 'accounts secrets'
    })
    .end(function(err, res) {
      console.log(res.text);
      done();
    });
  });
});

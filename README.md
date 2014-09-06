# OAuth2

A collection of Connect/Express middleware functions and orderings that help
you implement an OAuth2 server in Node.js. This library was built (amongst the
others) with extensibility in mind, keeping the developer near those middleware
`req` and `res` objects that are oh so familiar and warm.

## Example

A simple and complete, in-memory example.

```js
var OAuth2 = require('osh-oauth2');
var hash = require('bcrypt').hashSync;
var express = require('express');

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
    accessTokens[req.accessToken.id] = req.accessToken;
    next();
  },
  loadAccessToken: function(req, res, next) {
    req.accessToken = accessTokens[req.accessToken.id];
    next();
  },
  saveRefreshToken: function(req, res, next) {
    refreshTokens[req.refreshToken.id] = req.refreshToken;
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
    req.client = users[req.user.username];
    next();
  }
});

var app = express();

app.post(
  '/oauth2/token',
  oauth2.token('password')
);

app.get(
  '/user/:username',
  oauth2.scope('account'),
  function(req, res) {
    res.send(users[req.params.username]);
  }
);

app.listen(3333);
```

## Documentation

- [Configuration](#configuration)
- [Methods](#methods)
  - [generateTokenId()](oauth2generatetokenid)
  - [token()](#oauth2prototypetoken)
  - [scope()](#oauth2prototypescope)
- [Flows](#flows)
  - [Token flows](#token-flows)
    - [Code flow](#code-flow)
    - [Password flow](#password-flow)
    - [Refresh flow](#refresh-flow)
  - [Resource flow](#resource-flow)
- [Data structures](#data-structures)

### Configuration

This library is customized by overriding its [middleware
functions](#middleware). New middleware is defined on a configuration object or
on the instance itself under the same identifiers as [listed
below](#middleware).  Default middleware can be replaced by a function or an
array of functions where each function conforms to the usual Connect/Express
middleware signature (make sure to call `next()`!).  If an array is given, they
will be executed in order wherever the default middleware would have run.

The configuration object will be available in each middleware function
at `req.oauth2`; for example, from the [init](#init) middleware:

```js
var oauth2 = OAuth2({
  expires_in: 3600,
  init: function(req, res, next) {
    console.log(req.oauth2.expires_in); // 3600!
  }
});
```

There are some default parameters for use by the default middleware. These
are:

- `req.oauth2.expires_in`: This is used by the default middleware to generate
  a new access token. Default value is 3600 (seconds).
- `req.oauth2.token_type`: Set to `'bearer'`. You probably do not want to
  change this.

### Methods

Non-middleware OAuth2 class/instance methods.

#### OAuth2.generateTokenId

This is used by the default implementations of [newAccessToken](#newaccesstoken)
and [newRefreshToken](#newrefreshtoken).

Signature

```
Function(Function(Error err, String id)<> callback)<>
```

Uses the [crypto](http://nodejs.org/api/crypto.html) library to SHA1 hash
256 random bytes into a hexadecimal string.

#### OAuth2.prototype.token

Return a middleware function that handles requests for access tokens. Must be
mounted as an HTTP POST endpoint.

Signature

```
Function(Array<String> flows)<Function>
```

where an entry in `flows` is one of:

- `'password'` (see [password flow](#password-flow))
- `'client'` (see [client flow](#client-flow))
- `'code'` (see [code flow](#code-flow))
- `'implicit'` (see [implicit flow](#implicit-flow))

Example usage:

```js
app.get(
  '/oauth2/token',
  oauth2.token(['password', 'client'])
);
```

**NOTICE**: Sorry, only `'password'` is supported right now.

#### OAuth2.prototype.scope

Return middleware that restricts access to a resource by OAuth2 scope. The
returned middleware checks for an access token in the HTTP request, loads its
scope from persistent storage, and checks that scope against the scope required
to access the protected resource. See [resource flow](#resource-flow).

Signature

```
Function(String scope)<Function>
```

For a resource request to succeed, the given `scope` must exist in the scope
of the access token accompanying the request.

In the example below, the phone number will be sent only if `'sensitive'`
is found in the `req.accessToken.scope` array.

```js
app.get(
  '/sensitive/data',
  oauth2.scope('sensitive'),
  function(req, res) {
    res.send('my phone number is 555-5555');
  }
);
```


### Flows

The various ways to interact with an OAuth2 authorization server are referred
to as "flows" in [the
standard](http://tools.ietf.org/html/rfc6749#section-1.3)). In the context of
this library, "flow" means any ordered set of calls to recognized middleware
(or named steps); for example, this includes the "flow" involved in authorizing
a client access to a resource.

#### Authorization flows

These are flows behind the authorization endpoint.

The authorization process requires:

- A GET authorization endpoint. This returns a form that the resource owner
  completes to deny/allow access to the requesting client.
- A POST decision endpoint. The authorization form contents are sent here
  after the resource owner denies/allows access to a client.

- [validateAuthRequest](#validateauthrequest)
- [branchAuthRequest](#branchauthrequest)

##### Code authorization

- [loadClient](#loadclient)
- [validateRedirectUri](#validateredirecturi)

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.1

##### Decision flow

##### Implicit authorization

#### Token flows

These are the flows for requesting an access token.

All of the following flows are preceded by these steps (which are
therefore omitted from the individual token flow lists):

1. [setOptions](#setoptions)
2. [attachErrorHandler](#attacherrorhandler)
3. [validateTokenRequest](#validatetokenrequest)

##### Client token flow

- [validateClientTokenRequest](#validateclienttokenrequest)
- [readClientCredentials](#readclientcredentials)
- [userFromClient](#userfromclient)
- [loadUser](#loaduser)
- [authenticateUser](#authenticateuser)
- [readScope](#readscope)
- [newAccessToken](#newaccesstoken)
- [saveAccessToken](#saveaccesstoken)
- [sendToken](#sendtoken)

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.4

##### Code token flow

- [validateCodeTokenRequest](#validatecodetokenrequest)
- [readClientCredentials](#readclientcredentials)
- [loadClient](#loadclient)
- [authenticateClient](#authenticateclient)
- [readAuthorizationCode](#readauthorizationcode)
- [loadAuthorizationCode](#loadauthorizationcode)
- [validateRedirectUri](#validateredirecturi)
- [scopeFromCode](#scopefromcode)
- [newAccessToken](#newaccesstoken)
- [newRefreshToken](#newrefreshtoken)
- [saveAccessToken](#saveaccesstoken)
- [saveRefreshToken](#saverefreshtoken)
- [sendToken](#sendtoken)

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.1.3

##### Password token flow


Support for the [password authorization grant
type](http://tools.ietf.org/html/rfc6749#section-4.3) is enabled when
`'password'` is passed to [token()](#oauth2prototypetoken).

- [validatePasswordTokenRequest](#validatepasswordtokenrequest)
- [readClientCredentials](#readclientcredentials)
- [loadClient](#loadclient)
- [authenticateClient](#authenticateclient)
- [allowClientPasswordToken](#allowclientpasswordtoken)
- [readUserCredentials](#readusercredentials)
- [loadUser](#loaduser)
- [authenticateUser](#authenticateuser)
- [readScope](#readscope)
- [newAccessToken](#newaccesstoken)
- [newRefreshToken](#newrefreshtoken)
- [saveAccessToken](#saveaccesstoken)
- [saveRefreshToken](#saverefreshtoken)
- [sendToken](#sendtoken)

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.3

##### Refresh flow

#### Resource flow

This is the set of middleware executed when a request is made to an endpoint
protected by [scope()](#oauth2prototypescope) middleware.

### Middleware

The following is the collection of middleware expected by osh-oauth2. An
incarnation of each exists as a static method on the class returned by this
module and acts as the default for that method on an OAuth2 instance.
Emphasized names *require* custom implementations, usually because they depend
on some kind of persistent storage mechanism.

- [setOptions](#setoptions)
- [attachErrorHandler](#attacherrorhandler)
- [validateTokenRequest](#validatetokenrequest)
- [readClientCredentials](#readclientcredentials)
- [**loadClient**](#loadclient)
- [authenticateClient](#authenticateclient)
- [readUserCredentials](#readusercredentials)
- [**loadUser**](#loaduser)
- [authenticateUser](#authenticateuser)
- [readScope](#readscope)
- [newAccessToken](#newaccesstoken)
- [**saveAccessToken**](#saveaccesstoken)
- [**loadAccessToken**](#loadaccesstoken)
- [newRefreshToken](#newrefreshtoken)
- [**saveRefreshToken**](#saverefreshtoken)
- [**loadRefreshToken**](#loadrefreshtoken)

#### init

- [Token flows](#token-flows) [&#8594;](#validatetokenrequest)
- [Authorization flows](#authorization-flows) [&#8594;](#validateauthrequest)

Initializes some OAuth2-specific properties on the request and response
objects.

- `req.began`: This is set to `new Date()` if it does not already exist.
- `res.oauth2Error`: This is a function that returns a 400 response formatted
  according to the standard.

#### setOptions

Middleware for customizing subsequent default middleware behavior
(e.g. the lifetime of new access tokens generated by the default
implementation of [newAccessToken](#newaccesstoken)).

Shown below are the options recognized by later default middleware
and their default values.

```js
req.oauth2 = {

  // Options for default access token creation (see newAccessToken
  // middleware).
  accessToken: {

    // Lifetime to set on all new access tokens.
    expiresIn: 3600,

    // The token type. Just leave this as 'bearer'
    type: 'bearer'
  }
};
```

A common way of modifying setOptions is to override its default behavior,
which involves:

```js
var oauth2 = OAuth2({
  setOptions: [
    OAuth2.setOptions,
    function(req, res, next) {
      req.oauth2.accessToken.expiresIn = 200;
      // override other req.oauth2 options...
      next();
    }
  ]
});
```

Notice that, with this technique, one can set options *per request*.


#### attachErrorHandler

The result of this middleware must be a function of the following form attached
to the response object under the name `oAuth2Error` that, when invoked, returns
a 400 response to the client conforming to the [OAuth2
standard](http://tools.ietf.org/html/rfc6749#section-5.2).

```
Function(String error, String error_description, String error_uri)
```

The parameters in the above are those expected by [the
standard](http://tools.ietf.org/html/rfc6749#section-5.2); `error_description`
and `error_uri` should be optional.

In subsequent middleware, one should be able to call the error
handler like this:

```js
res.oAuth2Error(
  'client_error',
  'No one likes this client'
);
```

Standard references:

- http://tools.ietf.org/html/rfc6749#section-5.2

#### validateAuthRequest

- [&#8592;](#init) [Authorization flows](#authorization-flows) [&#8594;](#branchauthrequest)

This middleware runs through the query parameters that are expected on an
authorization GET request. These are:

- `response_type`
- `client_id`
- `redirect_uri`
- `scope`
- `state`

The value from each is placed directly on the request object under the
same identifier (e.g. `req.response_type`) for later use.

Standard references

- http://tools.ietf.org/html/rfc6749#section-4.1.1
- http://tools.ietf.org/html/rfc6749#section-4.2.1


#### branchAuthRequest

- [&#8592;](#validateauthrequest) [Authorization flows](#authorization-flows) 

| prev | flow | next |
|------|------|------|
| [validateAuthRequest](#validateauthrequest) | [Authorization flow](#authorization-flows) | &nbsp; |
| &nbsp; | [Authorization code](#code-authorization-flow) | []() |

<table>
  <tr>
    <td>[&#8592;](#validateAuthRequest)</td>
    <td>[Authorization flow](#authorization-flows)</td>
    <td>[&#8594;]()</td>
  </tr>
</table>

This middleware validates the `req.response_type` and kicks off another
subflow depending on its value.

#### validateTokenRequest

- [&#8592;](#init) [Token flows](#token-flows) [&#8594;](#branchtokenrequest)

Validate various aspects of a token request. The default implementation
checks that the request type is `application/x-www-form-urlencoded`, and
that the `grant_type` parameter is present in the request body. If validation
is successful, it sets `req.endpoint = 'token'` and `req.flow` to one of

- `'code'` for authorization code flow,
- `'password'` for password flow, or
- `'client'` for the client flow.

Standard references:

- http://tools.ietf.org/html/rfc6749#section-3.2


#### branchTokenRequest

- [&#8592;](#validatetokenrequest) [Token flows](#token-flows) 

Switches to one of the following flows depending on the `req.grant_type`
found in [validateTokenRequest](#validatetokenrequest):

- [Password token flow](password-token-flow)
- [Client token flow](client-token-flow)
- [Code token flow](code-token-flow)

#### readClientCredentials

- [&#8592;](#validatepasswordtokenrequest) [Password token flow](#password-token-flow) [&#8594;](#loadclient)
- [&#8592;](#validateclienttokenrequest) [Client token flow](#client-token-flow) [&#8594;](#userfromclient)
- [&#8592;](#validatecodetokenrequest) [Code token flow](#code-token-flow) [&#8594;](#loadclient)

Flows: [token](#token-flows)

The result of this middleware should be a `client` object attached to the
request object that has the following properties.

- `id {String}`:
- `secret {String}`:

The default implementation uses the
[basic-auth](https://github.com/jshttp/node-basic-auth) module to get this
information from the Authorization header.

Subsequent middleware should be able to access the client credentials like:

```js
function middleware(req, res, next) {
  var client = Clients.find(req.client.id);
  if (client.secret !== req.client.secret) {
    next(new Error);
  }
  else next();
}
```

Standard references:

- http://tools.ietf.org/html/rfc6749#section-2
- http://tools.ietf.org/html/rfc6749#section-3.2.1

#### loadClient

- [&#8592;](#readclientcredentials) [Password token flow](#password-token-flow) [&#8594;](#authenticateclient)
- [&#8592;](#readclientcredentials) [Code token flow](#code-token-flow) [&#8594;](#authenticateclient)
- [Code authorization](#code-authorization) [&#8594;](#validateredirecturi)

Flows: [token](#token-flows)

Load client information from persistent storage and add it to the `req.client`
object. The default implementation throws an Error.

#### authenticateClient

- [&#8592;](#loadclient) [Password token flow](#password-token-flow) [&#8594;](#allowclientpasswordtoken)
- [&#8592;](#loadclient) [Code token flow](#code-token-flow) [&#8594;](#readauthorizationcode)

Flows: [token](#token-flows)

Given client credentials from [readClientCredentials](#readclientcredentials)
and client properties from [loadClient](#loadclient), authenticate the
client. That is, check that the secret given in the request matches the (hashed!)
secret stored by the backend.

The default authenticateClient middleware assumes the following two properties
on the `req.client` object:

- `secret {String}`: See [readClientCredentials](#readclientcredentials).
- `secret_hash {String}`: This is a hash that is assumed to have been produced
  by passing `req.client.secret` through
  [bcrypt.hash](https://github.com/ncb000gt/node.bcrypt.js).

#### readUserCredentials

- [&#8592;](#allowclientpasswordtoken) [Password token flow](#password-token-flow) [&#8594;](#loaduser)
- [Decision flow](#decision-flow) [&#8594;](#loaduser)

Flows: [password](#password-flow)

Read the resource owner (i.e. user) credentials from the request body and
set them on a new `req.user` object as:

- `username {String}`: See [the standard](http://tools.ietf.org/html/rfc6749#section-4.3.2).
- `password {String}`: See [the standard](http://tools.ietf.org/html/rfc6749#section-4.3.2).

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.3.2

#### loadUser

- [&#8592;](#readusercredentials) [Password token flow](#password-token-flow) [&#8594;](#authenticateuser)
- [&#8592;](#userfromclient) [Client token flow](#client-token-flow) [&#8594;](#authenticateuser)
- [&#8592;](#readusercredentials) [Decision flow](#decision-flow) [&#8594;](#authenticateuser)

Flows: [password](#password-flow)

Load user (resource owner) information from persistent storage and add it to
the `req.user` object. The default implementation throws an Error.

#### authenticateUser

- [&#8592;](#loaduser) [Password token flow](#password-token-flow) [&#8594;](#readscope)
- [&#8592;](#loaduser) [Client token flow](#client-token-flow) [&#8594;](#readscope)
- [&#8592;](#loaduser) [Decision flow](#decision-flow) [&#8594;](#newauthorizationcode)

Flows: [password](#password-flow)

Given user credentials [read from the request](#readusercredentials)
and properties [loaded from persistent storage](#loaduser), authenticate the
client. That is, check that the secret given in the request matches the (hashed!)
secret stored by the backend.

The default authenticateClient middleware assumes the following two properties
on the `req.client` object:

- `password {String}`: See [readUserCredentials](#readusercredentials).
- `password_hash {String}`: This is a hash that is assumed to have been produced
  by passing `req.user.password` through
  [bcrypt.hash](https://github.com/ncb000gt/node.bcrypt.js).

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.3.2

#### readScope

- [&#8592;](#authenticateuser) [Password token flow](#password-token-flow) [&#8594;](#newaccesstoken)
- [&#8592;](#authenticateuser) [Client token flow](#client-token-flow) [&#8594;](#newaccesstoken)

Flows: [token](#token-flows)

Read the requested scope from the HTTP request for an access token.

Standard references:

- http://tools.ietf.org/html/rfc6749#section-3.3
- http://tools.ietf.org/html/rfc6749#section-4.1.1 (code flow)

#### newAccessToken

- [&#8592;](#readscope) [Password token flow](#password-token-flow) [&#8594;](#newrefreshtoken)
- [&#8592;](#readscope) [Client token flow](#client-token-flow) [&#8594;](#saveaccesstoken)
- [&#8592;](#scopefromcode) [Code token flow](#code-token-flow) [&#8594;](#newrefreshtoken)

This is called at the end of a successful access token request via any
grant type (i.e. token flow) and should attach an `accessToken` object
to the `res` middleware object. The default implementation uses the
[generateTokenId](#oauth2generatetokenid) function to create the id
and then uses the `req.oauth2.accessToken` configuration options to fill
in the remaining properties, which should include:

- `id {String}`: The token. See `access_token` in the standard.
- `type {String}`: The token type; usually `'bearer'`. See `token_type`
  in the standard. 
- `expiresIn {Number}`: Number of seconds until access token expires.
  See `expires_in` in the standard.

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.1.4 (code flow)
- http://tools.ietf.org/html/rfc6749#section-4.2.2 (implicit flow)
- http://tools.ietf.org/html/rfc6749#section-4.3.3 (password flow)
- http://tools.ietf.org/html/rfc6749#section-4.4.3 (client flow)

#### setScope



#### loadRefreshToken

Flows: [refresh](#refresh-flow)


### Data structures

The following data structures are used by the OAuth2 default middleware stack.
If you want to change the names of any properties, you'll have to [add some
custom middleware](#configuration) in the appropriate places.

In the samples below, `req` refers to the usual request object found in
Connect and Express middleware.

```js
// OAuth2 sets this only if it does not exist already.
req.began = new Date();

// Options for customizing subsequent default middleware behavior.
req.oauth2 = {
  accessToken: {
    expiresIn: 3600,
    type: 'bearer'
  }
};

// Information on clients that access resources on the user's behalf. This
// object is almost always present throughout and after the various oauth2
// flows.
req.client = {
  id: 'third-party',
  secret: 'bite my shiny metal ---!'
  secret_hash: 'asbsbsbcbdbdsb0f00a0d0v03846'
};

// The resource owner. This shows up when requesting resources or new access
// tokens.
req.user = {
  username: 'banya',
  password: 'ovaltine'
};

// Scope that is required to access the requested resource. Shows up when a
// client requests a protected resource.
req.scope = 'account';

// In general, the access and refresh tokens show up at the beginning of a
// resource request and at the end of new token requests.
req.accessToken = {
  id: '5afef00d',
  expires: new Date(),
  scope: ['account', 'article']
};

req.refreshToken = {
  id: '5afef00d',
  expires: new Date()
};
```

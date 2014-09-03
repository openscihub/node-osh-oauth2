

## Example

```js
var OAuth2 = require('osh-oauth2');

var oa = OAuth2({
  saveAccessToken: function(req, res, next) {

  },
  loadAccessToken: function(req, res, next) {

  }
});
```

## Documentation

- [Configuration](#configuration)
- [Methods](#methods)
  - [token()](#oauth2prototypetoken)
  - [scope()](#oauth2prototypescope)
- [Data structures](#data-structures)


### Configuration

This library is customized by overriding its [middleware
functions](#middleware). New middleware is specified directly on a
configuration object, under the same names as [listed below](#middleware).
Default middleware can be replaced by a function or an array of functions where
each function conforms to the usual Connect/Express middleware signature (make
sure to call `next()`!).  If an array is given, they will be executed in order
wherever the default middleware would have run.

### Methods

OAuth2 instance methods.

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

### Data structures

The following data structures are used by this middleware by default. If
you want to change the names of any properties, you'll have to [add some
custom middleware](#configuration) in the appropriate places.

In the samples below, `req` refers to the usual request object found in
Connect and Express middleware.

```js
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
req.scope = ['account', 'article'];

// In general, the access and refresh tokens show up at the beginning of a
// resource request and at the end of new token requests.
req.accessToken = {
  id: '5afef00d',
  expires: new Date(),
  scope: ['account']
};

req.refreshToken = {
  id: '5afef00d',
  expires: new Date()
};
```

### Middleware

The following is the collection of middleware expected by
osh-oauth2. An incarnation of each exists as a static method on the
class returned by this module and acts as the default for that
method on an OAuth2 instance. Emphasized names *require* custom
implementations, usually because they depend on some kind of persistent
storage mechanism.

- [attachErrorHandler](#attacherrorhandler)
- [validateTokenRequest](#validatetokenrequest)
- [readClientCredentials](#readclientcredentials)
- [**loadClient**](#loadclient)
- [authenticateClient](#authenticateclient)
- [readUserCredentials](#readusercredentials)
- [**loadUser**](#loaduser)

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

#### validateTokenRequest

Validate various aspects of a token request. The default implementation
checks that the request type is `application/x-www-form-urlencoded`, and
that the `grant_type` parameter is present in the request body.

Standard references:

- http://tools.ietf.org/html/rfc6749#section-3.2

#### readClientCredentials

- **Flows**
  - [token](#token-flows)

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

- **Flows**
  - [token](#token-flows)

Load client information from persistent storage and add it to the `req.client`
object. The default implementation throws an Error.

#### authenticateClient

- **Flows**
  - [token](#token-flows)

Given client credentials [read from the request](#readclientcredentials)
and properties [loaded from persistent storage](#loadclient), authenticate the
client. That is, check that the secret given in the request matches the (hashed!)
secret stored by the backend.

The default authenticateClient middleware assumes the following two properties
on the `req.client` object:

- `secret {String}`: See [readClientCredentials](#readclientcredentials).
- `secret_hash {String}`: This is a hash that is assumed to have been produced
  by passing `req.client.secret` through
  [bcrypt.hash](https://github.com/ncb000gt/node.bcrypt.js).

#### readUserCredentials

- **Flows**
  - [token/password](#password-flow)

Read the resource owner (i.e. user) credentials from the request body and
set them on a new `req.user` object as:

- `username {String}`: See [the standard](http://tools.ietf.org/html/rfc6749#section-4.3.2).
- `password {String}`: See [the standard](http://tools.ietf.org/html/rfc6749#section-4.3.2).

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.3.2

#### loadUser

- **Flows**
  - [token/password](#password-flow)

Load user (resource owner) information from persistent storage and add it to
the `req.user` object. The default implementation throws an Error.

#### authenticateUser

- **Flows**
  - [token/password](#password-flow)

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

- **Flows**
  - [token](#token-flows)

Read the requested scope from the HTTP request.

#### loadRefreshToken

- **Flows**
  - [token/refresh](#refresh-flow)

### Flows

The various ways to request an access token from an OAuth2 authorization server
are referred to as "flows" in [the
standard](http://tools.ietf.org/html/rfc6749#section-1.3)). In the context of
this library, "flow" means any ordered set of calls to recognized middleware
(or named steps); for example, this includes the "flow" involved in authorizing
a client access to a resource.

#### Token flows

These are the flows for requesting an access token.

All of the following flows are preceded by these steps (which are
therefore omitted from the individual token flow lists):

- [attachErrorHandler](#attacherrorhandler)
- [validateTokenRequest](#validatetokenrequest)

##### Password flow

Support for the [password authorization grant
type](http://tools.ietf.org/html/rfc6749#section-4.3) is provided when
`'password'` is passed to [token()](#oauth2prototypetoken).

- [readClientCredentials](#readclientcredentials)
- [**loadClient**](#loadclient)
- [authenticateClient](#authenticateclient)
- [readUserCredentials](#readusercredentials)
- [**loadUser**](#loaduser)

##### Refresh flow

#### Resource flow

This is the set of middleware executed when a request is made to an endpoint
protected by [scope()](#oauth2prototypescope) middleware.
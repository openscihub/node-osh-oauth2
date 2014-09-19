# OAuth2

A collection of Connect/Express middleware functions and orderings that help
you implement an OAuth2 server in Node.js. The middleware is concealed by a
high-level, yet detailed, model abstraction described in
[Configuration](#configuration). This library is very inspired by
[node-oauth2-server](https://github.com/thomseddon/node-oauth2-server).

- [Installation](#installation)
- [Example](#example)
- [Usage](#usage)
- [Configuration](#configuration)
- [Access token flow](#access-token-flow)
- [Authorization code flow](#authorization-code-flow)
- [License](#license)

## Installation

```
npm install osh-oauth2
```

## Example

The simplest flow is probably a token request using the
`client_credentials` grant type, so this example handles only that case.

```js
IMPORT example/simple.js
```

The above code is from `example/simple.js`.

## Usage

Usage of this library is very similar to
[node-oauth2-server](https://github.com/thomseddon/node-oauth2-server) except
for the authorization code endpoint (see [discussion](#authorization-code-flow)
for details).

The following methods are available on:

```js
var oauth2 = OAuth2({ /* ... */ });
```

### oauth2.token()

This method produces a middleware function that acts as the access token
endpoint (see http://tools.ietf.org/html/rfc6749#section-3.2). It should be
mounted under an express `post()` route.

Example:

```js
app.post('/token', oauth2.token());
```

### oauth2.authorize()

This produces middleware for OAuth2's custom authorization code endpoint.
This middleware is only a part of the full authorization process (as detailed
in [authorization code flow](#authorization-code-flow)).

Example usage:

```js
app.use('/authorize', oauth2.authorize());
```

It handles both `GET` and `POST` requests, and therefore should be mounted
using the express `use()` method. All requests to this endpoint should
conform to the standard (http://tools.ietf.org/html/rfc6749#section-4.1.1)

This middleware looks for an access token in the request (and, in fact,
*requires* one for `POST` requests). The access token must contain
[authorization scope](#accesstokenauthorizationscope) to have any effect.

#### GET oauth2.authorize()

`GET` requests will return a 200 ok response only if the query string is
well-formed and the provided `client_id` is validated against the provided
`redirect_uri`. If an access token with authorization scope is provided to this
endpoint, the (non-confidential) user information (obtained from
[User.load()](#userload)) will be returned in the response body
like:

```
{
  "user": { ...custom user properties here... }
}
```

If the access token is missing or does not possess authorization scope,
the following is returned:

```
{
  "user": null
}
```

#### POST oauth2.authorize()

The following request body parameters are expected

- `authorized_scope`: This is a space-separated string of scopes. It should
  be a subset of the scope requested in the query string (parts of the
  authorized scope not mentioned in the requested scope will be ignored).

This endpoint also requires an access token with authorization scope. This
satisfies the user authentication requirement vaguely mentioned by the
standard, and does so using the OAuth2 server itself. Autogenous for real!

On success, a 200 ok response is returned, with the authorization code
placed inside a JSON response body. The response parameters are:

- `code`: see http://tools.ietf.org/html/rfc6749#section-4.1.2
- `state`: see http://tools.ietf.org/html/rfc6749#section-4.1.2
- `redirect`: *If present*, this is the url to which the receiver of this
  response should redirect the user.

On error, a 400 status is returned with the following JSON body:

- `error`: see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
- `error_description`: see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
- `error_uri`: see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
- `state`: see http://tools.ietf.org/html/rfc6749#section-4.1.2
- `redirect`: *If present*, this is the url to which the receiver of this
  response should redirect the user.

### oauth2.allow(scope)

Protect user resources with this middleware. Only requests carrying an access
token with the specified scope will get through.

```js
app.get(
  '/secret',
  oauth2.allow('secrets'),
  function(req, res) {
    // User and client objects are loaded by oauth2.
    var user = req.oauth2.user;
    var client = req.oauth2.client;
  }
);
```

### oauth2.load()

Use this middleware if you want to load client and user from an access
token only if it exists. This is useful when data from a single
endpoint depends on the level of access.

```js
app.get(
  '/secret',
  oauth2.load(),
  function(req, res) {
    var user = req.oauth2.user;
    if (user) {
      // Return user-specific stuff.
    }
    else {
      // Return generic public data.
    }

    // Or check the scope manually:

    var accessToken = req.oauth2.accessToken;
    if (accessToken && OAuth2.hasScope(accessToken.scope, 'secrets'))
      // Return secrets.
    }
    else {
      // Return generic public data.
    }
  }
);
```


## Configuration

OAuth2 is configured by defining various models that manage the storage,
retrieval, and validation of [clients](#client), [users](#user), [access
tokens](#accesstoken), [refresh tokens](#refreshtoken), and [authorization
codes](#authorizationcode).

```js
var oauth2 = OAuth2({
  Client: { /* options */ },
  User: { /* options */ },
  AccessToken: { /* options */ },
  RefreshToken: { /* options */ },
  AuthorizationCode: { /* options */ }
});
```

- [Client](#client)
  - [load](#clientload)
  - [authenticate](#clientauthenticate)
  - [allowGrant](#clientallowgrant)
  - [validateId](#clientvalidateid)
  - [validateRedirectUri](#clientvalidateredirecturi)
- [User](#user)
  - [load](#userload)
- [AccessToken](#accesstoken)
  - [save](#accesstokensave)
  - [load](#accesstokenload)
  - [lifetime](#accesstokenlifetime)
  - [generateId](#accesstokengenerateid)
  - [defaultScope](#accesstokendefaultscope)
  - [revokeScope](#accesstokenrevokescope)
  - [authorizationScope](#accesstokenauthorizationscope)
  - [allowRefresh](#accesstokenallowrefresh)
- [RefreshToken](#refreshtoken)
  - [save](#refreshtokensave)
  - [load](#refreshtokenload)
  - [generateId](#refreshtokengenerateid)
  - [lifetime](#refreshtokenlifetime)
- [AuthorizationCode](#authorizationcode)
  - [save](#authorizationcodesave)
  - [load](#authorizationcodeload)
  - [del](#authorizationcodedel)
  - [generateId](#authorizationcodegenerateid)
  - [lifetime](#authorizationcodelifetime)

### Client

A Client is an entity that requests access tokens so that it can read, write,
and modify user data. For example, a client can be a user requesting its own
data, or a third-party app requesting data on behalf of a user.

The Client model validates, authenticates, and retrieves client instances. It
also provides callbacks for allowing/denying access token and authorization
requests on a per-client basis.

#### Client.load

- signature: `Function(id, callback)`
- required

Load the client identified by the given id string from persistent storage and
pass it as the second argument of the given callback. If the client cannot be
found in the database (and there was no db error), an error *must not* be given
to the callback. In this case, leave both callback arguments undefined (or
falsey).

This function is called often.

#### Client.authenticate

- signature: `Function(secret, client, callback)`
- required

Authenticate a client instance against the provided secret string. The callback
takes an error as first argument and a boolean as the second. Return a falsey
as the second argument if authentication fails. Return an error only if
something goes very wrong with the underlying authentication function.

The secret is parsed from the `Authorization` header in token requests (to
simplify the life of the developer, we take the advice of the standard to heart
and require client credentials be sent this way). A custom implementation may
disregard the provided secret if other authentication measures are in place.

Example:

```js
var bcrypt = require('bcrypt');

Client.authenticate = function(secret, client, callback) {
  bcrypt.compare(secret, client.secret_hash, callback);
};
```

#### Client.allowGrant

- signature: `Array<String>` or `Function(grant, client)<Boolean>`
- optional
- default: `[]`

As an array of strings, indiscriminately allow the grant types listed. As a
function, return truthy or falsey given a grant type string and the client
requesting an access token or authorization code. Truthy allows the grant
type.

The following grant types are defined in the OAuth2 standard:

- `'authorization_code'`
- `'client_credentials'`
- `'password'`

The standard discourages use of the `'password'` grant type.

Example:

```js
Client.allowGrant = function(grant, client) {
  return ['client_credentials', 'authorization_code'].indexOf(grant) >= 0;
};

// Or equivalently:
Client.allowGrant = ['client_credentials', 'authorization_code'];
```

#### Client.validateId

- signature: `Function(id)<Boolean>`
- optional
- default tests for `VSCHAR` string

Validate a client id sent in a request.  In conformance with [the
standard](http://tools.ietf.org/html/rfc6749#appendix-A), the default
implementation checks that the id is a nonzero-length array of `VSCHAR`s, where
`VSCHAR` is defined by the unicode range [`U+0020 -
U+007E`](http://unicode-table.com/en/#basic-latin).

#### Client.validateRedirectUri

- signature: `Function(uri, client)<Boolean>`
- required

Validate a redirect uri string given in a request against the client making
the request. Validate successfully by returning truthy.

Example

```js
Client.validateRedirectUri = function(uri, client) {
  return client.redirect_uris.indexOf(uri) >= 0;
};
```


### User

A User is a [Client](#client) that is also a resource owner. Therefore, **for
every user, there must exist a client with the same identifier**.

An important consequence of this design decision is that the authorization
server never authenticates a User, only Clients. This is why the User model
does not require an `authenticate()` method. Furthermore, authentication
secrets should never be stored in the User model (they should be stored in the
Client model); this design creates a nice separation between
authentication-based (e.g. password hash) and regular (e.g. name) User
properties.

Another consequence is that a User instance must be identified by a valid
`client_id`. [The OAuth2
standard](http://tools.ietf.org/html/rfc6749#appendix-A) says a `client_id`
should be an array of `VSCHAR`s, where `VSCHAR` is defined by the unicode range
[`U+0020 - U+007E`](http://unicode-table.com/en/#basic-latin).  Fortunately,
this range is quite generous when it comes to selecting usernames, and you will
probably want to restrict the range further using `Client.validateId`.

The User model API is extremely simple. It has two purposes:

- Test that a client is also a user.
- Provide user-specific properties (like a real name).

Both functions are achieved through a single method `User.load`.


#### User.load

- signature: `Function(id, callback)`
- required

Load the user identified by the given id string from persistent storage and
pass it as the second argument of the given callback. If the user cannot be
found in the database (and there was no db error), an error *must not* be given
to the callback. In this case, leave both callback arguments undefined (or
falsey).

**NOTE**: User model data is returned by the `oauth2.authorize()` methods!
Never store secret information (like password hashes) on the User model (or at
least never return secret data from `User.load`). See the [discussion
above](#user).


### AccessToken

The AccessToken model is responsible for setting the default scope, revoking
scope on a per-client/user basis.

#### AccessToken.save

- signature: `Function(accessToken, callback)`
- required

The `accessToken` object provided to this function is preloaded with the
following properties

- `id {String}`: The access token id.
- `user_id {String}`: The resource owner user id.
- `client_id {String}`: The client receiving the access token.
- `lifetime {Number}`: Lifetime of the access token in seconds.
- `expires {Date}`: The date at which the access token expires.
- `scope {String}`: Space-separated string of scopes.
- `type {String}`: The token type.

The object actually saved to disk by this method is arbitrary,
as long as the above properties are reproduced by
[AccessToken.load](#accesstokenload); however, you should treat the
given `accessToken` object as immutable.

#### AccessToken.load

- signature: `Function(id, callback)`
- required

Load the access token identified by the given id string from persistent storage and
pass it as the second argument of the given callback. If the access token cannot be
found in the database (and there was no db error), an error *must not* be given
to the callback. In this case, leave both callback arguments undefined (or
falsey).

The following properties are *required* on the returned access token object

- `user_id {String}`: The resource owner user id.
- `client_id {String}`: The client receiving the access token.
- `lifetime {Number}`: Lifetime of the access token in seconds.
- `expires {Date}`: The date at which the access token expires.
- `scope {String}`: Space-separated string of scopes.
- `type {String}`: The token type.


#### AccessToken.lifetime

- signature: `Number` or `Function(scope, client, user)<Number>`
- required
- parameters:
  - `scope {String}`: the scope requested by `client`
  - `client {Object}`: the client requesting `scope`
  - `user {Object}`: the resource owner

If a function, it should return a number. The `OAuth2.hasScope()` function
is provided for convenience inside this method.

Example:

```js
AccessToken.lifetime = 3600;
AccessToken.lifetime = function(scope, client, user) {
  return (
    OAuth2.hasScope(scope, 'secrets') ?
    90 : 3600
  );
};
```

#### AccessToken.generateId

- signature: `Function(callback)`
- parameters:
  - `callback {Function(err, id)}` where `id` is a string
- optional
- default generates a random hex string

Provide the generated id string to the callback as second argument.

Example:

```js
AccessToken.generateId = function(callback) {
  crypto.randomBytes(32, function(err, buf) {
    callback(null, buf.toString('hex'));
  });
};
```

#### AccessToken.defaultScope

- signature: `String` or `Function(client, user, callback)`
- required

If a function, provide the default scope as second argument to the
callback.

#### AccessToken.revokeScope

- signature: `Function(scope, client, user, callback)` or falsey
- required
- parameters:
  - `scope {String}`: the scope requested by `client`
  - `client {Object}`: the client requesting `scope`
  - `user {Object}`: the resource owner
  - `callback {Function(err, acceptedScope)}`

Revoke a subset of the scope requested by the given client. The requested scope
applies to the given user's resources. This is called whenever scope is
requested by a client, which can occur in an authorization request or a
direct token request (e.g. `'client_credentials'` grant).

When the client id is the same as the user id, a '`client_credentials`' access
token is being requested.

The `OAuth2.removeScope()` function is provided for convenient use within
this method.

Example:

```js
AccessToken.revokeScope = function(scope, client, user, callback) {
  scope = OAuth2.removeScope('secrets account', scope);
  callback(null, scope);
};
```

#### AccessToken.authorizationScope

- signature: `String`
- default: `'authorization'`

This is a special scope automatically managed by this library. An authorization
code will be granted only if the user-agent making the request provides an
access token with authorization scope. Authorization scope is never given out
through the authorization code flow; it is only attached to access tokens
obtained by other grant types, like `'client_credentials'`.

See [authorization code flow discussion](#authorization-code-flow)

#### AccessToken.allowRefresh

- signature: `Boolean` or `Function(accessToken, client, user)<Boolean>`
- required
- parameters:
  - `accessToken {Object}`: The newly created access token.
  - `client {Object}`: The client receiving the access token.
  - `user {Object}`: The resource owner.

Allow a refresh token to be issued with this access token. At this point,
the given access token has been approved and will be sent to the client
barring some catastrophic error.

### RefreshToken

#### RefreshToken.save

- signature: `Function(refreshToken, callback)`
- required

The `refreshToken` object provided to this function is preloaded with the
following properties

- `id {String}`: The refresh token id.
- `user_id {String}`: The resource owner user id.
- `client_id {String}`: The client receiving the access and refresh tokens.
- `lifetime {Number}`: Lifetime of the refresh token in seconds.
- `expires {Date}`: The date at which the refresh token expires.
- `scope {String}`: Space-separated string of scopes.
- `type {String}`: The access token type.

The object actually saved to disk by this method is arbitrary,
as long as the above properties are reproduced by
[RefreshToken.load](#refreshtokenload); however, you should treat the
given `refreshToken` object as immutable.

#### RefreshToken.load

- signature: `Function(id, callback)`
- required

Load the refresh token identified by the given id string from persistent storage and
pass it as the second argument of the given callback. If the refresh token cannot be
found in the database (and there was no db error), an error *must not* be given
to the callback. In this case, leave both callback arguments undefined (or
falsey).

The following properties are *required* on the returned refresh token object

- `user_id {String}`: The resource owner user id.
- `client_id {String}`: The client receiving the access and refresh tokens.
- `lifetime {Number}`: Lifetime of the refresh token in seconds.
- `expires {Date}`: The date at which the refresh token expires.
- `scope {String}`: Space-separated string of scopes.
- `type {String}`: The access token type.

#### RefreshToken.generateId

- signature: `Function(callback)`
- parameters:
  - `callback {Function(err, id)}` where `id` is a string
- optional
- default generates a random hex string

Provide the generated id string to the callback as second argument.

Example:

```js
RefreshToken.generateId = function(callback) {
  crypto.randomBytes(32, function(err, buf) {
    callback(null, buf.toString('hex'));
  });
};
```

#### RefreshToken.lifetime

- signature: `Number` or `Function(accessToken, client, user)<Number>`
- required
- parameters:
  - `accessToken {Object}`: The newly created access token.
  - `client {Object}`: the client requesting `scope`
  - `user {Object}`: the resource owner

If a function, it should return a number. The `OAuth2.hasScope()` function
is provided for convenience inside this method.

Example:

```js
RefreshToken.lifetime = 36000;
RefreshToken.lifetime = function(accessToken, client, user) {
  return (
    OAuth2.hasScope(accessToken.scope, 'secrets') ?
    900 : 36000
  );
};
```

### AuthorizationCode

#### AuthorizationCode.save

- signature: `Function(code, callback)`
- required

The `code` object provided to this function is preloaded with the
following properties

- `id {String}`: The authorization code id.
- `user_id {String}`: The resource owner user id.
- `client_id {String}`: The client receiving the authorization code.
- `lifetime {Number}`: Lifetime of the code in seconds.
- `expires {Date}`: The date at which the code expires.
- `scope {String}`: Space-separated string of scopes authorized by the code.
- `redirect_uri {String}`: The redirect uri supplied by the client in the
  authorization code request query string.

The object actually saved to disk by this method is arbitrary,
as long as the above properties are reproduced by
[AuthorizationCode.load](#authorizationcodeload); however, you should treat the
given `code` object as immutable.

#### AuthorizationCode.load

- signature: `Function(id, callback)`
- required

Load the authorization code identified by the given id string from
persistent storage and
pass it as the second argument of the given callback. If the code cannot be
found in the database (and there was no db error), an error *must not* be given
to the callback. In this case, leave both callback arguments undefined (or
falsey).

The following properties are *required* on the returned code object

- `user_id {String}`: The resource owner user id.
- `client_id {String}`: The client receiving the authorization code.
- `lifetime {Number}`: Lifetime of the code in seconds.
- `expires {Date}`: The date at which the code expires.
- `scope {String}`: Space-separated string of scopes authorized by the code.
- `redirect_uri {String}`: The redirect uri supplied by the client in the
  authorization code request query string.

#### AuthorizationCode.del

- signature: `Function(id, callback)`
- required

Delete the authorization code identified by `id` from persistent storage.
Actually, the only requirement after the library calls this method is that
the identified code *not* be returned from subsequent calls to
[AuthorizationCode.load](#authorizationcodeload) with the same id.

#### AuthorizationCode.generateId

- signature: `Function(callback)`
- parameters:
  - `callback {Function(err, id)}` where `id` is a string
- optional
- default generates a random hex string

Provide the generated id string to the callback as second argument.

Example:

```js
AuthorizationCode.generateId = function(callback) {
  crypto.randomBytes(32, function(err, buf) {
    callback(null, buf.toString('hex'));
  });
};
```

#### AuthorizationCode.lifetime

- signature: `Number` or `Function(accessToken, client, user)<Number>`
- required
- parameters:
  - `accessToken {Object}`: The newly created access token.
  - `client {Object}`: the client requesting `scope`
  - `user {Object}`: the resource owner

If a function, it should return a number. The `OAuth2.hasScope()` function
is provided for convenience inside this method.

Example:

```js
AuthorizationCode.lifetime = 60;
AuthorizationCode.lifetime = function(accessToken, client, user) {
  return (
    OAuth2.hasScope(accessToken.scope, 'secrets') ?
    10 : 60
  );
};
```

## Access token flow

This library allows client authentication of two types in requests to the token
endpoint.

1. Basic HTTP authentication
2. Access token authentication

The first is covered by the standard
(http://tools.ietf.org/html/rfc6749#section-2.3.1). With the second option,
user-clients (clients that are requesting their own resources) can upgrade
their access token scope without re-entering their password information.

The second option requires an access token with [authorization
scope](#accesstokenauthorizationscope) in the request.  As mentioned above,
such an access token is only available to user-clients authenticating with
username/password.


## Authorization code flow

The OAuth2 standard sort of leaves us hanging when it comes to the details
of the resource owner authentication/authorization part of an authorization
code request. And I [quote](http://tools.ietf.org/html/rfc6749#section-4.1.1):

```
...the authorization server authenticates the resource owner and obtains
an authorization decision (by asking the resource owner or by
establishing approval via other means).
```

Additionally, it appears to be written with a static-page web server in mind,
given that the authorization endpoint must return HTTP redirects.

If you are following modern practices in web development, your app probably has
an api server, an html server (or single-page js app server), an Android app,
an iOS app, etc.  When the standard says `...by asking the resource owner...`,
one has to consider a myriad of user-agents. This cries out for a pure-data
interface to the authorization code endpoint...

This library implements an autogenous authorization code protocol that
separates the presentation of resource owner authorization (the actual
user-agent form filled out by the resource owner) from the underlying oauth2
logic. As a result, your oauth2 server can live entirely on your api server,
close to your data.

Resource owner authentication/authorization proceeds roughly as
follows, where the *data-client* is the client requesting an authorization
code, and the *form-client* is the (trusted) client presenting the resource
owner with an authorization form (a data-client can also be a form-client).

1. A data-client sends a user to an authorization form or presents one
   themselves (if they can be trusted with a username/password... unlikely).
2. With the user's credentials, the form-client requests an
   access token with `authorization` scope.
3. The form-client obtains an authorization code with the access token
   and delivers it to the data-client by redirecting the user.

The form-client can hang on to the access token with `authorization` scope to
make future authorizations run smoother (like auto-filling the username and
not prompting for a password).

Any malicious app can pose as a *form-client* (see
[phishing attacks](http://tools.ietf.org/html/rfc6749#section-10.11)); the
developer should educate its users to avoid all but the most trustworthy
clients (which probably means sticking with *your* app's authorization form).

### Narrative example

The following is an example of how a web app might interface with the
API-style authorization endpoints provided by this library.

- A client redirects a user to your authorization form, say `GET /authorize`
  on your *html server*.
- `GET /authorize` looks for the user credentials in the form of a session
  cookie.
- If the cookie is present, the current access token for the user is
  loaded from the session store.
- `GET /authorize` forwards the request (and the access token) to, say,
  `GET /api/authorize` on the *API server*, where OAuth2 is configured.
- `GET /api/authorize` validates the request (checks `redirect_uri`
  against `client_id` and so forth) and sends a JSON response indicating
  success, failure, and where to direct the response (either to the user
  or the initiating client).
- `GET /api/authorize` also checks for an access token; if the token has
  authorization scope, the resource owner for the token is returned in the
  JSON response (this is an indication to the requester that the given
  access token will allow the authorization when POST'd; keep reading).
- `GET /authorize` receives word from `GET /api/authorize` and either redirects
  the user back to the client with an error or sends an authorization form to
  the user (possibly with an error msg telling the user a client is trying
  to bamboozle them).
- The authorization form can take two courses of action: it can send the
  user's decision back to `POST /authorize`, or `POST /api/authorize` via
  an AJAX request.
- If authorization requires user authentication (i.e. the user is
  not logged in), they can do so via AJAX to `POST /api/token` using
  the `client_credentials` grant type. Alternatively, they can
  `POST /authorize` with user credentials in the form, and the html
  server will obtain an authorization access token behind the scenes
  using the `client_credentials` grant type.
- `POST /api/authorize` *requires* an access token with authorization scope.


But wait, a client could work around the `/authorize` endpoint and do
something nasty with user credentials at the `/api/authorize` endpoint.
Not really, because the client can never see the access token held by
the web app (and
cannot obtain one unless they steal the user's credentials).
The access token is held on the html server and possibly in the user's
browser (in local storage, which is only accessible by javascript run
on pages served by the html server).

If a client gets a hold of an access token with authorization scope, it can
bypass explicit user authorization by using only the `POST /api/authorize`
endpoint. A client possessing an access token with authorization scope is
tantamount to the client knowing a user's password.

The client *could* request authorization scope from a user, though, through
`GET /authorize`. Users should be informed that this is a very dangerous
scope to authorize, because it enables the client to allow access to any
other client.

For this reason, OAuth2 (by default) allows authorization scope through only
the `client_credentials` grant type, where the client *is* the resource
owner.

## License

MIT

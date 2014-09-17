# OAuth2

A collection of Connect/Express middleware functions and orderings that help
you implement an OAuth2 server in Node.js. This library was built (amongst the
others) with extensibility in mind, keeping the developer near those middleware
`req` and `res` objects that are oh so familiar and warm.

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

See [authorization code discussion](#authorization-code)

### AuthorizationCode

This model


## Authorization code

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


## Example

The simplest flow is probably a token request using the
`client_credentials` grant type, so this example handles only that case.

```js
var OAuth2 = require('osh-oauth2');
var bcrypt = require('bcrypt');
var supertest = require('supertest');

var oauth2 = OAuth2({
  User: {
    load: function(id, callback) {
      callback(null, {
        name: 'Homer'
      });
    }
  },

  Client: {
    load: function(id, callback) {
      // There is only one client.
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
.expect(200, /access_token/);
```


## Documentation (outdated)

- [Configuration](#configuration)
- [Methods](#methods)
  - [generateToken()](oauth2generatetoken)
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

#### OAuth2.generateToken

This is used by the default implementations of [newAccessToken](#newaccesstoken)
and [newRefreshToken](#newrefreshtoken).

Signature

```
Function(Function(Error err, String id)<> callback)<>
```

Uses the [crypto](http://nodejs.org/api/crypto.html) library to SHA1 hash
256 random bytes into a hexadecimal string.

#### OAuth2.validateSecret

This is set to
[`bcrypt.compare`](https://github.com/ncb000gt/node.bcrypt.js#async-recommended)
which has the signature,

```
Function(String secret, String hash, Function callback)
```


#### OAuth2.hashSecret

Used in the signup/join and register client flows.

This is set to
[`bcrypt.hash`](https://github.com/ncb000gt/node.bcrypt.js#async-recommended),
with the signature,

```
Function(String secret, Integer|String salt, Function callback)
```

Usage of this function by default middleware sets the salt with an Integer,
which indicates the number of rounds bcrypt should use to auto-generate a
salt. This integer can be changed on the OAuth2 options object, under
`opts.bcryptRounds`.


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

#### FLOWS.AUTH

These are flows behind the authorization endpoint.

The authorization process requires:

- A GET authorization endpoint. This returns a form that the resource owner
  completes to deny/allow access to the requesting client.
- A POST decision endpoint. The authorization form contents are sent here
  after the resource owner denies/allows access to a client.

- [validateAuthRequest](#validateauthrequest)
- [branchAuthRequest](#branchauthrequest)

##### FLOWS.CODE_AUTH

{FLOWS.CODE_AUTH}

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.1

##### FLOWS.DECISION

##### FLOWS.IMPLICIT

#### FLOWS.TOKEN

These are the flows for requesting an access token.

All of the following flows are preceded by these steps (which are
therefore omitted from the individual token flow lists):

1. [setOptions](#setoptions)
2. [attachErrorHandler](#attacherrorhandler)
3. [validateTokenRequest](#validatetokenrequest)

##### FLOWS.CLIENT_TOKEN

{FLOWS.CLIENT_TOKEN}

Standard references:

- oauth2#4.4

##### FLOWS.CODE_TOKEN

{FLOWS.CODE_TOKEN}

Standard references:

- oauth2#4.1.3

##### FLOWS.PASSWORD_TOKEN


Support for the [password authorization grant
type](http://tools.ietf.org/html/rfc6749#section-4.3) is enabled when
`'password'` is passed to [token()](#oauth2prototypetoken).

{FLOWS.PASSWORD_TOKEN}

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

- oauth2#4.1.1
- oauth2#4.2.1


#### branchAuthRequest

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

Switches to one of the following flows depending on the `req.grant_type`
found in [validateTokenRequest](#validatetokenrequest):

- FLOWS.PASSWORD_TOKEN
- FLOWS.CLIENT_TOKEN
- FLOWS.CODE_TOKEN

#### loadAuthorizationCode

Given `req.code` sent in the authorization code token request, load the
following from persistent storage:

- `req.scope`: The scope that was requested from the authorization endpoint.
- `req.expires`: The expiration date of the authorization code.

#### readClientCredentials

The result of this middleware should be the following properties attached
to the request object.

- `req.client_id`:
- `req.client_secret`:

The default implementation uses the
[basic-auth](https://github.com/jshttp/node-basic-auth) module to get this
information from the Authorization header. The standard says you can get it
from the request body, but with discouragement. Therefore, the default
implementation ignores client creds in the body.

Standard references:

- http://tools.ietf.org/html/rfc6749#section-2
- http://tools.ietf.org/html/rfc6749#section-3.2.1

#### loadClient

Load client information from persistent storage and set it as the `req.client`
object. The default implementation throws an Error.

#### authenticateClient

Given client credentials from [readClientCredentials](#readclientcredentials)
and client properties from [loadClient](#loadclient), authenticate the
client. That is, check that the secret given in the request matches the (hashed!)
secret stored by the backend.

The default authenticateClient middleware assumes the following two properties
on the `req.client` object:

- `secret {String}`: See [readClientCredentials](#readclientcredentials).
- `secret_hash {String}`: This is a hash that is assumed to have been produced
  by passing `req.client_secret` through
  [bcrypt.hash](https://github.com/ncb000gt/node.bcrypt.js).

#### readUserCredentials

Read the resource owner (i.e. user) credentials from the request body and
set them on the request object as:

- `req.username {String}`: See [the standard](oauth2#4.3.2).
- `req.password {String}`: See [the standard](oauth2#4.3.2).

Standard references:

- http://tools.ietf.org/html/rfc6749#section-4.3.2

#### loadUser

Flows: [password](#password-flow)

Load user (resource owner) information from persistent storage and add it to
the `req.user` object. The default implementation throws an Error.

#### authenticateUser

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

Flows: [token](#token-flows)

Read the requested scope from the HTTP request for an access token.

Standard references:

- http://tools.ietf.org/html/rfc6749#section-3.3
- http://tools.ietf.org/html/rfc6749#section-4.1.1 (code flow)

#### newAccessToken

This is called at the end of a successful access token request via any grant
type (i.e. token flow) and should attach a `token` object to `res` (the
response object) with the following minimum set of properties:

- `access_token {String}`
- `token_type {String}`
- `expires_in {Integer}`
- `refresh_token {String}`
- `expires {Date}`

The default implementation uses the [generateToken](#oauth2generatetoken)
function to create `access_token` and then uses the `req.oauth2.opts`
configuration options to fill in the remaining properties.

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

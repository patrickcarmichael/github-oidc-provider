const express = require('express');
const session = require('express-session');
const cors = require('cors');
const crypto = require('crypto');
const { generateKeyPair, exportJWK, SignJWT, importJWK } = require('jose');
const axios = require('axios');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const ISSUER = process.env.ISSUER || BASE_URL;

// In-memory stores (use Redis/database in production)
const authorizationCodes = new Map();
const accessTokens = new Map();
let keyPair = null;
let publicJwk = null;

// Initialize RSA key pair for signing tokens
async function initializeKeys() {
    keyPair = await generateKeyPair('RS256');
    publicJwk = await exportJWK(keyPair.publicKey);
    publicJwk.kid = crypto.randomUUID();
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';
    console.log('RSA key pair initialized');
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// OIDC Discovery Endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
    res.json({
          issuer: ISSUER,
          authorization_endpoint: `${BASE_URL}/authorize`,
          token_endpoint: `${BASE_URL}/token`,
          userinfo_endpoint: `${BASE_URL}/userinfo`,
          jwks_uri: `${BASE_URL}/.well-known/jwks.json`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          scopes_supported: ['openid', 'profile', 'email', 'groups'],
          token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
          claims_supported: [
                  'iss', 'sub', 'aud', 'exp', 'iat', 'name', 
                  'preferred_username', 'email', 'email_verified', 
                  'picture', 'groups'
                ]
    });
});

// JWKS Endpoint
app.get('/.well-known/jwks.json', (req, res) => {
    res.json({
          keys: [publicJwk]
    });
});

// Authorization Endpoint
app.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state, nonce } = req.query;

          if (response_type !== 'code') {
                return res.status(400).json({ error: 'unsupported_response_type' });
          }

          // Store authorization request in session
          req.session.authRequest = {
                client_id,
                redirect_uri,
                scope: scope || 'openid',
                state,
                nonce
          };

          // Redirect to GitHub OAuth
          const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
    githubAuthUrl.searchParams.set('client_id', process.env.GITHUB_CLIENT_ID);
    githubAuthUrl.searchParams.set('redirect_uri', `${BASE_URL}/callback`);
    githubAuthUrl.searchParams.set('scope', 'read:user user:email read:org');
    githubAuthUrl.searchParams.set('state', crypto.randomBytes(16).toString('hex'));

          res.redirect(githubAuthUrl.toString());
});

// GitHub OAuth Callback
app.get('/callback', async (req, res) => {
    const { code, error } = req.query;
    const authRequest = req.session.authRequest;

          if (error || !authRequest) {
                return res.status(400).json({ error: error || 'invalid_request' });
          }

          try {
                // Exchange code for GitHub access token
      const tokenResponse = await axios.post(
              'https://github.com/login/oauth/access_token',
        {
                  client_id: process.env.GITHUB_CLIENT_ID,
                  client_secret: process.env.GITHUB_CLIENT_SECRET,
                  code,
                  redirect_uri: `${BASE_URL}/callback`
        },
        { headers: { Accept: 'application/json' } }
            );

      const githubToken = tokenResponse.data.access_token;

      // Fetch user info from GitHub
      const [userResponse, emailsResponse, orgsResponse] = await Promise.all([
              axios.get('https://api.github.com/user', {
                        headers: { Authorization: `Bearer ${githubToken}` }
              }),
              axios.get('https://api.github.com/user/emails', {
                        headers: { Authorization: `Bearer ${githubToken}` }
              }),
              axios.get('https://api.github.com/user/orgs', {
                        headers: { Authorization: `Bearer ${githubToken}` }
              })
            ]);

      const user = userResponse.data;
                const primaryEmail = emailsResponse.data.find(e => e.primary) || emailsResponse.data[0];
                const orgs = orgsResponse.data.map(o => o.login);

      // Check organization restrictions
      const allowedOrgs = process.env.ALLOWED_ORGS?.split(',').map(o => o.trim());
                if (allowedOrgs && allowedOrgs.length > 0) {
                        const hasAccess = orgs.some(org => allowedOrgs.includes(org));
                        if (!hasAccess) {
                                  return res.status(403).json({ error: 'access_denied', error_description: 'User is not a member of an allowed organization' });
                        }
                }

      // Generate authorization code
      const authCode = crypto.randomBytes(32).toString('hex');
                authorizationCodes.set(authCode, {
                        user: {
                                  id: user.id,
                                  login: user.login,
                                  name: user.name,
                                  email: primaryEmail?.email,
                                  email_verified: primaryEmail?.verified,
                                  avatar_url: user.avatar_url,
                                  orgs
                        },
                        client_id: authRequest.client_id,
                        redirect_uri: authRequest.redirect_uri,
                        scope: authRequest.scope,
                        nonce: authRequest.nonce,
                        expires: Date.now() + 600000 // 10 minutes
                });

      // Redirect back to client with authorization code
      const redirectUrl = new URL(authRequest.redirect_uri);
                redirectUrl.searchParams.set('code', authCode);
                if (authRequest.state) {
                        redirectUrl.searchParams.set('state', authRequest.state);
                }

      delete req.session.authRequest;
                res.redirect(redirectUrl.toString());

          } catch (err) {
                console.error('GitHub OAuth error:', err.response?.data || err.message);
                res.status(500).json({ error: 'server_error' });
          }
});

// Token Endpoint
app.post('/token', async (req, res) => {
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

           // Support both POST body and Basic auth
           let actualClientId = client_id;
    let actualClientSecret = client_secret;

           const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Basic ')) {
          const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
          const [id, secret] = credentials.split(':');
          actualClientId = actualClientId || id;
          actualClientSecret = actualClientSecret || secret;
    }

           if (grant_type !== 'authorization_code') {
                 return res.status(400).json({ error: 'unsupported_grant_type' });
           }

           const authData = authorizationCodes.get(code);
    if (!authData || authData.expires < Date.now()) {
          authorizationCodes.delete(code);
          return res.status(400).json({ error: 'invalid_grant' });
    }

           if (authData.redirect_uri !== redirect_uri) {
                 return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
           }

           // Delete used authorization code
           authorizationCodes.delete(code);

           const user = authData.user;
    const now = Math.floor(Date.now() / 1000);
    const tokenExpiry = parseInt(process.env.TOKEN_EXPIRY) || 3600;

           // Build groups claim
           const groups = user.orgs.map(org => `org:${org}`);

           // Create ID token
           const idToken = await new SignJWT({
                 name: user.name || user.login,
                 preferred_username: user.login,
                 email: user.email,
                 email_verified: user.email_verified || false,
                 picture: user.avatar_url,
                 groups
           })
      .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid })
      .setIssuer(ISSUER)
      .setSubject(`github|${user.id}`)
      .setAudience(actualClientId || authData.client_id)
      .setIssuedAt(now)
      .setExpirationTime(now + tokenExpiry)
      .setJti(crypto.randomUUID())
      .sign(keyPair.privateKey);

           // Create access token
           const accessToken = crypto.randomBytes(32).toString('hex');
    accessTokens.set(accessToken, {
          user,
          scope: authData.scope,
          expires: Date.now() + (tokenExpiry * 1000)
    });

           if (authData.nonce) {
                 // Add nonce to ID token payload (already set above, but noting here for clarity)
           }

           res.json({
                 access_token: accessToken,
                 token_type: 'Bearer',
                 expires_in: tokenExpiry,
                 id_token: idToken,
                 scope: authData.scope
           });
});

// UserInfo Endpoint
app.get('/userinfo', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'invalid_token' });
    }

          const token = authHeader.slice(7);
    const tokenData = accessTokens.get(token);

          if (!tokenData || tokenData.expires < Date.now()) {
                accessTokens.delete(token);
                return res.status(401).json({ error: 'invalid_token' });
          }

          const user = tokenData.user;
    const scopes = tokenData.scope.split(' ');

          const userinfo = {
                sub: `github|${user.id}`
          };

          if (scopes.includes('profile')) {
                userinfo.name = user.name || user.login;
                userinfo.preferred_username = user.login;
                userinfo.picture = user.avatar_url;
          }

          if (scopes.includes('email')) {
                userinfo.email = user.email;
                userinfo.email_verified = user.email_verified || false;
          }

          if (scopes.includes('groups')) {
                userinfo.groups = user.orgs.map(org => `org:${org}`);
          }

          res.json(userinfo);
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// Start server
initializeKeys().then(() => {
    app.listen(PORT, () => {
          console.log(`GitHub OIDC Provider running on ${BASE_URL}`);
          console.log(`Discovery: ${BASE_URL}/.well-known/openid-configuration`);
    });
});

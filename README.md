# GitHub OIDC Provider

A self-hosted OpenID Connect (OIDC) identity provider that uses GitHub as the authentication backend. This allows you to use your GitHub identity to authenticate with Cloudflare Access, self-hosted services, and any other OIDC-compatible platform.

## Features

- **Full OIDC Compliance**: Implements the OpenID Connect specification with discovery endpoint, JWKS, and token endpoints
- - **GitHub Authentication**: Uses GitHub OAuth/GitHub Apps for secure authentication
  - - **Cloudflare Access Compatible**: Pre-configured to work seamlessly with Cloudflare Zero Trust
    - - **Self-Hosted Ready**: Deploy on your own infrastructure for full control
      - - **Organization/Team Claims**: Include GitHub org membership and team information in tokens
        - - **Configurable Claims**: Customize which user attributes are included in ID tokens
          - - **Docker Support**: Easy deployment with Docker and Docker Compose
           
            - ## Quick Start
           
            - ### Prerequisites
           
            - - Node.js 18+ or Docker
              - - A GitHub OAuth App or GitHub App
                - - A domain with HTTPS (required for OIDC)
                 
                  - ### 1. Create a GitHub OAuth App
                 
                  - 1. Go to GitHub Settings > Developer settings > OAuth Apps > New OAuth App
                    2. 2. Set the Authorization callback URL to: `https://your-domain.com/callback`
                       3. 3. Note your Client ID and generate a Client Secret
                         
                          4. ### 2. Configure Environment Variables
                         
                          5. ```bash
                             cp .env.example .env
                             ```

                             Edit `.env` with your values:

                             ```env
                             # Server Configuration
                             PORT=3000
                             BASE_URL=https://your-domain.com
                             SESSION_SECRET=your-random-session-secret

                             # GitHub OAuth
                             GITHUB_CLIENT_ID=your-client-id
                             GITHUB_CLIENT_SECRET=your-client-secret

                             # OIDC Configuration
                             ISSUER=https://your-domain.com
                             TOKEN_EXPIRY=3600

                             # Optional: Restrict to specific organizations
                             ALLOWED_ORGS=your-org-name
                             ```

                             ### 3. Run the Server

                             #### Using Node.js

                             ```bash
                             npm install
                             npm start
                             ```

                             #### Using Docker

                             ```bash
                             docker-compose up -d
                             ```

                             ## OIDC Endpoints

                             | Endpoint | Description |
                             |----------|-------------|
                             | `/.well-known/openid-configuration` | OIDC Discovery document |
                             | `/.well-known/jwks.json` | JSON Web Key Set |
                             | `/authorize` | Authorization endpoint |
                             | `/token` | Token endpoint |
                             | `/userinfo` | UserInfo endpoint |
                             | `/callback` | GitHub OAuth callback |

                             ## Configuring Cloudflare Access

                             1. Go to Cloudflare Zero Trust Dashboard > Settings > Authentication
                             2. 2. Add a new identity provider, select "OpenID Connect"
                                3. 3. Configure:
                                   4.    - **Name**: GitHub OIDC
                                         -    - **App ID**: `cloudflare-access` (or your configured client ID)
                                              -    - **Client Secret**: Your configured client secret
                                                   -    - **Auth URL**: `https://your-domain.com/authorize`
                                                        -    - **Token URL**: `https://your-domain.com/token`
                                                             -    - **Certificate URL**: `https://your-domain.com/.well-known/jwks.json`
                                                              
                                                                  - 4. Test the connection and save
                                                                   
                                                                    5. ## Configuring Other Services
                                                                   
                                                                    6. ### Generic OIDC Configuration
                                                                   
                                                                    7. For any OIDC-compatible service, use these values:
                                                                   
                                                                    8. - **Issuer/Discovery URL**: `https://your-domain.com`
                                                                       - - **Authorization Endpoint**: `https://your-domain.com/authorize`
                                                                         - - **Token Endpoint**: `https://your-domain.com/token`
                                                                           - - **UserInfo Endpoint**: `https://your-domain.com/userinfo`
                                                                             - - **JWKS URI**: `https://your-domain.com/.well-known/jwks.json`
                                                                              
                                                                               - ### Supported Scopes
                                                                              
                                                                               - - `openid` - Required, returns subject identifier
                                                                                 - - `profile` - Returns name, preferred_username, picture
                                                                                   - - `email` - Returns email and email_verified
                                                                                     - - `groups` - Returns GitHub organization and team memberships
                                                                                      
                                                                                       - ## Token Claims
                                                                                      
                                                                                       - The ID token includes the following claims:
                                                                                      
                                                                                       - ```json
                                                                                         {
                                                                                           "iss": "https://your-domain.com",
                                                                                           "sub": "github|12345678",
                                                                                           "aud": "your-client-id",
                                                                                           "exp": 1234567890,
                                                                                           "iat": 1234567890,
                                                                                           "name": "John Doe",
                                                                                           "preferred_username": "johndoe",
                                                                                           "email": "john@example.com",
                                                                                           "email_verified": true,
                                                                                           "picture": "https://avatars.githubusercontent.com/u/12345678",
                                                                                           "groups": ["org:myorg", "team:myorg/developers"]
                                                                                         }
                                                                                         ```

                                                                                         ## Security Considerations

                                                                                         - Always use HTTPS in production
                                                                                         - - Store secrets securely (use environment variables or secret management)
                                                                                           - - Regularly rotate your signing keys
                                                                                             - - Consider IP allowlisting for the token endpoint
                                                                                               - - Use the `ALLOWED_ORGS` setting to restrict access to specific GitHub organizations
                                                                                                
                                                                                                 - ## Development
                                                                                                
                                                                                                 - ```bash
                                                                                                   # Install dependencies
                                                                                                   npm install

                                                                                                   # Run in development mode
                                                                                                   npm run dev

                                                                                                   # Run tests
                                                                                                   npm test
                                                                                                   ```

                                                                                                   ## License

                                                                                                   MIT License - see [LICENSE](LICENSE) for details

# OAuth Provider Implementation Plan

## Overview

This document outlines the comprehensive implementation plan for adding OAuth provider functionality to GD Central. The system will allow third-party applications to authenticate users and access their GD data through a secure OAuth 2.0 flow.

## System Architecture

```mermaid
graph TB
    subgraph "External Services"
        Discord[Discord OAuth]
        GitHub[GitHub OAuth]
    end
    
    subgraph "GD Central OAuth Provider"
        subgraph "Authentication Layer"
            UserAuth[User Login<br/>Discord OAuth]
            DevAuth[Developer Login<br/>GitHub OAuth]
        end
        
        subgraph "OAuth Provider Core"
            AuthServer[Authorization Server<br/>zitadel/oidc]
            TokenMgmt[Token Management]
            ScopeCtrl[Scope Control]
        end
        
        subgraph "Application Management"
            AppReg[App Registration]
            DevDash[Developer Dashboard]
            Analytics[Analytics Engine]
        end
        
        subgraph "Protected APIs"
            ProfileAPI[Profile API]
            GameDataAPI[Game Data API]
            ActivityAPI[Activity API]
        end
    end
    
    subgraph "Third-Party Apps"
        App1[Third-Party App 1]
        App2[Third-Party App 2]
        App3[Third-Party App N]
    end
    
    Discord --> UserAuth
    GitHub --> DevAuth
    
    UserAuth --> AuthServer
    DevAuth --> AppReg
    
    AuthServer --> TokenMgmt
    TokenMgmt --> ScopeCtrl
    ScopeCtrl --> ProfileAPI
    ScopeCtrl --> GameDataAPI
    ScopeCtrl --> ActivityAPI
    
    AppReg --> DevDash
    DevDash --> Analytics
    
    App1 --> AuthServer
    App2 --> AuthServer
    App3 --> AuthServer
    
    App1 --> ProfileAPI
    App2 --> GameDataAPI
    App3 --> ActivityAPI
```

## OAuth Authorization Code Flow

The following sequence diagram shows the complete OAuth 2.0 Authorization Code Flow with PKCE implementation, demonstrating how third-party applications authenticate users and obtain access tokens.

```mermaid
sequenceDiagram
    participant User as User
    participant App as Third-Party App
    participant Browser as User Browser
    participant AuthServer as GD Central Auth Server
    participant DB as Database (GORM)
    participant API as Protected APIs

    Note over User,API: OAuth 2.0 Authorization Code Flow with PKCE

    %% Step 1: App initiates OAuth flow
    User->>App: Click "Login with GD Central"
    App->>App: Generate PKCE challenge<br/>(code_verifier, code_challenge)
    
    %% Step 2: Redirect to authorization endpoint
    App->>Browser: Redirect to /oauth/authorize<br/>?client_id=xxx&redirect_uri=xxx<br/>&scope=profile:read gamedata:read<br/>&code_challenge=xxx&code_challenge_method=S256<br/>&state=random_state
    
    %% Step 3: User authentication
    Browser->>AuthServer: GET /oauth/authorize
    AuthServer->>DB: Validate client_id and redirect_uri<br/>SELECT * FROM oauth_apps WHERE client_id=?
    DB-->>AuthServer: App details
    
    alt User not authenticated
        AuthServer->>Browser: Redirect to Discord OAuth
        Browser->>User: Discord login prompt
        User->>Browser: Enter Discord credentials
        Browser->>AuthServer: Discord OAuth callback
        AuthServer->>DB: Create/update user session<br/>INSERT/UPDATE users
    end
    
    %% Step 4: Consent screen
    AuthServer->>Browser: Show consent screen<br/>(App name, requested scopes, user info)
    Browser->>User: Display consent form
    User->>Browser: Grant/Deny permissions
    Browser->>AuthServer: POST consent decision
    
    %% Step 5: Generate authorization code
    alt User grants consent
        AuthServer->>DB: Store authorization code<br/>INSERT INTO oauth_authorization_codes<br/>(code, app_id, user_id, scopes, code_challenge)
        DB-->>AuthServer: Code stored
        AuthServer->>DB: Store user authorization<br/>INSERT INTO oauth_user_authorizations<br/>(user_id, app_id, scopes)
        AuthServer->>Browser: Redirect to app<br/>?code=auth_code&state=random_state
    else User denies consent
        AuthServer->>Browser: Redirect to app<br/>?error=access_denied&state=random_state
    end
    
    %% Step 6: Token exchange
    Browser->>App: Authorization callback<br/>(code or error)
    
    alt Authorization granted
        App->>App: Validate state parameter
        App->>AuthServer: POST /oauth/token<br/>grant_type=authorization_code<br/>&code=auth_code&client_id=xxx<br/>&code_verifier=original_verifier<br/>&redirect_uri=xxx
        
        %% Step 7: Validate and exchange code
        AuthServer->>DB: Validate authorization code<br/>SELECT * FROM oauth_authorization_codes<br/>WHERE code=? AND used=false AND expires_at > NOW()
        DB-->>AuthServer: Code details
        AuthServer->>AuthServer: Verify PKCE challenge<br/>SHA256(code_verifier) == code_challenge
        AuthServer->>DB: Mark code as used<br/>UPDATE oauth_authorization_codes SET used=true
        
        %% Step 8: Generate tokens
        AuthServer->>AuthServer: Generate JWT access token<br/>(user_id, app_id, scopes, exp: 1h)
        AuthServer->>AuthServer: Generate refresh token<br/>(random, exp: 30d)
        AuthServer->>DB: Store tokens<br/>INSERT INTO oauth_access_tokens<br/>INSERT INTO oauth_refresh_tokens
        DB-->>AuthServer: Tokens stored
        
        AuthServer-->>App: JSON response<br/>access_token, refresh_token,<br/>token_type, expires_in, scope
        
        %% Step 9: API access
        App->>API: GET /api/v1/profile<br/>Authorization: Bearer access_token
        API->>API: Validate JWT signature & expiration
        API->>DB: Log API usage<br/>INSERT INTO oauth_api_usage
        API->>DB: Fetch user data<br/>SELECT * FROM users WHERE id=?
        DB-->>API: User profile data
        API-->>App: JSON user profile
        App-->>User: Display user data
    end

    Note over User,API: Token refresh flow (when access token expires)
    
    %% Token refresh
    App->>AuthServer: POST /oauth/token<br/>grant_type=refresh_token<br/>&refresh_token=xxx&client_id=xxx
    AuthServer->>DB: Validate refresh token<br/>SELECT * FROM oauth_refresh_tokens<br/>WHERE token=? AND revoked=false AND expires_at > NOW()
    DB-->>AuthServer: Token valid
    AuthServer->>DB: Revoke old tokens<br/>UPDATE oauth_refresh_tokens SET revoked=true<br/>UPDATE oauth_access_tokens SET revoked=true
    AuthServer->>AuthServer: Generate new tokens<br/>(access + refresh)
    AuthServer->>DB: Store new tokens
    AuthServer-->>App: New token pair
```

## Token Management Flow

The following diagram illustrates the complete token lifecycle including generation, validation, refresh, and revocation processes.

```mermaid
flowchart TD
    Start([Token Request]) --> AuthCode{Authorization Code<br/>Exchange?}
    
    %% Authorization Code Flow
    AuthCode -->|Yes| ValidateCode[Validate Authorization Code<br/>- Check expiration<br/>- Verify PKCE challenge<br/>- Confirm not used]
    ValidateCode --> CodeValid{Code Valid?}
    CodeValid -->|No| CodeError[Return Error<br/>invalid_grant]
    CodeValid -->|Yes| GenerateTokens[Generate Token Pair<br/>- JWT Access Token 1h<br/>- Random Refresh Token 30d]
    
    %% Refresh Token Flow
    AuthCode -->|No| RefreshFlow{Refresh Token<br/>Request?}
    RefreshFlow -->|Yes| ValidateRefresh[Validate Refresh Token<br/>- Check expiration<br/>- Verify not revoked<br/>- Confirm client match]
    ValidateRefresh --> RefreshValid{Refresh Valid?}
    RefreshValid -->|No| RefreshError[Return Error<br/>invalid_grant]
    RefreshValid -->|Yes| RevokeOld[Revoke Old Tokens<br/>- Mark refresh token revoked<br/>- Mark access token revoked]
    RevokeOld --> GenerateNew[Generate New Token Pair<br/>- New JWT Access Token<br/>- New Refresh Token]
    
    %% Token Storage
    GenerateTokens --> StoreTokens[(Store in Database<br/>GORM Models:<br/>- oauth_access_tokens<br/>- oauth_refresh_tokens)]
    GenerateNew --> StoreTokens
    StoreTokens --> LogEvent[Log Security Event<br/>- token_issued<br/>- Include user_id, app_id<br/>- Store in security_events]
    LogEvent --> ReturnTokens[Return Token Response<br/>- access_token<br/>- refresh_token<br/>- token_type: Bearer<br/>- expires_in: 3600]
    
    %% Token Usage
    ReturnTokens --> TokenUsage[Token Usage]
    TokenUsage --> APIRequest[API Request with<br/>Bearer Token]
    APIRequest --> ValidateAccess[Validate Access Token<br/>- Verify JWT signature<br/>- Check expiration<br/>- Validate scopes]
    ValidateAccess --> AccessValid{Token Valid?}
    AccessValid -->|No| AccessError[Return 401<br/>Unauthorized]
    AccessValid -->|Yes| LogUsage[Log API Usage<br/>- oauth_api_usage table<br/>- Track endpoint, method<br/>- Response time, status]
    LogUsage --> ProcessRequest[Process API Request<br/>- Apply scope restrictions<br/>- Return requested data]
    
    %% Token Revocation
    RefreshFlow -->|No| RevocationFlow{Token Revocation<br/>Request?}
    RevocationFlow -->|Yes| ValidateRevocation[Validate Revocation Request<br/>- Check client authentication<br/>- Verify token ownership]
    ValidateRevocation --> RevocationValid{Valid Request?}
    RevocationValid -->|No| RevocationError[Return Error<br/>invalid_request]
    RevocationValid -->|Yes| RevokeTokens[Revoke Tokens<br/>- Mark access token revoked<br/>- Mark refresh token revoked<br/>- Update database]
    RevokeTokens --> LogRevocation[Log Security Event<br/>- token_revoked<br/>- Include reason, timestamp]
    LogRevocation --> RevocationSuccess[Return Success<br/>200 OK]
    
    %% Error Handling
    CodeError --> End([End])
    RefreshError --> End
    AccessError --> End
    RevocationError --> End
    RevocationSuccess --> End
    ProcessRequest --> End
    
    %% Cleanup Process
    RevocationFlow -->|No| CleanupFlow[Background Cleanup<br/>- Remove expired tokens<br/>- Archive old usage logs<br/>- Rotate encryption keys]
    CleanupFlow --> End

    %% Styling
    classDef errorClass fill:#ffebee,stroke:#f44336,stroke-width:2px
    classDef successClass fill:#e8f5e8,stroke:#4caf50,stroke-width:2px
    classDef processClass fill:#e3f2fd,stroke:#2196f3,stroke-width:2px
    classDef storageClass fill:#fff3e0,stroke:#ff9800,stroke-width:2px
    
    class CodeError,RefreshError,AccessError,RevocationError errorClass
    class ReturnTokens,RevocationSuccess,ProcessRequest successClass
    class ValidateCode,ValidateRefresh,ValidateAccess,GenerateTokens,GenerateNew processClass
    class StoreTokens,LogEvent,LogUsage,LogRevocation storageClass
```

## Database Schema Design

### GORM Models for OAuth Provider

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "github.com/lib/pq"
)

// OAuthApp represents OAuth applications registered by developers
type OAuthApp struct {
    ID                  uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    DeveloperID         uuid.UUID      `gorm:"type:uuid;not null;index" json:"developer_id"`
    Name                string         `gorm:"size:255;not null" json:"name"`
    Description         string         `gorm:"type:text" json:"description"`
    ClientID            string         `gorm:"size:255;uniqueIndex;not null" json:"client_id"`
    ClientSecret        string         `gorm:"size:255;not null" json:"client_secret"`
    RedirectURIs        pq.StringArray `gorm:"type:text[];not null" json:"redirect_uris"`
    Scopes              pq.StringArray `gorm:"type:text[];not null" json:"scopes"`
    LogoURL             string         `gorm:"size:500" json:"logo_url"`
    WebsiteURL          string         `gorm:"size:500" json:"website_url"`
    PrivacyPolicyURL    string         `gorm:"size:500" json:"privacy_policy_url"`
    TermsOfServiceURL   string         `gorm:"size:500" json:"terms_of_service_url"`
    Active              bool           `gorm:"default:true" json:"active"`
    CreatedAt           time.Time      `json:"created_at"`
    UpdatedAt           time.Time      `json:"updated_at"`
    
    // Relationships
    Developer           Developer                `gorm:"foreignKey:DeveloperID" json:"developer,omitempty"`
    AuthorizationCodes  []OAuthAuthorizationCode `gorm:"foreignKey:AppID" json:"authorization_codes,omitempty"`
    AccessTokens        []OAuthAccessToken       `gorm:"foreignKey:AppID" json:"access_tokens,omitempty"`
    UserAuthorizations  []OAuthUserAuthorization `gorm:"foreignKey:AppID" json:"user_authorizations,omitempty"`
    APIUsage            []OAuthAPIUsage          `gorm:"foreignKey:AppID" json:"api_usage,omitempty"`
    Webhooks            []OAuthWebhook           `gorm:"foreignKey:AppID" json:"webhooks,omitempty"`
}

// OAuthAuthorizationCode represents temporary authorization codes
type OAuthAuthorizationCode struct {
    ID                    uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    Code                  string    `gorm:"size:255;uniqueIndex;not null" json:"code"`
    AppID                 uuid.UUID `gorm:"type:uuid;not null;index" json:"app_id"`
    UserID                uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
    Scopes                pq.StringArray `gorm:"type:text[];not null" json:"scopes"`
    RedirectURI           string    `gorm:"size:500;not null" json:"redirect_uri"`
    CodeChallenge         string    `gorm:"size:255" json:"code_challenge"`
    CodeChallengeMethod   string    `gorm:"size:10" json:"code_challenge_method"`
    ExpiresAt             time.Time `gorm:"not null" json:"expires_at"`
    Used                  bool      `gorm:"default:false" json:"used"`
    CreatedAt             time.Time `json:"created_at"`
    
    // Relationships
    App                   OAuthApp  `gorm:"foreignKey:AppID" json:"app,omitempty"`
    User                  User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// OAuthAccessToken represents OAuth access tokens
type OAuthAccessToken struct {
    ID        uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    Token     string    `gorm:"size:255;uniqueIndex;not null" json:"token"`
    AppID     uuid.UUID `gorm:"type:uuid;not null;index" json:"app_id"`
    UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
    Scopes    pq.StringArray `gorm:"type:text[];not null" json:"scopes"`
    ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
    Revoked   bool      `gorm:"default:false" json:"revoked"`
    CreatedAt time.Time `json:"created_at"`
    
    // Relationships
    App          OAuthApp            `gorm:"foreignKey:AppID" json:"app,omitempty"`
    User         User                `gorm:"foreignKey:UserID" json:"user,omitempty"`
    RefreshToken OAuthRefreshToken   `gorm:"foreignKey:AccessTokenID" json:"refresh_token,omitempty"`
}

// OAuthRefreshToken represents OAuth refresh tokens
type OAuthRefreshToken struct {
    ID            uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    Token         string    `gorm:"size:255;uniqueIndex;not null" json:"token"`
    AccessTokenID uuid.UUID `gorm:"type:uuid;not null;index" json:"access_token_id"`
    ExpiresAt     time.Time `gorm:"not null" json:"expires_at"`
    Revoked       bool      `gorm:"default:false" json:"revoked"`
    CreatedAt     time.Time `json:"created_at"`
    
    // Relationships
    AccessToken   OAuthAccessToken `gorm:"foreignKey:AccessTokenID" json:"access_token,omitempty"`
}

// OAuthUserAuthorization tracks user consent for applications
type OAuthUserAuthorization struct {
    ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    UserID       uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
    AppID        uuid.UUID  `gorm:"type:uuid;not null;index" json:"app_id"`
    Scopes       pq.StringArray `gorm:"type:text[];not null" json:"scopes"`
    AuthorizedAt time.Time  `gorm:"default:CURRENT_TIMESTAMP" json:"authorized_at"`
    RevokedAt    *time.Time `json:"revoked_at"`
    
    // Relationships
    User         User       `gorm:"foreignKey:UserID" json:"user,omitempty"`
    App          OAuthApp   `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

// Ensure unique constraint on user_id and app_id
func (OAuthUserAuthorization) TableName() string {
    return "oauth_user_authorizations"
}

// OAuthAPIUsage tracks API usage for analytics
type OAuthAPIUsage struct {
    ID             uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    AppID          uuid.UUID      `gorm:"type:uuid;not null;index" json:"app_id"`
    UserID         *uuid.UUID     `gorm:"type:uuid;index" json:"user_id"`
    Endpoint       string         `gorm:"size:255;not null" json:"endpoint"`
    Method         string         `gorm:"size:10;not null" json:"method"`
    StatusCode     int            `gorm:"not null" json:"status_code"`
    ResponseTimeMs int            `gorm:"not null" json:"response_time_ms"`
    IPAddress      string         `gorm:"type:inet" json:"ip_address"`
    UserAgent      string         `gorm:"type:text" json:"user_agent"`
    ScopesUsed     pq.StringArray `gorm:"type:text[]" json:"scopes_used"`
    CreatedAt      time.Time      `json:"created_at"`
    
    // Relationships
    App            OAuthApp       `gorm:"foreignKey:AppID" json:"app,omitempty"`
    User           *User          `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// OAuthWebhook represents developer webhooks
type OAuthWebhook struct {
    ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    AppID     uuid.UUID      `gorm:"type:uuid;not null;index" json:"app_id"`
    URL       string         `gorm:"size:500;not null" json:"url"`
    Events    pq.StringArray `gorm:"type:text[];not null" json:"events"`
    Secret    string         `gorm:"size:255;not null" json:"secret"`
    Active    bool           `gorm:"default:true" json:"active"`
    CreatedAt time.Time      `json:"created_at"`
    UpdatedAt time.Time      `json:"updated_at"`
    
    // Relationships
    App       OAuthApp       `gorm:"foreignKey:AppID" json:"app,omitempty"`
}

// Updated Developer model with OAuth fields
type Developer struct {
    ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
    Email          string     `gorm:"size:255;uniqueIndex;not null" json:"email"`
    GitHubID       string     `gorm:"size:255;uniqueIndex" json:"github_id"`
    GitHubUsername string     `gorm:"size:255" json:"github_username"`
    Name           string     `gorm:"size:255" json:"name"`
    AvatarURL      string     `gorm:"size:500" json:"avatar_url"`
    CreatedAt      time.Time  `json:"created_at"`
    UpdatedAt      time.Time  `json:"updated_at"`
    
    // Relationships
    OAuthApps      []OAuthApp `gorm:"foreignKey:DeveloperID" json:"oauth_apps,omitempty"`
}
```

### GORM Migration Functions

```go
package migrations

import (
    "gorm.io/gorm"
    "your-project/internal/models"
)

// MigrateOAuthTables creates all OAuth-related tables
func MigrateOAuthTables(db *gorm.DB) error {
    // Enable UUID extension
    if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
        return err
    }
    
    // Auto-migrate all OAuth models
    err := db.AutoMigrate(
        &models.Developer{},
        &models.OAuthApp{},
        &models.OAuthAuthorizationCode{},
        &models.OAuthAccessToken{},
        &models.OAuthRefreshToken{},
        &models.OAuthUserAuthorization{},
        &models.OAuthAPIUsage{},
        &models.OAuthWebhook{},
    )
    if err != nil {
        return err
    }
    
    // Add unique constraint for user_id and app_id in oauth_user_authorizations
    if err := db.Exec(`
        ALTER TABLE oauth_user_authorizations
        ADD CONSTRAINT unique_user_app
        UNIQUE (user_id, app_id)
    `).Error; err != nil {
        // Ignore error if constraint already exists
    }
    
    return nil
}

// DropOAuthTables removes all OAuth-related tables (for testing)
func DropOAuthTables(db *gorm.DB) error {
    return db.Migrator().DropTable(
        &models.OAuthWebhook{},
        &models.OAuthAPIUsage{},
        &models.OAuthUserAuthorization{},
        &models.OAuthRefreshToken{},
        &models.OAuthAccessToken{},
        &models.OAuthAuthorizationCode{},
        &models.OAuthApp{},
    )
}
```

## OAuth Scopes System

### Scope Definitions

```go
type OAuthScope string

const (
    // Profile scopes
    ScopeProfileRead  OAuthScope = "profile:read"
    ScopeProfileWrite OAuthScope = "profile:write"
    
    // Game data scopes
    ScopeGameDataRead  OAuthScope = "gamedata:read"
    ScopeGameDataWrite OAuthScope = "gamedata:write"
    
    // Activity scopes
    ScopeActivityRead  OAuthScope = "activity:read"
    ScopeActivityWrite OAuthScope = "activity:write"
)

var ScopeDescriptions = map[OAuthScope]string{
    ScopeProfileRead:   "Read your basic profile information (username, Discord tag)",
    ScopeProfileWrite:  "Update your profile information",
    ScopeGameDataRead:  "Read your Geometry Dash data (stats, levels, icons)",
    ScopeGameDataWrite: "Update your Geometry Dash data",
    ScopeActivityRead:  "Read your activity and completions",
    ScopeActivityWrite: "Create new completions and activities",
}
```

## Implementation Phases

### Phase 1: Core OAuth Infrastructure
1. **GORM Models Implementation**
   - Define OAuth GORM models with proper relationships
   - Create migration functions for table creation
   - Set up model validations and hooks

2. **zitadel/oidc Integration**
   - Set up OAuth provider server with GORM backend
   - Implement authorization endpoints using GORM queries
   - Configure token management with GORM operations

3. **Developer Authentication Update**
   - Modify GitHub OAuth to create developer accounts using GORM
   - Update developer model with new OAuth fields
   - Implement GORM-based authentication flow

### Phase 2: Application Management
1. **App Registration System with GORM**
   - Developer dashboard for app creation using GORM models
   - Client ID/secret generation with GORM persistence
   - Redirect URI validation with GORM queries

2. **OAuth Authorization Flow with GORM**
   - Authorization endpoint with consent screen using GORM
   - Token exchange endpoints with GORM token management
   - PKCE support with GORM code challenge storage

### Phase 3: API Protection & Scopes
1. **Scope-based Middleware with GORM**
   - Token validation middleware using GORM token queries
   - Scope checking for endpoints with GORM authorization lookups
   - Rate limiting per app with GORM usage tracking

2. **Protected API Endpoints with GORM**
   - Profile API with scope validation using GORM user queries
   - Game data API with scope validation using GORM data queries
   - Activity API with scope validation using GORM activity queries

### Phase 4: Analytics & Monitoring
1. **Usage Tracking with GORM**
   - Request logging and analytics using GORM API usage models
   - Real-time usage monitoring with GORM aggregation queries
   - Performance metrics collection stored in GORM models

2. **Developer Dashboard with GORM**
   - Comprehensive analytics views using GORM complex queries
   - Export capabilities with GORM batch operations
   - Webhook management using GORM webhook models

### Phase 5: Advanced Features
1. **Security & Compliance**
   - Rate limiting and abuse prevention
   - Security headers and CORS
   - Audit logging

2. **Developer Experience**
   - API documentation
   - SDK generation
   - Testing tools

## Key Technical Decisions

### OAuth Flow Architecture
- **Authorization Code Flow** with PKCE for security
- **Refresh Token Rotation** for enhanced security
- **Scope-based Access Control** for granular permissions

### Token Management
- **JWT Access Tokens** for stateless validation
- **Database-stored Refresh Tokens** for revocation capability
- **Short-lived Access Tokens** (1 hour) with refresh capability

### Analytics Architecture
- **Real-time Usage Tracking** with efficient database design
- **Aggregated Metrics** for dashboard performance
- **Export Capabilities** with background job processing

## Security Considerations

1. **PKCE Implementation** for public clients
2. **Rate Limiting** per app and per user
3. **Scope Validation** on every API request
4. **Token Revocation** capabilities
5. **Audit Logging** for security events
6. **CORS Configuration** for web applications
7. **Webhook Signature Verification** for secure notifications

## API Endpoints Structure

```
OAuth Provider Endpoints:
- GET  /oauth/authorize          # Authorization endpoint
- POST /oauth/token             # Token exchange
- POST /oauth/revoke            # Token revocation
- GET  /oauth/userinfo          # User info endpoint

Developer Management:
- POST /dev/apps                # Create app
- GET  /dev/apps                # List apps
- PUT  /dev/apps/:id            # Update app
- DELETE /dev/apps/:id          # Delete app
- GET  /dev/apps/:id/analytics  # App analytics

Protected APIs:
- GET  /api/v1/profile          # User profile (scope: profile:read)
- GET  /api/v1/gamedata         # Game data (scope: gamedata:read)
- GET  /api/v1/activity         # Activity data (scope: activity:read)
```

## Dependencies to Add

### Go Modules
```go
require (
    // OAuth Provider
    github.com/zitadel/oidc/v3 v3.15.0
    github.com/go-jose/go-jose/v3 v3.0.1
    github.com/golang/mock v1.6.0
    
    // GORM and Database
    gorm.io/gorm v1.25.5
    gorm.io/driver/postgres v1.5.4
    github.com/google/uuid v1.4.0
    github.com/lib/pq v1.10.9  // For PostgreSQL arrays
    
    // Additional features
    github.com/gorilla/websocket v1.5.0  // For real-time dashboard
    github.com/robfig/cron/v3 v3.0.1     // For analytics aggregation
)
```

### Environment Variables
```env
# Database Configuration
DATABASE_URL=postgres://user:password@localhost:5432/gdcentral
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=25
DB_CONN_MAX_LIFETIME=5m

# OAuth Provider Configuration
OAUTH_ISSUER_URL=https://api.gdcentral.com
OAUTH_SIGNING_KEY=your-rsa-private-key
OAUTH_ACCESS_TOKEN_LIFETIME=3600
OAUTH_REFRESH_TOKEN_LIFETIME=2592000

# Analytics Configuration
ANALYTICS_RETENTION_DAYS=365
WEBHOOK_TIMEOUT_SECONDS=30
```

## File Structure

```
backend/
├── internal/
│   ├── models/               # GORM models
│   │   ├── oauth.go         # OAuth-related models
│   │   ├── user.go          # User models
│   │   └── developer.go     # Developer models
│   ├── migrations/          # GORM migrations
│   │   ├── oauth_tables.go  # OAuth table migrations
│   │   └── migrate.go       # Migration runner
│   ├── oauth/
│   │   ├── provider/        # OAuth provider implementation
│   │   │   ├── server.go
│   │   │   ├── handlers.go
│   │   │   └── middleware.go
│   │   ├── apps/            # App management with GORM
│   │   │   ├── service.go   # GORM-based app operations
│   │   │   ├── repository.go # Database layer
│   │   │   └── handlers.go
│   │   ├── tokens/          # Token management with GORM
│   │   │   ├── service.go   # GORM-based token operations
│   │   │   ├── repository.go # Database layer
│   │   │   └── validation.go
│   │   └── scopes/          # Scope management
│   │       ├── definitions.go
│   │       └── middleware.go
│   ├── analytics/           # Usage analytics with GORM
│   │   ├── collector.go     # GORM-based usage tracking
│   │   ├── aggregator.go    # GORM aggregation queries
│   │   ├── repository.go    # Database layer
│   │   └── exporter.go
│   ├── webhooks/            # Webhook system with GORM
│   │   ├── dispatcher.go
│   │   ├── repository.go    # GORM webhook operations
│   │   └── handlers.go
│   └── dashboard/           # Developer dashboard APIs
│       ├── handlers.go
│       ├── repository.go    # GORM dashboard queries
│       └── websocket.go
└── docs/
    └── oauth_api.md
```

## Testing Strategy

1. **Unit Tests** for all OAuth components
2. **Integration Tests** for OAuth flows
3. **Load Testing** for analytics endpoints
4. **Security Testing** for token validation
5. **End-to-End Tests** for complete OAuth flows

## Deployment Considerations

1. **GORM Migrations** must be run before deployment using `MigrateOAuthTables()`
2. **Environment Variables** need to be configured including database connection
3. **SSL Certificates** required for OAuth endpoints
4. **Rate Limiting** configuration per environment with GORM-based tracking
5. **Monitoring** setup for OAuth metrics using GORM analytics models

This comprehensive plan provides a robust foundation for implementing a full-featured OAuth provider that integrates seamlessly with the existing GD Central architecture while providing developers with powerful tools for building applications on top of the platform.
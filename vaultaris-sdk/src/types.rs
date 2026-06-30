//! SDK types for API requests and responses

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================
// PAGINATION
// ============================================

/// Paginated response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

impl<T> Page<T> {
    #[must_use]
    pub fn total_pages(&self) -> i64 {
        if self.per_page == 0 {
            return 0;
        }
        (self.total as f64 / self.per_page as f64).ceil() as i64
    }

    #[must_use]
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages()
    }

    #[must_use]
    pub fn has_prev(&self) -> bool {
        self.page > 1
    }
}

/// Pagination query parameters.
///
/// `page` is 1-based, matching the server's `Pagination` extractor.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub per_page: u32,
}

impl Pagination {
    #[must_use]
    pub fn new(page: u32, per_page: u32) -> Self {
        Self { page, per_page }
    }

    /// First page, 20 items.
    #[must_use]
    pub fn first() -> Self {
        Self::default()
    }
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
        }
    }
}

/// Internal wrapper for `{ success, data }` API responses
#[derive(Debug, Deserialize)]
pub(crate) struct ApiResponse<T> {
    pub data: T,
}

// ============================================
// TOKEN / INTEGRATION
// ============================================

/// Token validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidation {
    /// Whether the token is valid
    pub valid: bool,
    /// User ID if token is valid
    pub user_id: Option<Uuid>,
    /// Tenant ID if token is valid
    pub tenant_id: Option<Uuid>,
    /// Username if token is valid
    pub username: Option<String>,
    /// Email if token is valid
    pub email: Option<String>,
    /// User's roles
    pub roles: Vec<String>,
    /// User's permissions
    pub permissions: Vec<String>,
    /// Token scopes
    pub scopes: Vec<String>,
    /// Token expiration timestamp (Unix)
    pub expires_at: Option<i64>,
    /// Error message if validation failed
    pub error: Option<String>,
}

/// Permission check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheck {
    /// Whether the permission is granted
    pub allowed: bool,
    /// Reason for the decision
    pub reason: Option<String>,
    /// Matched policy if any
    pub matched_policy: Option<String>,
}

/// Batch permission check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPermissionCheck {
    /// Results for each check
    pub results: Vec<PermissionCheckResult>,
}

/// Single permission check result in a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheckResult {
    pub resource: String,
    pub action: String,
    pub allowed: bool,
}

/// Permission to check in a batch request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionToCheck {
    pub resource: String,
    pub action: String,
}

impl PermissionToCheck {
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
        }
    }
}

/// Session validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidation {
    pub valid: bool,
    pub session: Option<SessionInfo>,
    pub user: Option<SessionUserInfo>,
    pub error: Option<String>,
}

/// Session information (from integration endpoint)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub is_active: bool,
    pub mfa_verified: bool,
    pub expires_at: DateTime<Utc>,
}

/// Basic user info from session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

/// Integration user info (lightweight)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub roles: Vec<RoleInfo>,
    pub groups: Vec<GroupInfo>,
    pub permissions: Vec<String>,
    pub metadata: serde_json::Value,
}

/// Role info (brief)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleInfo {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
}

/// Group info (brief)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub id: Uuid,
    pub name: String,
    pub path: String,
}

/// OAuth2 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: String,
}

// ============================================
// TENANTS
// ============================================

/// Tenant entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub settings: serde_json::Value,
    pub access_token_lifetime_seconds: i32,
    pub refresh_token_lifetime_seconds: i32,
    pub id_token_lifetime_seconds: i32,
    pub authorization_code_lifetime_seconds: i32,
    pub password_policy: serde_json::Value,
    pub mfa_enabled: bool,
    pub mfa_required: bool,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new tenant
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateTenantRequest {
    pub name: String,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
}

/// Request to update an existing tenant
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateTenantRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
}

// ============================================
// USERS (management)
// ============================================

/// Full user entity returned from management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub locale: String,
    pub timezone: String,
    pub status: String,
    pub mfa_enabled: bool,
    pub mfa_type: Option<String>,
    pub metadata: serde_json::Value,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a user
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Request to update a user
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

// ============================================
// ROLES
// ============================================

/// Full role entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_system: bool,
    pub is_composite: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a role
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_composite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request to update a role
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_composite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// ============================================
// PERMISSIONS
// ============================================

/// Full permission entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub conditions: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a permission
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub resource: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

/// Request to update a permission
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdatePermissionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

// ============================================
// GROUPS
// ============================================

/// Full group entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub path: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a group
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request to update a group
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateGroupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// ============================================
// OAUTH CLIENTS
// ============================================

/// Full OAuth client entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub logo_url: Option<String>,
    pub is_public: bool,
    pub is_enabled: bool,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub default_scopes: Vec<String>,
    pub require_pkce: bool,
    pub access_token_lifetime_seconds: Option<i32>,
    pub refresh_token_lifetime_seconds: Option<i32>,
    pub require_consent: bool,
    pub homepage_url: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response for client creation that includes the plain-text secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientWithSecret {
    pub client: OAuthClient,
    pub client_secret: String,
}

/// Request to create an OAuth client
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateOAuthClientRequest {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_consent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request to update an OAuth client
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateOAuthClientRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_consent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// ============================================
// SESSIONS (management)
// ============================================

/// Full session entity returned from management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub session_id: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub user_agent: Option<String>,
    pub is_active: bool,
    pub last_activity_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

// ============================================
// ABAC POLICIES
// ============================================

/// ABAC policy entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub resource_pattern: String,
    pub actions: Vec<String>,
    pub conditions: serde_json::Value,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an ABAC policy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateAbacPolicyRequest {
    pub name: String,
    pub effect: String,
    pub resource_pattern: String,
    pub actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Request to update an ABAC policy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateAbacPolicyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvaluatePoliciesRequest {
    pub subject: PolicySubject,
    pub resource: PolicyResource,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<PolicyEnvironment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySubject {
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub groups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyResource {
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyEnvironment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

/// Result of policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub allowed: bool,
    pub effect: String,
    pub matched_policies: Vec<MatchedPolicy>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedPolicy {
    pub policy_id: Uuid,
    pub policy_name: String,
    pub effect: String,
    pub priority: i32,
}

// ============================================
// AUDIT LOGS
// ============================================

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub actor_type: String,
    pub actor_user_agent: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub description: Option<String>,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

// ============================================
// IDENTITY PROVIDERS
// ============================================

/// Identity provider entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub provider_type: String,
    pub status: String,
    pub provider_id: Option<String>,
    pub logo_url: Option<String>,
    pub client_id: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub jwks_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub saml_entity_id: Option<String>,
    pub saml_sso_url: Option<String>,
    pub saml_name_id_format: Option<String>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub auto_create_users: bool,
    pub update_user_on_login: bool,
    pub sync_groups: bool,
    pub default_roles: Option<Vec<String>>,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an identity provider
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateIdentityProviderRequest {
    pub name: String,
    pub provider_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_sso_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_slo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_signing_certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_name_id_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_mapping: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_create_users: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_user_on_login: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_groups: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

// ============================================
// MFA
// ============================================

/// TOTP setup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetupResult {
    pub secret: String,
    pub qr_code_url: String,
    pub backup_codes: Vec<String>,
}

/// TOTP verify result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpVerifyResult {
    pub verified: bool,
    pub backup_codes: Option<Vec<String>>,
}

/// WebAuthn credential stored on the server after a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    /// Base64url-encoded credential ID (opaque handle used by the browser).
    pub credential_id_base64: String,
    /// COSE algorithm: `-7` = ES256, `-257` = RS256.
    pub public_key_algorithm: i32,
    /// Authenticator sign counter — increases on every use.
    pub counter: i32,
    /// Human-readable label set at registration time (e.g. "MacBook Touch ID").
    pub device_name: Option<String>,
    /// `"platform"` (built-in) or `"cross-platform"` (roaming key).
    pub device_type: Option<String>,
    /// Transport hints reported by the authenticator (e.g. `["internal"]`, `["usb", "nfc"]`).
    pub transports: Option<Vec<String>>,
    /// Attestation statement format used during registration (e.g. `"none"`, `"packed"`).
    pub attestation_format: Option<String>,
    pub is_active: bool,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================
// WEBAUTHN — OPTIONS (server → SDK → browser)
// ============================================

/// Relying Party info bundled inside registration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingPartyInfo {
    pub id: String,
    pub name: String,
}

/// User entity bundled inside registration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntityInfo {
    /// Base64url-encoded user ID.
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Public-key credential algorithm parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    /// COSE algorithm identifier: `-7` = ES256, `-257` = RS256.
    pub alg: i32,
}

/// Authenticator selection criteria sent to the browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// `"platform"`, `"cross-platform"`, or absent (no preference).
    pub authenticator_attachment: Option<String>,
    /// `"required"`, `"preferred"`, or `"discouraged"`.
    pub resident_key: String,
    /// `"required"`, `"preferred"`, or `"discouraged"`.
    pub user_verification: String,
}

/// A credential descriptor — identifies an already-registered credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptorInfo {
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Base64url-encoded credential ID.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Options returned by `register/begin` — pass directly to `navigator.credentials.create()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationOptions {
    /// Base64url-encoded random challenge.
    pub challenge: String,
    pub rp: RelyingPartyInfo,
    pub user: UserEntityInfo,
    pub pubkey_cred_params: Vec<PubKeyCredParam>,
    /// Browser timeout in milliseconds.
    pub timeout: u32,
    /// Attestation preference: `"none"`, `"indirect"`, `"direct"`.
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// Credentials to exclude (prevents re-registering the same key).
    pub exclude_credentials: Vec<CredentialDescriptorInfo>,
}

/// Options returned by `authenticate/begin` — pass directly to `navigator.credentials.get()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOptions {
    /// Base64url-encoded random challenge.
    pub challenge: String,
    pub timeout: u32,
    /// Relying Party ID (domain without scheme or port).
    pub rp_id: String,
    /// Credentials the browser may use to fulfill this request.
    pub allow_credentials: Vec<CredentialDescriptorInfo>,
    /// `"required"`, `"preferred"`, or `"discouraged"`.
    pub user_verification: String,
}

// ============================================
// WEBAUTHN — BEGIN RESPONSES
// ============================================

/// Server response to `POST /api/v1/mfa/webauthn/register/begin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationBeginResponse {
    pub challenge_id: Uuid,
    pub options: CreationOptions,
}

/// Server response to `POST /api/v1/mfa/webauthn/authenticate/begin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationBeginResponse {
    pub challenge_id: Uuid,
    pub options: RequestOptions,
}

// ============================================
// WEBAUTHN — BROWSER RESPONSE TYPES (SDK → server)
// ============================================

/// The attestation response produced by the browser after `navigator.credentials.create()`.
///
/// Extract values from the `PublicKeyCredential` the browser hands you and build this struct.
///
/// ```javascript
/// const cred = await navigator.credentials.create({ publicKey: options });
/// // Then pass to SDK:
/// // AttestationResponse {
/// //   id: cred.id,
/// //   client_data_json: bufferToBase64url(cred.response.clientDataJSON),
/// //   attestation_object: bufferToBase64url(cred.response.attestationObject),
/// //   transports: cred.response.getTransports(),
/// //   device_name: "My MacBook",
/// // }
/// ```
#[derive(Debug, Clone)]
pub struct AttestationResponse {
    /// Base64url-encoded credential ID (`credential.id`).
    pub id: String,
    /// Base64url-encoded clientDataJSON.
    pub client_data_json: String,
    /// Base64url-encoded attestationObject (CBOR).
    pub attestation_object: String,
    /// Transport hints from `credential.response.getTransports()`.
    pub transports: Option<Vec<String>>,
    /// Optional human-readable label for this device (stored on the server).
    pub device_name: Option<String>,
}

impl AttestationResponse {
    /// Create an attestation response from browser output.
    pub fn new(
        id: impl Into<String>,
        client_data_json: impl Into<String>,
        attestation_object: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            client_data_json: client_data_json.into(),
            attestation_object: attestation_object.into(),
            transports: None,
            device_name: None,
        }
    }

    /// Set transport hints (from `credential.response.getTransports()`).
    pub fn with_transports(mut self, transports: Vec<String>) -> Self {
        self.transports = Some(transports);
        self
    }

    /// Set a human-readable label for this device (e.g. `"MacBook Touch ID"`).
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = Some(name.into());
        self
    }
}

/// The assertion response produced by the browser after `navigator.credentials.get()`.
///
/// ```javascript
/// const assertion = await navigator.credentials.get({ publicKey: options });
/// // Then pass to SDK:
/// // AssertionResponse {
/// //   id: assertion.id,
/// //   client_data_json: bufferToBase64url(assertion.response.clientDataJSON),
/// //   authenticator_data: bufferToBase64url(assertion.response.authenticatorData),
/// //   signature: bufferToBase64url(assertion.response.signature),
/// //   user_handle: assertion.response.userHandle ? bufferToBase64url(...) : None,
/// // }
/// ```
#[derive(Debug, Clone)]
pub struct AssertionResponse {
    /// Base64url-encoded credential ID (`assertion.id`).
    pub id: String,
    /// Base64url-encoded clientDataJSON.
    pub client_data_json: String,
    /// Base64url-encoded authenticatorData.
    pub authenticator_data: String,
    /// Base64url-encoded DER-encoded signature.
    pub signature: String,
    /// Base64url-encoded userHandle (may be absent for non-resident keys).
    pub user_handle: Option<String>,
}

impl AssertionResponse {
    /// Create an assertion response from browser output.
    pub fn new(
        id: impl Into<String>,
        client_data_json: impl Into<String>,
        authenticator_data: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            client_data_json: client_data_json.into(),
            authenticator_data: authenticator_data.into(),
            signature: signature.into(),
            user_handle: None,
        }
    }

    /// Set the userHandle if the authenticator returned one.
    pub fn with_user_handle(mut self, handle: impl Into<String>) -> Self {
        self.user_handle = Some(handle.into());
        self
    }
}

// ============================================
// PASSWORD RESET / EMAIL
// ============================================

/// Token validation response for password reset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetTokenValidation {
    pub valid: bool,
    pub email: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================
// JWT KEYS
// ============================================

/// JWT signing key info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub algorithm: String,
    pub key_id: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================
// STATISTICS
// ============================================

/// Tenant overview statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantOverview {
    pub tenant_id: Uuid,
    pub total_users: i64,
    pub active_users: i64,
    pub total_roles: i64,
    pub total_groups: i64,
    pub total_clients: i64,
    pub active_sessions: i64,
    pub total_authentications: i64,
    pub failed_authentications: i64,
    pub mfa_enabled_users: i64,
    pub timestamp: DateTime<Utc>,
}

/// Authentication statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationStats {
    pub total_attempts: i64,
    pub successful: i64,
    pub failed: i64,
    pub success_rate: f64,
    pub by_method: Vec<MethodCount>,
    pub time_series: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodCount {
    pub method: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: i64,
    pub label: Option<String>,
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStats {
    pub active_sessions: i64,
    pub sessions_today: i64,
    pub avg_session_duration: i64,
    pub by_device: Vec<DeviceStats>,
    pub by_location: Vec<LocationStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStats {
    pub device_type: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationStats {
    pub country: String,
    pub country_name: String,
    pub count: i64,
}

/// Security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStats {
    pub blocked_attempts: i64,
    pub locked_accounts: i64,
    pub suspicious_activities: i64,
    pub password_resets: i64,
    pub mfa_enrollments: i64,
    pub api_key_usage: i64,
    pub security_events: Vec<TimeSeriesPoint>,
}

/// Dashboard summary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSummary {
    pub overview: TenantOverview,
    pub authentication: AuthSummary,
    pub security_alerts: Vec<SecurityAlert>,
    pub system_health: SystemHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSummary {
    pub today: i64,
    pub change_vs_yesterday: f64,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAlert {
    pub id: Uuid,
    pub severity: String,
    pub alert_type: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemHealth {
    pub status: String,
    pub database: String,
    pub api_latency_ms: i64,
    pub uptime_seconds: i64,
}

// ============================================
// SETUP
// ============================================

/// Setup status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatus {
    pub is_configured: bool,
    pub requires_setup: bool,
    pub admin_exists: bool,
}

/// Request to perform initial setup
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SetupRequest {
    pub admin_username: String,
    pub admin_email: String,
    pub admin_password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_slug: Option<String>,
}

// ============================================
// INTERNAL REQUEST TYPES
// ============================================

#[derive(Debug, Serialize)]
pub(crate) struct ValidateTokenRequest {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CheckPermissionRequest {
    pub user_id: Uuid,
    pub resource: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BatchCheckPermissionRequest {
    pub user_id: Uuid,
    pub checks: Vec<PermissionToCheck>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssignRoleRequest {
    pub role_id: Uuid,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssignGroupRequest {
    pub group_id: Uuid,
}

#[derive(Debug, Serialize)]
pub(crate) struct AssignPermissionRequest {
    pub permission_id: Uuid,
}

#[derive(Debug, Serialize)]
pub(crate) struct TotpVerifyRequest {
    pub code: String,
    pub is_backup_code: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PasswordResetConfirmRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct EmailVerificationRequest {
    pub token: String,
}

// ============================================
// STATISTICS QUERY
// ============================================

/// Time range + bucketing for statistics endpoints.
#[derive(Debug, Clone, Serialize, Default)]
pub struct StatsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    /// `"hour"`, `"day"`, `"week"`, `"month"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
}

impl StatsQuery {
    #[must_use]
    pub fn last_24h() -> Self {
        Self {
            from: Some(Utc::now() - chrono::Duration::hours(24)),
            to: Some(Utc::now()),
            interval: Some("hour".to_string()),
        }
    }

    #[must_use]
    pub fn last_7d() -> Self {
        Self {
            from: Some(Utc::now() - chrono::Duration::days(7)),
            to: Some(Utc::now()),
            interval: Some("day".to_string()),
        }
    }

    #[must_use]
    pub fn last_30d() -> Self {
        Self {
            from: Some(Utc::now() - chrono::Duration::days(30)),
            to: Some(Utc::now()),
            interval: Some("day".to_string()),
        }
    }
}

// ============================================
// API KEYS
// ============================================

/// Public API key metadata. The plain-text secret is never returned after
/// creation — see [`ApiKeyWithSecret`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub owner_type: String,
    pub owner_id: Uuid,
    pub name: String,
    pub prefix: String,
    pub description: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub ip_restrictions: Option<Vec<String>>,
    pub conditions: Option<serde_json::Value>,
    pub is_enabled: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub use_count: i64,
    pub created_at: DateTime<Utc>,
}

/// Returned by `create_api_key` — the plain-text `secret` is shown only here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyWithSecret {
    pub api_key: ApiKey,
    pub secret: String,
}

/// Request to create an API key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_restrictions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to update an API key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateApiKeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_restrictions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// `GET /api/v1/api-keys/me` — introspection of the calling key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyMe {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_type: String,
    pub owner_id: Uuid,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyAuthorizeRequest {
    pub resource: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyAuthorizeResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

// ============================================
// DEVICES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub fingerprint: String,
    pub device_type: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
    pub is_trusted: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub login_count: i64,
    pub created_at: DateTime<Utc>,
}

// ============================================
// APPLICATIONS
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub logo_url: Option<String>,
    pub homepage_url: Option<String>,
    pub primary_color: Option<String>,
    pub redirect_uris_base: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub access_token_lifetime_seconds: Option<i32>,
    pub refresh_token_lifetime_seconds: Option<i32>,
    pub id_token_lifetime_seconds: Option<i32>,
    pub is_active: bool,
    pub isolation_enabled: bool,
    pub settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateApplicationRequest {
    pub slug: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris_base: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_audiences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateApplicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris_base: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_audiences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_lifetime_seconds: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

/// Body for `POST .../applications/{app_id}/{resource}/link/{id}`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct LinkApplicationResourceRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_inherited: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddApplicationMemberRequest {
    pub user_id: Uuid,
    /// `"owner" | "admin" | "member"`. Defaults to `"member"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_activate: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateApplicationMemberRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `"pending" | "active" | "suspended"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMember {
    pub user_id: Uuid,
    pub application_id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub status: String,
    pub invited_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

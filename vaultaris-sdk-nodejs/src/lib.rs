//! Vaultaris SDK for Node.js
//!
//! Native Node.js bindings for Vaultaris IAM platform using napi-rs.

#![deny(clippy::all)]

use napi_derive::napi;
use serde::{Deserialize, Serialize};

mod client;
mod dpop;

pub use client::VaultarisClient;
pub use dpop::DpopKey;

// ============================================
// PAGINATION
// ============================================

/// Paginated response (used internally only, not exposed to Node.js)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

// ============================================
// INTEGRATION
// ============================================

/// Token validation result
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidation {
    pub valid: bool,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub tenant_id: Option<String>,
    pub expires_at: Option<String>,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub error: Option<String>,
}

/// Permission check result
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheck {
    pub allowed: bool,
    pub reason: Option<String>,
    pub policy: Option<String>,
}

/// Batch permission result
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPermissionResult {
    pub resource: String,
    pub action: String,
    pub allowed: bool,
}

/// Batch permission response
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPermissionResponse {
    pub results: Vec<BatchPermissionResult>,
    pub all_allowed: bool,
}

/// User information
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

/// Session validation result
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidation {
    pub valid: bool,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub tenant_id: Option<String>,
    pub expires_at: Option<String>,
    pub error: Option<String>,
}

/// SDK configuration
#[napi(object)]
#[derive(Debug, Clone)]
pub struct VaultarisConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_ms: Option<u32>,
    /// Device fingerprint. When set, sent via `X-Device-Fingerprint`
    /// header on every request. Pass `"auto"` to auto-compute from
    /// machine signals, or a pre-computed hex string.
    pub device_fingerprint: Option<String>,
}

// ============================================
// TENANTS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_required: bool,
    pub created_at: String,
    pub updated_at: String,
}

// ============================================
// USERS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub tenant_id: String,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserInput {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

// ============================================
// ROLES
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_composite: bool,
    pub created_at: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleInput {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

// ============================================
// PERMISSIONS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub resource: String,
    pub action: String,
    pub created_at: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePermissionInput {
    pub name: String,
    pub resource: String,
    pub action: String,
}

// ============================================
// GROUPS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub path: String,
    pub created_at: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupInput {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

// ============================================
// OAUTH CLIENTS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub is_enabled: bool,
    pub redirect_uris: Vec<String>,
    pub created_at: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientWithSecret {
    pub client: OAuthClient,
    pub client_secret: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClientInput {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
}

// ============================================
// SESSIONS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub session_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub is_active: bool,
    pub created_at: String,
    pub expires_at: String,
}

// ============================================
// POLICIES
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    pub id: String,
    pub name: String,
    pub resource_pattern: String,
    pub actions: Vec<String>,
    pub effect: String,
    pub priority: i32,
}

// ============================================
// AUDIT LOGS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: String,
    pub actor_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub created_at: String,
}

// ============================================
// STATISTICS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantOverview {
    pub tenant_id: String,
    pub total_users: i64,
    pub active_users: i64,
    pub total_roles: i64,
    pub total_groups: i64,
    pub total_clients: i64,
    pub active_sessions: i64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStats {
    pub total_attempts: i64,
    pub successful: i64,
    pub failed: i64,
    pub success_rate: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub active_sessions: i64,
    pub sessions_today: i64,
    pub avg_session_duration: i64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    pub blocked_attempts: i64,
    pub locked_accounts: i64,
    pub suspicious_activities: i64,
}

// ============================================
// WORKFLOW TYPES
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDefinitionInput {
    pub resource: String,
    pub action: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinitionInput {
    pub name: String,
    pub display_name: String,
    pub permissions: Vec<PermissionDefinitionInput>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapTenantInput {
    pub tenant_name: String,
    pub tenant_slug: String,
    pub admin_email: String,
    pub admin_username: String,
    pub admin_password: String,
    pub initial_roles: Vec<RoleDefinitionInput>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResult {
    pub tenant: Tenant,
    pub admin_user: User,
    pub role_ids: Vec<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatus {
    pub requires_setup: bool,
}

// ============================================
// API KEYS
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyInput {
    pub name: String,
    pub description: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub ip_restrictions: Option<Vec<String>>,
}

/// Plain-text secret is shown only on creation — copy it then.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyWithSecret {
    pub api_key_id: String,
    pub name: String,
    pub prefix: String,
    pub secret: String,
}

// ============================================
// OAUTH TOKEN
// ============================================

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

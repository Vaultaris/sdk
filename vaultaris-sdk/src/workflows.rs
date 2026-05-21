//! High-level workflow helpers that combine multiple SDK operations into common patterns.
//!
//! These methods are designed for developers who want to get things done quickly without
//! needing to understand every individual API call. Each workflow composes the low-level
//! client methods into a single, meaningful operation.
//!
//! # Example
//!
//! ```rust,no_run
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
//! use vaultaris_sdk::workflows::{BootstrapTenantRequest, RoleDefinition, PermissionDefinition};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), vaultaris_sdk::Error> {
//!     let client = VaultarisClient::from_env()?;
//!
//!     let result = client.bootstrap_tenant(BootstrapTenantRequest {
//!         tenant_name: "Acme Corp".into(),
//!         tenant_slug: "acme".into(),
//!         admin_email: "admin@acme.com".into(),
//!         admin_username: "admin".into(),
//!         admin_password: "s3cr3t!".into(),
//!         initial_roles: vec![
//!             RoleDefinition {
//!                 name: "admin".into(),
//!                 display_name: "Administrator".into(),
//!                 permissions: vec![
//!                     PermissionDefinition::new("users", "read"),
//!                     PermissionDefinition::new("users", "write"),
//!                 ],
//!             },
//!         ],
//!     }).await?;
//!
//!     println!("Tenant: {} ({})", result.tenant.name, result.tenant.id);
//!     println!("Admin: {} ({})", result.admin_user.username, result.admin_user.id);
//!     println!("Roles created: {}", result.role_ids.len());
//!     Ok(())
//! }
//! ```

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::Error;
use crate::types::{
    CreatePermissionRequest, CreateRoleRequest, CreateTenantRequest, CreateUserRequest,
    SetupRequest, Tenant, User,
};

// ============================================
// WORKFLOW TYPES
// ============================================

/// Describes a permission to create as part of a role definition.
#[derive(Debug, Clone)]
pub struct PermissionDefinition {
    pub resource: String,
    pub action: String,
    pub description: Option<String>,
}

impl PermissionDefinition {
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            description: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Describes a role (and its permissions) to create in one shot.
#[derive(Debug, Clone)]
pub struct RoleDefinition {
    pub name: String,
    pub display_name: String,
    pub permissions: Vec<PermissionDefinition>,
}

impl RoleDefinition {
    pub fn new(name: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            permissions: Vec::new(),
        }
    }

    pub fn with_permission(mut self, perm: PermissionDefinition) -> Self {
        self.permissions.push(perm);
        self
    }

    pub fn with_permissions(
        mut self,
        perms: impl IntoIterator<Item = PermissionDefinition>,
    ) -> Self {
        self.permissions.extend(perms);
        self
    }
}

/// Input for the `bootstrap_tenant` workflow.
#[derive(Debug, Clone)]
pub struct BootstrapTenantRequest {
    pub tenant_name: String,
    pub tenant_slug: String,
    pub admin_email: String,
    pub admin_username: String,
    pub admin_password: String,
    /// Roles to create. The first role in the list is assigned to the admin user.
    pub initial_roles: Vec<RoleDefinition>,
}

/// Output from the `bootstrap_tenant` workflow.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    pub tenant: Tenant,
    pub admin_user: User,
    /// IDs of all created roles, in the same order as `initial_roles`.
    pub role_ids: Vec<Uuid>,
}

// ============================================
// WORKFLOW METHODS
// ============================================

#[cfg(feature = "async")]
impl VaultarisClient {
    /// Check whether first-time setup is required and, if so, perform it atomically.
    ///
    /// Returns `true` if setup was performed, `false` if it was already done.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
    /// # use vaultaris_sdk::types::SetupRequest;
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// let client = VaultarisClient::from_env()?;
    /// let performed = client.setup_if_needed(SetupRequest {
    ///     admin_username: "admin".into(),
    ///     admin_email: "admin@example.com".into(),
    ///     admin_password: "changeme!".into(),
    ///     tenant_name: Some("Default".into()),
    ///     tenant_slug: Some("default".into()),
    /// }).await?;
    /// if performed { println!("Setup complete!"); }
    /// # Ok(()) }
    /// ```
    pub async fn setup_if_needed(&self, req: SetupRequest) -> Result<bool, Error> {
        let status = self.requires_setup().await?;
        if status.requires_setup {
            self.perform_setup(&req).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Create a user and immediately assign one or more roles to them.
    ///
    /// If any role assignment fails the user is deleted so the operation
    /// is all-or-nothing from the caller's perspective.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
    /// # use vaultaris_sdk::types::CreateUserRequest;
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// let client = VaultarisClient::from_env()?;
    /// let user = client.provision_user(
    ///     "tenant-uuid",
    ///     &CreateUserRequest {
    ///         username: "jane.doe".into(),
    ///         email: "jane@example.com".into(),
    ///         password: Some("hunter2".into()),
    ///         ..Default::default()
    ///     },
    ///     &["role-uuid-1", "role-uuid-2"],
    /// ).await?;
    /// println!("Created user {}", user.id);
    /// # Ok(()) }
    /// ```
    pub async fn provision_user(
        &self,
        tenant_id: &str,
        user_req: &CreateUserRequest,
        role_ids: &[&str],
    ) -> Result<User, Error> {
        let user = self.create_user(tenant_id, user_req).await?;
        let user_id = user.id.to_string();

        for role_id in role_ids {
            if let Err(e) = self.assign_role_to_user(tenant_id, &user_id, role_id).await {
                // Best-effort rollback: delete the user we just created
                let _ = self.delete_user(tenant_id, &user_id).await;
                return Err(e);
            }
        }

        Ok(user)
    }

    /// Assert that a user has a permission, returning an error if they do not.
    ///
    /// Useful as a guard inside request handlers:
    /// ```rust,no_run
    /// # use vaultaris_sdk::VaultarisClient;
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// # let client = VaultarisClient::from_env()?;
    /// client.require_permission("tenant-id", "user-id", "invoices", "delete").await?;
    /// // ... proceed knowing the user is allowed
    /// # Ok(()) }
    /// ```
    pub async fn require_permission(
        &self,
        tenant_id: &str,
        user_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), Error> {
        let allowed = self
            .check_permission(tenant_id, user_id, resource, action)
            .await?;
        if allowed {
            Ok(())
        } else {
            Err(Error::PermissionDenied(format!(
                "user {} does not have {}:{} on tenant {}",
                user_id, resource, action, tenant_id
            )))
        }
    }

    /// Validate a Bearer token **and** check a permission in a single call.
    ///
    /// Returns `Ok(())` only when the token is valid and the permission is granted.
    /// Use this at the top of protected API handlers to do both checks at once.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use vaultaris_sdk::VaultarisClient;
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// # let client = VaultarisClient::from_env()?;
    /// // Fails if the token is expired OR the user cannot delete reports
    /// client.check_token_permission("Bearer eyJ...", "reports", "delete").await?;
    /// # Ok(()) }
    /// ```
    pub async fn check_token_permission(
        &self,
        token: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), Error> {
        let token = token.trim_start_matches("Bearer ").trim();
        let validation = self.validate_token(token).await?;

        if !validation.valid {
            return Err(Error::TokenInvalid(
                validation.error.unwrap_or_else(|| "invalid token".into()),
            ));
        }

        let tenant_id = validation
            .tenant_id
            .ok_or_else(|| Error::TokenInvalid("token missing tenant_id".into()))?;
        let user_id = validation
            .user_id
            .ok_or_else(|| Error::TokenInvalid("token missing user_id".into()))?;

        self.require_permission(
            &tenant_id.to_string(),
            &user_id.to_string(),
            resource,
            action,
        )
        .await
    }

    /// Create multiple roles with their permissions in one operation.
    ///
    /// For each `RoleDefinition`:
    /// 1. Creates the role.
    /// 2. Creates each permission (if it doesn't already exist).
    /// 3. Assigns the permissions to the role.
    ///
    /// Returns the IDs of the created roles in the same order as the input slice.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use vaultaris_sdk::VaultarisClient;
    /// # use vaultaris_sdk::workflows::{RoleDefinition, PermissionDefinition};
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// # let client = VaultarisClient::from_env()?;
    /// let role_ids = client.setup_rbac("tenant-id", &[
    ///     RoleDefinition {
    ///         name: "editor".into(),
    ///         display_name: "Editor".into(),
    ///         permissions: vec![
    ///             PermissionDefinition::new("articles", "read"),
    ///             PermissionDefinition::new("articles", "write"),
    ///         ],
    ///     },
    /// ]).await?;
    /// # Ok(()) }
    /// ```
    pub async fn setup_rbac(
        &self,
        tenant_id: &str,
        roles: &[RoleDefinition],
    ) -> Result<Vec<Uuid>, Error> {
        let mut role_ids = Vec::with_capacity(roles.len());

        for role_def in roles {
            // Create the role
            let role = self
                .create_role(
                    tenant_id,
                    &CreateRoleRequest {
                        name: role_def.name.clone(),
                        display_name: Some(role_def.display_name.clone()),
                        ..Default::default()
                    },
                )
                .await?;

            // Create permissions and assign them
            for perm_def in &role_def.permissions {
                let name = format!("{}:{}", perm_def.resource, perm_def.action);
                let permission = self
                    .create_permission(
                        tenant_id,
                        &CreatePermissionRequest {
                            name: name.clone(),
                            resource: perm_def.resource.clone(),
                            action: perm_def.action.clone(),
                            display_name: Some(name),
                            description: perm_def.description.clone(),
                            ..Default::default()
                        },
                    )
                    .await?;

                self.assign_permission_to_role(
                    tenant_id,
                    &role.id.to_string(),
                    &permission.id.to_string(),
                )
                .await?;
            }

            role_ids.push(role.id);
        }

        Ok(role_ids)
    }

    /// Fetch **all** users in a tenant, automatically handling pagination.
    ///
    /// Be careful with large tenants — consider `list_users` with explicit pages instead.
    pub async fn collect_users(&self, tenant_id: &str) -> Result<Vec<crate::types::User>, Error> {
        let mut all = Vec::new();
        let mut page = 1i64;
        let per_page = 100i64;

        loop {
            let result = self.list_users(tenant_id, page, per_page).await?;
            let has_next = result.has_next();
            all.extend(result.data);
            if !has_next {
                break;
            }
            page += 1;
        }

        Ok(all)
    }

    /// Fetch **all** roles in a tenant, automatically handling pagination.
    pub async fn collect_roles(&self, tenant_id: &str) -> Result<Vec<crate::types::Role>, Error> {
        let mut all = Vec::new();
        let mut page = 1i64;
        let per_page = 100i64;

        loop {
            let result = self.list_roles(tenant_id, page, per_page).await?;
            let has_next = result.has_next();
            all.extend(result.data);
            if !has_next {
                break;
            }
            page += 1;
        }

        Ok(all)
    }

    /// Provision a complete tenant in one call:
    /// 1. Creates the tenant.
    /// 2. Creates the admin user.
    /// 3. Calls `setup_rbac` for all initial roles.
    /// 4. Assigns the first role to the admin user (if any roles were provided).
    ///
    /// Returns a `BootstrapResult` with the tenant, admin user, and role IDs.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use vaultaris_sdk::VaultarisClient;
    /// # use vaultaris_sdk::workflows::{BootstrapTenantRequest, RoleDefinition, PermissionDefinition};
    /// # #[tokio::main] async fn main() -> Result<(), vaultaris_sdk::Error> {
    /// # let client = VaultarisClient::from_env()?;
    /// let result = client.bootstrap_tenant(BootstrapTenantRequest {
    ///     tenant_name: "Acme Corp".into(),
    ///     tenant_slug: "acme".into(),
    ///     admin_email: "admin@acme.com".into(),
    ///     admin_username: "admin".into(),
    ///     admin_password: "s3cr3t!".into(),
    ///     initial_roles: vec![
    ///         RoleDefinition {
    ///             name: "admin".into(),
    ///             display_name: "Administrator".into(),
    ///             permissions: vec![
    ///                 PermissionDefinition::new("users", "read"),
    ///                 PermissionDefinition::new("users", "write"),
    ///             ],
    ///         },
    ///     ],
    /// }).await?;
    /// println!("Tenant ready: {}", result.tenant.id);
    /// # Ok(()) }
    /// ```
    pub async fn bootstrap_tenant(
        &self,
        req: BootstrapTenantRequest,
    ) -> Result<BootstrapResult, Error> {
        // 1. Create the tenant
        let tenant = self
            .create_tenant(&CreateTenantRequest {
                name: req.tenant_name,
                slug: req.tenant_slug,
                ..Default::default()
            })
            .await?;
        let tenant_id = tenant.id.to_string();

        // 2. Create admin user
        let admin_user = self
            .create_user(
                &tenant_id,
                &CreateUserRequest {
                    username: req.admin_username,
                    email: req.admin_email,
                    password: Some(req.admin_password),
                    email_verified: Some(true),
                    status: Some("active".into()),
                    ..Default::default()
                },
            )
            .await?;

        // 3. Create roles with permissions
        let role_ids = if req.initial_roles.is_empty() {
            Vec::new()
        } else {
            self.setup_rbac(&tenant_id, &req.initial_roles).await?
        };

        // 4. Assign first role to the admin user
        if let Some(first_role_id) = role_ids.first() {
            self.assign_role_to_user(
                &tenant_id,
                &admin_user.id.to_string(),
                &first_role_id.to_string(),
            )
            .await?;
        }

        Ok(BootstrapResult {
            tenant,
            admin_user,
            role_ids,
        })
    }
}

//! High-level workflow helpers that compose multiple SDK operations.
//!
//! # Example
//!
//! ```rust,no_run
//! use vaultaris_sdk::{VaultarisClient, VaultarisConfig};
//! use vaultaris_sdk::workflows::{BootstrapTenantRequest, PermissionDefinition, RoleDefinition};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), vaultaris_sdk::Error> {
//! let client = VaultarisClient::from_env()?;
//! let result = client
//!     .bootstrap_tenant(BootstrapTenantRequest {
//!         tenant_name: "Acme Corp".into(),
//!         tenant_slug: "acme".into(),
//!         admin_email: "admin@acme.com".into(),
//!         admin_username: "admin".into(),
//!         admin_password: "s3cr3t!".into(),
//!         initial_roles: vec![RoleDefinition::new("admin", "Administrator")
//!             .with_permission(PermissionDefinition::new("users", "read"))],
//!     })
//!     .await?;
//! println!("Tenant ready: {}", result.tenant.id);
//! # Ok(()) }
//! ```

use uuid::Uuid;

use crate::client::VaultarisClient;
use crate::error::{Error, Result};
use crate::types::{
    CreatePermissionRequest, CreateRoleRequest, CreateTenantRequest, CreateUserRequest, Pagination,
    Role, SetupRequest, Tenant, User,
};

/// A permission to declare alongside a role.
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

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// A role plus the permissions to attach to it.
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

    #[must_use]
    pub fn with_permission(mut self, perm: PermissionDefinition) -> Self {
        self.permissions.push(perm);
        self
    }

    #[must_use]
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
    /// Roles to create. The first role is assigned to the admin user.
    pub initial_roles: Vec<RoleDefinition>,
}

/// Output of the `bootstrap_tenant` workflow.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    pub tenant: Tenant,
    pub admin_user: User,
    /// IDs of all created roles, in the same order as `initial_roles`.
    pub role_ids: Vec<Uuid>,
}

#[cfg(feature = "async")]
impl VaultarisClient {
    /// Run first-time setup only when the server reports it's required.
    /// Returns `true` when setup actually ran.
    pub async fn setup_if_needed(&self, req: SetupRequest) -> Result<bool> {
        let status = self.requires_setup().await?;
        if status.requires_setup {
            self.perform_setup(&req).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Create a user and assign roles atomically — on assignment failure the
    /// freshly-created user is deleted.
    pub async fn provision_user(
        &self,
        tenant_id: Uuid,
        user_req: &CreateUserRequest,
        role_ids: &[Uuid],
    ) -> Result<User> {
        let user = self.create_user(tenant_id, user_req).await?;
        for role_id in role_ids {
            if let Err(e) = self.assign_role_to_user(tenant_id, user.id, *role_id).await {
                let _rollback = self.delete_user(tenant_id, user.id).await;
                return Err(e);
            }
        }
        Ok(user)
    }

    /// Assert that a user holds `(resource, action)`. Errors with
    /// [`Error::PermissionDenied`] when they don't.
    pub async fn require_permission(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        resource: &str,
        action: &str,
    ) -> Result<()> {
        if self
            .check_permission(tenant_id, user_id, resource, action)
            .await?
        {
            return Ok(());
        }
        Err(Error::PermissionDenied {
            tenant_id,
            user_id,
            resource: resource.to_string(),
            action: action.to_string(),
        })
    }

    /// Validate a Bearer token and check a permission in one call.
    pub async fn check_token_permission(
        &self,
        token: &str,
        resource: &str,
        action: &str,
    ) -> Result<()> {
        let token = token
            .trim_start_matches("Bearer ")
            .trim_start_matches("ApiKey ")
            .trim();
        let validation = self.validate_token(token).await?;
        if !validation.valid {
            return Err(Error::TokenInvalid(
                validation
                    .error
                    .unwrap_or_else(|| "invalid token".to_string()),
            ));
        }
        let tenant_id = validation
            .tenant_id
            .ok_or_else(|| Error::TokenInvalid("token missing tenant_id".to_string()))?;
        let user_id = validation
            .user_id
            .ok_or_else(|| Error::TokenInvalid("token missing user_id".to_string()))?;
        self.require_permission(tenant_id, user_id, resource, action)
            .await
    }

    /// Bulk-create roles with their permissions. Returns the role IDs in
    /// the same order as the input.
    pub async fn setup_rbac(&self, tenant_id: Uuid, roles: &[RoleDefinition]) -> Result<Vec<Uuid>> {
        let mut role_ids = Vec::with_capacity(roles.len());
        for role_def in roles {
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
                self.assign_permission_to_role(tenant_id, role.id, permission.id)
                    .await?;
            }
            role_ids.push(role.id);
        }
        Ok(role_ids)
    }

    /// Fetch every user in a tenant, paginating internally. Heavy operation
    /// — prefer `list_users` with explicit page bounds for large tenants.
    pub async fn collect_users(&self, tenant_id: Uuid) -> Result<Vec<User>> {
        self.collect_pages(|page| async move { self.list_users(tenant_id, page).await })
            .await
    }

    /// Fetch every role in a tenant, paginating internally.
    pub async fn collect_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>> {
        self.collect_pages(|page| async move { self.list_roles(tenant_id, page).await })
            .await
    }

    /// Build a tenant + admin + initial roles in one call.
    pub async fn bootstrap_tenant(&self, req: BootstrapTenantRequest) -> Result<BootstrapResult> {
        let tenant = self
            .create_tenant(&CreateTenantRequest {
                name: req.tenant_name,
                slug: req.tenant_slug,
                ..Default::default()
            })
            .await?;
        let admin_user = self
            .create_user(
                tenant.id,
                &CreateUserRequest {
                    username: req.admin_username,
                    email: req.admin_email,
                    password: Some(req.admin_password),
                    email_verified: Some(true),
                    status: Some("active".to_string()),
                    ..Default::default()
                },
            )
            .await?;
        let role_ids = if req.initial_roles.is_empty() {
            Vec::new()
        } else {
            self.setup_rbac(tenant.id, &req.initial_roles).await?
        };
        if let Some(first) = role_ids.first() {
            self.assign_role_to_user(tenant.id, admin_user.id, *first)
                .await?;
        }
        Ok(BootstrapResult {
            tenant,
            admin_user,
            role_ids,
        })
    }

    async fn collect_pages<T, F, Fut>(&self, mut fetch: F) -> Result<Vec<T>>
    where
        F: FnMut(Pagination) -> Fut,
        Fut: std::future::Future<Output = Result<crate::types::Page<T>>>,
    {
        let mut all = Vec::new();
        let mut pagination = Pagination::new(1, 100);
        loop {
            let result = fetch(pagination).await?;
            let has_next = result.has_next();
            all.extend(result.data);
            if !has_next {
                break;
            }
            pagination.page += 1;
        }
        Ok(all)
    }
}

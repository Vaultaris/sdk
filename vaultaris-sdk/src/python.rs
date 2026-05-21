//! Python bindings for Vaultaris SDK using PyO3

// pyo3-generated and wrapper signatures pull in tuple-of-tuple shapes that
// trip `type_complexity`, plus the migration from `PyObject` to `Py<PyAny>`
// is tracked separately. Suppressing these crate-wide for the `python`
// feature keeps the rest of the SDK's lint posture honest.
#![allow(clippy::type_complexity, deprecated, unused_imports)]

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

/// Helper: convert Rust Vec<(String, String, Vec<(String, String)>)> to workflow RoleDefinition
fn parse_roles_input(
    roles: Vec<(String, String, Vec<(String, String)>)>,
) -> Vec<crate::workflows::RoleDefinition> {
    roles
        .into_iter()
        .map(
            |(name, display_name, perms)| crate::workflows::RoleDefinition {
                name,
                display_name,
                permissions: perms
                    .into_iter()
                    .map(
                        |(resource, action)| crate::workflows::PermissionDefinition {
                            resource,
                            action,
                            description: None,
                        },
                    )
                    .collect(),
            },
        )
        .collect()
}

/// Helper: convert serde_json::Value to PyObject via JSON parsing
fn json_to_py(py: Python<'_>, value: serde_json::Value) -> PyResult<PyObject> {
    let json_str = serde_json::to_string(&value)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let json_mod = PyModule::import(py, "json")?;
    let result = json_mod.call_method("loads", (json_str,), None)?;
    Ok(result.into())
}

/// Python wrapper for TokenValidation
#[pyclass(name = "TokenValidation")]
pub struct PyTokenValidation {
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub user_id: Option<String>,
    #[pyo3(get)]
    pub tenant_id: Option<String>,
    #[pyo3(get)]
    pub username: Option<String>,
    #[pyo3(get)]
    pub email: Option<String>,
    #[pyo3(get)]
    pub roles: Vec<String>,
    #[pyo3(get)]
    pub permissions: Vec<String>,
    #[pyo3(get)]
    pub scopes: Vec<String>,
    #[pyo3(get)]
    pub expires_at: Option<i64>,
    #[pyo3(get)]
    pub error: Option<String>,
}

impl From<crate::types::TokenValidation> for PyTokenValidation {
    fn from(v: crate::types::TokenValidation) -> Self {
        Self {
            valid: v.valid,
            user_id: v.user_id.map(|u| u.to_string()),
            tenant_id: v.tenant_id.map(|u| u.to_string()),
            username: v.username,
            email: v.email,
            roles: v.roles,
            permissions: v.permissions,
            scopes: v.scopes,
            expires_at: v.expires_at,
            error: v.error,
        }
    }
}

/// Python wrapper for PermissionCheck
#[pyclass(name = "PermissionCheck")]
pub struct PyPermissionCheck {
    #[pyo3(get)]
    pub allowed: bool,
    #[pyo3(get)]
    pub reason: Option<String>,
    #[pyo3(get)]
    pub matched_policy: Option<String>,
}

impl From<crate::types::PermissionCheck> for PyPermissionCheck {
    fn from(v: crate::types::PermissionCheck) -> Self {
        Self {
            allowed: v.allowed,
            reason: v.reason,
            matched_policy: v.matched_policy,
        }
    }
}

/// Python wrapper for UserInfo
#[pyclass(name = "UserInfo")]
pub struct PyUserInfo {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub tenant_id: String,
    #[pyo3(get)]
    pub username: String,
    #[pyo3(get)]
    pub email: String,
    #[pyo3(get)]
    pub email_verified: bool,
    #[pyo3(get)]
    pub first_name: Option<String>,
    #[pyo3(get)]
    pub last_name: Option<String>,
    #[pyo3(get)]
    pub display_name: Option<String>,
    #[pyo3(get)]
    pub locale: Option<String>,
    #[pyo3(get)]
    pub timezone: Option<String>,
    #[pyo3(get)]
    pub permissions: Vec<String>,
}

impl From<crate::types::UserInfo> for PyUserInfo {
    fn from(v: crate::types::UserInfo) -> Self {
        Self {
            id: v.id.to_string(),
            tenant_id: v.tenant_id.to_string(),
            username: v.username,
            email: v.email,
            email_verified: v.email_verified,
            first_name: v.first_name,
            last_name: v.last_name,
            display_name: v.display_name,
            locale: v.locale,
            timezone: v.timezone,
            permissions: v.permissions,
        }
    }
}

/// ES256 keypair used to attach DPoP proofs to every request the client
/// makes. Generate one per install and persist it via `to_pkcs8_pem()`.
///
/// ```python
/// from vaultaris import VaultarisClient, DpopKey
///
/// key = DpopKey.generate()
/// open("/var/lib/myapp/dpop.pem", "w").write(key.to_pkcs8_pem())
///
/// client = VaultarisClient("https://auth.example.com",
///                         api_key="eyJ...", dpop_key=key)
/// # every call from here on attaches a DPoP proof automatically.
/// ```
#[pyclass(name = "DpopKey")]
#[derive(Clone)]
pub struct PyDpopKey {
    inner: crate::dpop::DpopKey,
}

#[pymethods]
impl PyDpopKey {
    /// Generate a fresh ES256 keypair using the OS RNG.
    #[staticmethod]
    pub fn generate() -> Self {
        Self {
            inner: crate::dpop::DpopKey::generate(),
        }
    }

    /// Load a key previously saved with `to_pkcs8_pem()`.
    #[staticmethod]
    pub fn from_pkcs8_pem(pem: &str) -> PyResult<Self> {
        crate::dpop::DpopKey::from_pkcs8_pem(pem)
            .map(|inner| Self { inner })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Serialize the private key as PKCS#8 PEM. Treat the output as a secret.
    pub fn to_pkcs8_pem(&self) -> PyResult<String> {
        self.inner
            .to_pkcs8_pem()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// JWK thumbprint (RFC 7638) of the public key — the value the server
    /// will pin in the access token's `cnf.jkt` claim.
    pub fn jkt(&self) -> String {
        self.inner.jkt().to_string()
    }

    fn __repr__(&self) -> String {
        format!("DpopKey(jkt='{}')", self.inner.jkt())
    }
}

/// Python Vaultaris client
#[pyclass(name = "VaultarisClient")]
pub struct PyVaultarisClient {
    client: crate::VaultarisClient,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl PyVaultarisClient {
    /// Create a new Vaultaris client. Pass `dpop_key` to issue and use
    /// sender-constrained tokens transparently.
    #[new]
    #[pyo3(signature = (base_url, api_key=None, tenant_id=None, timeout=None, dpop_key=None))]
    pub fn new(
        base_url: &str,
        api_key: Option<&str>,
        tenant_id: Option<&str>,
        timeout: Option<u64>,
        dpop_key: Option<PyDpopKey>,
    ) -> PyResult<Self> {
        let mut config = crate::VaultarisConfig::new(base_url);

        if let Some(key) = api_key {
            config = config.with_api_key(key);
        }

        if let Some(tenant) = tenant_id {
            config = config.with_tenant(tenant);
        }

        if let Some(t) = timeout {
            config = config.with_timeout(t);
        }

        if let Some(key) = dpop_key {
            config = config.with_dpop_key(key.inner);
        }

        let client = crate::VaultarisClient::new(config)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        Ok(Self { client, runtime })
    }

    /// Create a client from environment variables
    #[staticmethod]
    pub fn from_env() -> PyResult<Self> {
        let client = crate::VaultarisClient::from_env()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        Ok(Self { client, runtime })
    }

    // TOKEN OPERATIONS

    pub fn validate_token(&self, token: &str) -> PyResult<PyTokenValidation> {
        self.runtime
            .block_on(self.client.validate_token(token))
            .map(|v| v.into())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    #[pyo3(signature = (token, required_scopes=None, required_permissions=None))]
    pub fn validate_token_with_requirements(
        &self,
        token: &str,
        required_scopes: Option<Vec<String>>,
        required_permissions: Option<Vec<String>>,
    ) -> PyResult<PyTokenValidation> {
        self.runtime
            .block_on(self.client.validate_token_with_requirements(
                token,
                required_scopes,
                required_permissions,
            ))
            .map(|v| v.into())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn check_permission(
        &self,
        tenant_id: &str,
        user_id: &str,
        resource: &str,
        action: &str,
    ) -> PyResult<bool> {
        self.runtime
            .block_on(
                self.client
                    .check_permission(tenant_id, user_id, resource, action),
            )
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    #[pyo3(signature = (tenant_id, user_id, resource, action, context=None))]
    pub fn check_permission_detailed(
        &self,
        tenant_id: &str,
        user_id: &str,
        resource: &str,
        action: &str,
        context: Option<HashMap<String, String>>,
    ) -> PyResult<PyPermissionCheck> {
        let ctx = context.map(|c| serde_json::json!(c));

        self.runtime
            .block_on(
                self.client
                    .check_permission_detailed(tenant_id, user_id, resource, action, ctx),
            )
            .map(|v| v.into())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn batch_check_permissions(
        &self,
        tenant_id: &str,
        user_id: &str,
        checks: Vec<(String, String)>,
    ) -> PyResult<Vec<(String, String, bool)>> {
        let check_list: Vec<crate::types::PermissionToCheck> = checks
            .into_iter()
            .map(|(r, a)| crate::types::PermissionToCheck::new(r, a))
            .collect();

        self.runtime
            .block_on(
                self.client
                    .batch_check_permissions(tenant_id, user_id, check_list),
            )
            .map(|r| {
                r.results
                    .into_iter()
                    .map(|p| (p.resource, p.action, p.allowed))
                    .collect()
            })
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn get_user(&self, tenant_id: &str, user_id: &str) -> PyResult<PyUserInfo> {
        self.runtime
            .block_on(self.client.get_user(tenant_id, user_id))
            .map(|v| v.into())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn is_token_valid(&self, token: &str) -> bool {
        self.runtime.block_on(self.client.is_token_valid(token))
    }

    pub fn has_any_permission(
        &self,
        tenant_id: &str,
        user_id: &str,
        permissions: Vec<(String, String)>,
    ) -> PyResult<bool> {
        let perms: Vec<(&str, &str)> = permissions
            .iter()
            .map(|(r, a)| (r.as_str(), a.as_str()))
            .collect();

        self.runtime
            .block_on(self.client.has_any_permission(tenant_id, user_id, &perms))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn has_all_permissions(
        &self,
        tenant_id: &str,
        user_id: &str,
        permissions: Vec<(String, String)>,
    ) -> PyResult<bool> {
        let perms: Vec<(&str, &str)> = permissions
            .iter()
            .map(|(r, a)| (r.as_str(), a.as_str()))
            .collect();

        self.runtime
            .block_on(self.client.has_all_permissions(tenant_id, user_id, &perms))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn validate_session(&self, token: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.validate_session(token))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    // TENANT MANAGEMENT

    pub fn list_tenants(&self, page: i64, per_page: i64, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_tenants(page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn create_tenant(&self, name: &str, slug: &str, py: Python) -> PyResult<PyObject> {
        let req = crate::types::CreateTenantRequest {
            name: name.to_string(),
            slug: slug.to_string(),
            ..Default::default()
        };
        let result = self
            .runtime
            .block_on(self.client.create_tenant(&req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_tenant(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_tenant(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    // USER MANAGEMENT

    pub fn list_users(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_users(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn create_user(
        &self,
        tenant_id: &str,
        username: &str,
        email: &str,
        py: Python,
    ) -> PyResult<PyObject> {
        let req = crate::types::CreateUserRequest {
            username: username.to_string(),
            email: email.to_string(),
            ..Default::default()
        };
        let result = self
            .runtime
            .block_on(self.client.create_user(tenant_id, &req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_user_by_id(&self, tenant_id: &str, user_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_user_by_id(tenant_id, user_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn delete_user(&self, tenant_id: &str, user_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.delete_user(tenant_id, user_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // ROLE MANAGEMENT

    pub fn list_roles(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_roles(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn create_role(&self, tenant_id: &str, name: &str, py: Python) -> PyResult<PyObject> {
        let req = crate::types::CreateRoleRequest {
            name: name.to_string(),
            ..Default::default()
        };
        let result = self
            .runtime
            .block_on(self.client.create_role(tenant_id, &req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_role(&self, tenant_id: &str, role_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_role(tenant_id, role_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn delete_role(&self, tenant_id: &str, role_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.delete_role(tenant_id, role_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // PERMISSION MANAGEMENT

    pub fn list_permissions(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_permissions(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn create_permission(
        &self,
        tenant_id: &str,
        name: &str,
        resource: &str,
        action: &str,
        py: Python,
    ) -> PyResult<PyObject> {
        let req = crate::types::CreatePermissionRequest {
            name: name.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            ..Default::default()
        };
        let result = self
            .runtime
            .block_on(self.client.create_permission(tenant_id, &req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn delete_permission(&self, tenant_id: &str, permission_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.delete_permission(tenant_id, permission_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // GROUP MANAGEMENT

    pub fn list_groups(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_groups(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn create_group(&self, tenant_id: &str, name: &str, py: Python) -> PyResult<PyObject> {
        let req = crate::types::CreateGroupRequest {
            name: name.to_string(),
            ..Default::default()
        };
        let result = self
            .runtime
            .block_on(self.client.create_group(tenant_id, &req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_group(&self, tenant_id: &str, group_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_group(tenant_id, group_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn delete_group(&self, tenant_id: &str, group_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.delete_group(tenant_id, group_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // OAUTH CLIENT MANAGEMENT

    pub fn list_clients(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_clients(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_client(&self, tenant_id: &str, client_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_client(tenant_id, client_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn delete_client(&self, tenant_id: &str, client_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.delete_client(tenant_id, client_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // SESSION MANAGEMENT

    pub fn list_sessions(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_sessions(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn revoke_session(&self, tenant_id: &str, session_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.revoke_session(tenant_id, session_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // AUDIT LOGS

    pub fn list_audit_logs(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        py: Python,
    ) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.list_audit_logs(tenant_id, page, per_page))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    // STATISTICS

    pub fn get_tenant_overview(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_tenant_overview(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_auth_stats(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_auth_stats(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_session_stats(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_session_stats(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_security_stats(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_security_stats(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn get_dashboard_summary(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.get_dashboard_summary(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    // MFA

    pub fn setup_totp(&self, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.setup_totp())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn verify_totp(&self, user_id: &str, code: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.verify_totp(user_id, code, false))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn disable_totp(&self) -> PyResult<()> {
        self.runtime
            .block_on(self.client.disable_totp())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // PASSWORD RESET

    pub fn request_password_reset(&self, tenant_id: &str, email: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.request_password_reset(tenant_id, email))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn validate_reset_token(&self, token: &str, py: Python) -> PyResult<PyObject> {
        let result = self
            .runtime
            .block_on(self.client.validate_reset_token(token))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(result).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn complete_password_reset(&self, token: &str, new_password: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.complete_password_reset(token, new_password))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // EMAIL VERIFICATION

    pub fn verify_email(&self, token: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.verify_email(token))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // ============================================
    // LOW-LEVEL WORKFLOW SUPPORT
    // ============================================

    pub fn assign_role_to_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> PyResult<()> {
        self.runtime
            .block_on(self.client.assign_role_to_user(tenant_id, user_id, role_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn assign_permission_to_role(
        &self,
        tenant_id: &str,
        role_id: &str,
        permission_id: &str,
    ) -> PyResult<()> {
        self.runtime
            .block_on(
                self.client
                    .assign_permission_to_role(tenant_id, role_id, permission_id),
            )
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn revoke_user_sessions(&self, tenant_id: &str, user_id: &str) -> PyResult<()> {
        self.runtime
            .block_on(self.client.revoke_user_sessions(tenant_id, user_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    // ============================================
    // WORKFLOW METHODS
    // ============================================

    #[pyo3(signature = (admin_username, admin_email, admin_password, tenant_name=None, tenant_slug=None))]
    pub fn setup_if_needed(
        &self,
        admin_username: &str,
        admin_email: &str,
        admin_password: &str,
        tenant_name: Option<&str>,
        tenant_slug: Option<&str>,
    ) -> PyResult<bool> {
        let req = crate::types::SetupRequest {
            admin_username: admin_username.to_string(),
            admin_email: admin_email.to_string(),
            admin_password: admin_password.to_string(),
            tenant_name: tenant_name.map(|s| s.to_string()),
            tenant_slug: tenant_slug.map(|s| s.to_string()),
        };

        self.runtime
            .block_on(self.client.setup_if_needed(req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    #[pyo3(signature = (tenant_id, username, email, password=None, role_ids=None))]
    pub fn provision_user(
        &self,
        tenant_id: &str,
        username: &str,
        email: &str,
        password: Option<&str>,
        role_ids: Option<Vec<String>>,
        py: Python,
    ) -> PyResult<PyObject> {
        let user_req = crate::types::CreateUserRequest {
            username: username.to_string(),
            email: email.to_string(),
            password: password.map(|s| s.to_string()),
            ..Default::default()
        };

        let role_list = role_ids.unwrap_or_default();

        let user = self
            .runtime
            .block_on(
                self.client.provision_user(
                    tenant_id,
                    &user_req,
                    role_list
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .as_slice(),
                ),
            )
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(user).unwrap_or(serde_json::json!({})),
        )
    }

    pub fn require_permission(
        &self,
        tenant_id: &str,
        user_id: &str,
        resource: &str,
        action: &str,
    ) -> PyResult<()> {
        self.runtime
            .block_on(
                self.client
                    .require_permission(tenant_id, user_id, resource, action),
            )
            .map_err(|e| match e {
                crate::error::Error::PermissionDenied(msg) => {
                    pyo3::exceptions::PyPermissionError::new_err(msg)
                }
                other => pyo3::exceptions::PyRuntimeError::new_err(other.to_string()),
            })
    }

    pub fn check_token_permission(
        &self,
        token: &str,
        resource: &str,
        action: &str,
    ) -> PyResult<()> {
        self.runtime
            .block_on(self.client.check_token_permission(token, resource, action))
            .map_err(|e| match e {
                crate::error::Error::PermissionDenied(msg) => {
                    pyo3::exceptions::PyPermissionError::new_err(msg)
                }
                crate::error::Error::TokenInvalid(msg) => {
                    pyo3::exceptions::PyValueError::new_err(format!("Invalid token: {}", msg))
                }
                other => pyo3::exceptions::PyRuntimeError::new_err(other.to_string()),
            })
    }

    pub fn setup_rbac(
        &self,
        tenant_id: &str,
        roles: Vec<(String, String, Vec<(String, String)>)>,
    ) -> PyResult<Vec<String>> {
        let rust_roles = parse_roles_input(roles);

        self.runtime
            .block_on(self.client.setup_rbac(tenant_id, &rust_roles))
            .map(|ids| ids.into_iter().map(|id| id.to_string()).collect())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    pub fn collect_users(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let users = self
            .runtime
            .block_on(self.client.collect_users(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(users).unwrap_or(serde_json::json!([])),
        )
    }

    pub fn collect_roles(&self, tenant_id: &str, py: Python) -> PyResult<PyObject> {
        let roles = self
            .runtime
            .block_on(self.client.collect_roles(tenant_id))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        json_to_py(
            py,
            serde_json::to_value(roles).unwrap_or(serde_json::json!([])),
        )
    }

    #[pyo3(signature = (tenant_name, tenant_slug, admin_email, admin_username, admin_password, initial_roles=None))]
    pub fn bootstrap_tenant(
        &self,
        tenant_name: &str,
        tenant_slug: &str,
        admin_email: &str,
        admin_username: &str,
        admin_password: &str,
        initial_roles: Option<Vec<(String, String, Vec<(String, String)>)>>,
        py: Python,
    ) -> PyResult<PyObject> {
        let roles = initial_roles.unwrap_or_default();
        let rust_roles = parse_roles_input(roles);

        let req = crate::workflows::BootstrapTenantRequest {
            tenant_name: tenant_name.to_string(),
            tenant_slug: tenant_slug.to_string(),
            admin_email: admin_email.to_string(),
            admin_username: admin_username.to_string(),
            admin_password: admin_password.to_string(),
            initial_roles: rust_roles,
        };

        let result = self
            .runtime
            .block_on(self.client.bootstrap_tenant(req))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        let result_json = serde_json::json!({
            "tenant": result.tenant,
            "admin_user": result.admin_user,
            "role_ids": result.role_ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        });
        json_to_py(py, result_json)
    }
}

/// Python module initialization
#[pymodule]
fn vaultaris(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyVaultarisClient>()?;
    m.add_class::<PyTokenValidation>()?;
    m.add_class::<PyPermissionCheck>()?;
    m.add_class::<PyUserInfo>()?;
    m.add_class::<PyDpopKey>()?;
    Ok(())
}

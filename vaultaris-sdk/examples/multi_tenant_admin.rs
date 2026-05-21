//! Multi-tenant administration example
//!
//! Scenario: A platform admin dashboard that manages multiple customer tenants.
//! Demonstrates how to:
//!   - List all tenants
//!   - Inspect per-tenant statistics and user counts
//!   - Manage users across tenants
//!   - Revoke suspicious sessions across a tenant
//!   - Use the collect_* helpers for full result sets
//!
//! Run with:
//!   VAULTARA_URL=http://localhost:8080 VAULTARA_API_KEY=your-key \
//!   cargo run --example multi_tenant_admin

use vaultaris_sdk::VaultarisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    // --- 1. List all tenants ---
    println!("=== Tenant Overview ===");
    let mut page = 1i64;
    let per_page = 50i64;
    let mut all_tenants = Vec::new();

    loop {
        let result = client.list_tenants(page, per_page).await?;
        let has_next = result.has_next();
        all_tenants.extend(result.data);
        if !has_next {
            break;
        }
        page += 1;
    }

    println!("Found {} tenant(s):\n", all_tenants.len());

    for tenant in &all_tenants {
        println!("  {} / {} ({})", tenant.name, tenant.slug, tenant.id);

        // 2. Per-tenant stats
        match client.get_tenant_overview(&tenant.id.to_string()).await {
            Ok(stats) => {
                println!(
                    "     Users: {} active / {} total | Active sessions: {}",
                    stats.active_users, stats.total_users, stats.active_sessions
                );
                println!(
                    "     Auth attempts: {} | Failed: {}",
                    stats.total_authentications, stats.failed_authentications
                );
            }
            Err(e) => println!("     (stats unavailable: {})", e),
        }

        // 3. List all users in this tenant
        match client.collect_users(&tenant.id.to_string()).await {
            Ok(users) => {
                println!("     Users collected: {}", users.len());

                // Flag locked-out users
                let locked: Vec<_> = users.iter().filter(|u| u.locked_until.is_some()).collect();
                if !locked.is_empty() {
                    println!("     ⚠ Locked-out accounts ({}):", locked.len());
                    for u in &locked {
                        println!(
                            "       - {} ({}) — locked until {:?}",
                            u.username, u.id, u.locked_until
                        );
                    }
                }
            }
            Err(e) => println!("     (user list unavailable: {})", e),
        }

        println!();
    }

    // --- 4. Demonstrate cross-tenant user search by querying a specific tenant ---
    if let Some(first_tenant) = all_tenants.first() {
        let tid = first_tenant.id.to_string();
        println!(
            "=== Session Management for tenant '{}' ===",
            first_tenant.name
        );

        // List active sessions
        match client.list_sessions(&tid, 1, 20).await {
            Ok(sessions) => {
                println!("Active sessions (page 1): {}", sessions.data.len());
                for s in sessions.data.iter().take(5) {
                    println!(
                        "  Session {} — user {} — expires {}",
                        s.session_id, s.user_id, s.expires_at
                    );
                }
                if sessions.total > 20 {
                    println!("  ... and {} more", sessions.total - 20);
                }
            }
            Err(e) => println!("  (sessions unavailable: {})", e),
        }

        // 5. Audit log — last 10 entries
        println!("\n=== Audit Log (last 10) ===");
        match client.list_audit_logs(&tid, 1, 10).await {
            Ok(logs) => {
                for log in &logs.data {
                    println!(
                        "  [{}] {} on {} — actor: {:?}",
                        log.created_at.format("%Y-%m-%d %H:%M:%S"),
                        log.action,
                        log.resource_type,
                        log.actor_id
                    );
                }
            }
            Err(e) => println!("  (audit log unavailable: {})", e),
        }

        // 6. Security stats
        println!("\n=== Security Stats ===");
        match client.get_security_stats(&tid).await {
            Ok(s) => {
                println!("  Blocked attempts:        {}", s.blocked_attempts);
                println!("  Locked accounts:         {}", s.locked_accounts);
                println!("  Suspicious activities:   {}", s.suspicious_activities);
                println!("  Password resets:         {}", s.password_resets);
                println!("  MFA enrollments:         {}", s.mfa_enrollments);
            }
            Err(e) => println!("  (security stats unavailable: {})", e),
        }
    }

    Ok(())
}

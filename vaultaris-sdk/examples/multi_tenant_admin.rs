//! Multi-tenant admin dashboard — list tenants, inspect stats, audit, sessions.
//!
//! Run with:
//!   VAULTARIS_URL=http://localhost:8080 VAULTARIS_API_KEY=your-key \
//!   cargo run --example multi_tenant_admin

use vaultaris_sdk::{Pagination, StatsQuery, VaultarisClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultarisClient::from_env()?;

    println!("=== Tenant Overview ===");
    let mut pagination = Pagination::new(1, 50);
    let mut all_tenants = Vec::new();
    loop {
        let result = client.list_tenants(pagination).await?;
        let has_next = result.has_next();
        all_tenants.extend(result.data);
        if !has_next {
            break;
        }
        pagination.page += 1;
    }
    println!("Found {} tenant(s):\n", all_tenants.len());

    for tenant in &all_tenants {
        println!("  {} / {} ({})", tenant.name, tenant.slug, tenant.id);
        match client.tenant_overview(tenant.id).await {
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
            Err(e) => println!("     (stats unavailable: {e})"),
        }
        match client.collect_users(tenant.id).await {
            Ok(users) => {
                println!("     Users collected: {}", users.len());
                let locked: Vec<_> = users.iter().filter(|u| u.locked_until.is_some()).collect();
                if !locked.is_empty() {
                    println!("     Locked-out accounts ({}):", locked.len());
                    for u in &locked {
                        println!(
                            "       - {} ({}) — locked until {:?}",
                            u.username, u.id, u.locked_until
                        );
                    }
                }
            }
            Err(e) => println!("     (user list unavailable: {e})"),
        }
        println!();
    }

    if let Some(first_tenant) = all_tenants.first() {
        let tid = first_tenant.id;
        println!(
            "=== Session Management for tenant '{}' ===",
            first_tenant.name
        );

        match client.list_sessions(tid, Pagination::new(1, 20)).await {
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
            Err(e) => println!("  (sessions unavailable: {e})"),
        }

        println!("\n=== Audit Log (last 10) ===");
        match client.list_audit_logs(tid, Pagination::new(1, 10)).await {
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
            Err(e) => println!("  (audit log unavailable: {e})"),
        }

        println!("\n=== Security Stats (last 7d) ===");
        match client.security_stats(tid, &StatsQuery::last_7d()).await {
            Ok(s) => {
                println!("  Blocked attempts:        {}", s.blocked_attempts);
                println!("  Locked accounts:         {}", s.locked_accounts);
                println!("  Suspicious activities:   {}", s.suspicious_activities);
                println!("  Password resets:         {}", s.password_resets);
                println!("  MFA enrollments:         {}", s.mfa_enrollments);
            }
            Err(e) => println!("  (security stats unavailable: {e})"),
        }
    }

    Ok(())
}

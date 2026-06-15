//! Storage migration functions missing a version sentinel guard.
//!
//! A `pub fn migrate` / `pub fn upgrade_storage` / `pub fn migrate_v*` in a
//! `#[contractimpl]` block that writes to storage without first reading a
//! version/schema key can corrupt data if called twice or out of order.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Visibility};

const CHECK_NAME: &str = "migration-guard-missing";

fn is_migration_fn(name: &str) -> bool {
    name == "migrate"
        || name == "upgrade_storage"
        || name.starts_with("migrate_v")
        || name.starts_with("migrate_")
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn is_storage_set(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

/// Returns true if the method call looks like a version/schema sentinel read:
/// `.get(...)`, `.has(...)`, `.get_unchecked(...)` on any storage tier where
/// the key argument contains "version", "schema", or "migration".
fn is_version_read(m: &ExprMethodCall) -> bool {
    let method = m.method.to_string();
    if !matches!(method.as_str(), "get" | "has" | "get_unchecked") {
        return false;
    }
    if !receiver_chain_contains_storage(&m.receiver) {
        return false;
    }
    // Inspect the first argument for a version/schema/migration hint.
    if let Some(arg) = m.args.first() {
        let arg_str = quote_expr(arg).to_string().to_lowercase();
        return arg_str.contains("version")
            || arg_str.contains("schema")
            || arg_str.contains("migration");
    }
    false
}

fn quote_expr(expr: &Expr) -> String {
    match expr {
        Expr::Reference(r) => quote_expr(&r.expr),
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            _ => String::new(),
        },
        Expr::Macro(m) => m
            .mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Scan a block for (version_read_before_set, has_set).
struct MigrationScan {
    version_read_seen: bool,
    storage_set_seen: bool,
    first_set_line: usize,
    /// True once we've seen a version read; used to track ordering.
    version_read_before_set: bool,
}

impl MigrationScan {
    fn new() -> Self {
        Self {
            version_read_seen: false,
            storage_set_seen: false,
            first_set_line: 0,
            version_read_before_set: false,
        }
    }
}

impl<'ast> Visit<'ast> for MigrationScan {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_version_read(i) {
            self.version_read_seen = true;
            if !self.storage_set_seen {
                self.version_read_before_set = true;
            }
        }
        if is_storage_set(i) && !self.storage_set_seen {
            self.storage_set_seen = true;
            self.first_set_line = i.span().start().line;
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn scan_block(block: &Block) -> MigrationScan {
    let mut s = MigrationScan::new();
    s.visit_block(block);
    s
}

pub struct MigrationGuardCheck;

impl Check for MigrationGuardCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let name = method.sig.ident.to_string();
            if !is_migration_fn(&name) {
                continue;
            }
            let scan = scan_block(&method.block);
            if !scan.storage_set_seen {
                // No storage writes — nothing to guard.
                continue;
            }
            if scan.version_read_before_set {
                continue;
            }
            let line = if scan.first_set_line > 0 {
                scan.first_set_line
            } else {
                method.sig.fn_token.span().start().line
            };
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: name.clone(),
                description: format!(
                    "Migration function `{name}` writes to storage without first reading a \
                     version/schema sentinel key. Calling this function twice or out of order \
                     can corrupt contract state. Read and assert the current schema version \
                     before performing any storage writes, then update the version key."
                ),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_migrate_without_version_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const OLD_KEY: soroban_sdk::Symbol = symbol_short!("old");
const NEW_KEY: soroban_sdk::Symbol = symbol_short!("new");
#[contractimpl]
impl C {
    pub fn migrate(env: Env) {
        let val: u32 = env.storage().persistent().get(&OLD_KEY).unwrap();
        env.storage().persistent().set(&NEW_KEY, &val);
        env.storage().persistent().remove(&OLD_KEY);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MigrationGuardCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("version/schema sentinel"));
        Ok(())
    }

    #[test]
    fn flags_upgrade_storage_without_version_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const KEY: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn upgrade_storage(env: Env) {
        env.storage().instance().set(&KEY, &42u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MigrationGuardCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_when_version_read_precedes_set() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const VERSION_KEY: soroban_sdk::Symbol = symbol_short!("version");
const DATA_KEY: soroban_sdk::Symbol = symbol_short!("data");
#[contractimpl]
impl C {
    pub fn migrate(env: Env) {
        let v: u32 = env.storage().instance().get(&VERSION_KEY).unwrap();
        assert_eq!(v, 1u32);
        env.storage().instance().set(&DATA_KEY, &99u32);
        env.storage().instance().set(&VERSION_KEY, &2u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MigrationGuardCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_for_non_migration_fn() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const KEY: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn update(env: Env) {
        env.storage().persistent().set(&KEY, &1u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MigrationGuardCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_migrate_v2_without_version_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const KEY: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn migrate_v2(env: Env) {
        env.storage().persistent().set(&KEY, &2u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MigrationGuardCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_when_no_storage_writes() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn migrate(env: Env) {
        // read-only migration check
        let _v: Option<u32> = env.storage().instance().get(&soroban_sdk::symbol_short!("k"));
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MigrationGuardCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

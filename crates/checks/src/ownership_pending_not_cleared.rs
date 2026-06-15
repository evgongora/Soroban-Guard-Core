//! Detects `accept_ownership` functions that write a new admin/owner to storage
//! but do not `remove` or overwrite the pending-ownership storage key.
//!
//! In a two-step ownership transfer the pending key must be cleared after
//! `accept_ownership` succeeds; otherwise the same authorization can be replayed.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ownership-pending-not-cleared";

/// Function names that complete a two-step ownership transfer.
const ACCEPT_FN_NAMES: &[&str] = &[
    "accept_ownership",
    "accept_admin",
    "claim_ownership",
    "finalize_transfer",
];

pub struct OwnershipPendingNotClearedCheck;

impl Check for OwnershipPendingNotClearedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !ACCEPT_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }

            let mut scan = StorageScan::default();
            scan.visit_block(&method.block);

            // Flag if the function writes an admin/owner key but never removes
            // or overwrites the pending key.
            if scan.writes_admin && !scan.clears_pending {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "`{fn_name}` writes the new owner/admin to storage but does not \
                         `remove` or overwrite the pending-ownership key. The pending \
                         authorization can be replayed to transfer ownership again."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct StorageScan {
    writes_admin: bool,
    clears_pending: bool,
}

fn key_expr_text(expr: &Expr) -> String {
    match expr {
        Expr::Reference(r) => key_expr_text(&r.expr),
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
        _ => String::new(),
    }
}

fn is_admin_key(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("admin") || t.contains("owner") || t.contains("operator")
}

fn is_pending_key(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("pending") || t.contains("proposed") || t.contains("candidate")
}

fn receiver_chain_contains(expr: &Expr, method: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == method {
                return true;
            }
            receiver_chain_contains(&m.receiver, method)
        }
        Expr::Field(f) => receiver_chain_contains(&f.base, method),
        _ => false,
    }
}

fn is_storage_call(m: &ExprMethodCall) -> bool {
    receiver_chain_contains(&m.receiver, "storage")
}

impl<'ast> Visit<'ast> for StorageScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_call(i) {
            let method = i.method.to_string();
            if let Some(key_arg) = i.args.first() {
                let key_text = key_expr_text(key_arg);
                match method.as_str() {
                    "set" => {
                        if is_admin_key(&key_text) {
                            self.writes_admin = true;
                        }
                        if is_pending_key(&key_text) {
                            self.clears_pending = true;
                        }
                    }
                    "remove" if is_pending_key(&key_text) => {
                        self.clears_pending = true;
                    }
                    _ => {}
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_accept_ownership_without_clearing_pending() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env) {
        let new_owner: Address = env.storage().instance().get(&"pending_owner").unwrap();
        new_owner.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
        // ❌ pending_owner key is never removed
    }
}
"#,
        )?;
        let hits = OwnershipPendingNotClearedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_when_pending_key_removed() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env) {
        let new_owner: Address = env.storage().instance().get(&"pending_owner").unwrap();
        new_owner.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
        env.storage().instance().remove(&"pending_owner");
    }
}
"#,
        )?;
        let hits = OwnershipPendingNotClearedCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_pending_key_overwritten() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env) {
        let new_owner: Address = env.storage().instance().get(&"pending_owner").unwrap();
        new_owner.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
        env.storage().instance().set(&"pending_owner", &Address::default());
    }
}
"#,
        )?;
        let hits = OwnershipPendingNotClearedCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unrelated_function() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.storage().instance().set(&"pending_owner", &new_owner);
    }
}
"#,
        )?;
        let hits = OwnershipPendingNotClearedCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

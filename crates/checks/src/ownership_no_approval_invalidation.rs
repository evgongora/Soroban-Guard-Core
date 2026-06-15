//! Detects `transfer_ownership` functions that do not include a storage
//! operation to clear or invalidate existing allowances/approvals after the
//! transfer.
//!
//! When ownership changes, token approvals or operator permissions signed by
//! the old owner should be invalidated to prevent lingering authorization.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ownership-no-approval-invalidation";

/// Function names that perform an ownership transfer.
const TRANSFER_FN_NAMES: &[&str] = &[
    "transfer_ownership",
    "set_owner",
    "set_admin",
    "change_owner",
    "change_admin",
];

pub struct OwnershipNoApprovalInvalidationCheck;

impl Check for OwnershipNoApprovalInvalidationCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !TRANSFER_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }

            let mut scan = ApprovalScan::default();
            scan.visit_block(&method.block);

            if scan.writes_owner && !scan.clears_approvals {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "`{fn_name}` transfers ownership but does not clear existing \
                         allowances or approvals. Permissions granted by the old owner \
                         remain valid and can be exploited by the new owner or third parties."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct ApprovalScan {
    writes_owner: bool,
    clears_approvals: bool,
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

fn is_owner_key(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("admin") || t.contains("owner") || t.contains("operator")
}

fn is_approval_key(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("allow") || t.contains("approv") || t.contains("permit") || t.contains("operator")
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

impl<'ast> Visit<'ast> for ApprovalScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_call(i) {
            let method = i.method.to_string();
            if let Some(key_arg) = i.args.first() {
                let key_text = key_expr_text(key_arg);
                match method.as_str() {
                    "set" => {
                        if is_owner_key(&key_text) {
                            self.writes_owner = true;
                        }
                        if is_approval_key(&key_text) {
                            self.clears_approvals = true;
                        }
                    }
                    "remove" if is_approval_key(&key_text) => {
                        self.clears_approvals = true;
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
    fn flags_transfer_without_clearing_approvals() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
        // ❌ no allowance/approval clearing
    }
}
"#,
        )?;
        let hits = OwnershipNoApprovalInvalidationCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_when_allowance_removed() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
        env.storage().instance().remove(&"allowance");
    }
}
"#,
        )?;
        let hits = OwnershipNoApprovalInvalidationCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_approval_key_overwritten() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage().instance().set(&"owner", &new_owner);
        env.storage().instance().set(&"approvals", &0u32);
    }
}
"#,
        )?;
        let hits = OwnershipNoApprovalInvalidationCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_fn_that_does_not_write_owner() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        // only reads, no write
        let _ = env.storage().instance().get::<_, Address>(&"owner");
    }
}
"#,
        )?;
        let hits = OwnershipNoApprovalInvalidationCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

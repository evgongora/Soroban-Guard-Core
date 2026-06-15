//! `accept_ownership` / `claim_ownership` without verifying the pending owner from storage.
//!
//! Two-step ownership transfer must read the pending-owner key from storage and
//! verify the caller matches before writing the new admin. Without this check,
//! any address can claim ownership.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Visibility};

const CHECK_NAME: &str = "ownership-transfer-unchecked";

fn is_accept_fn(name: &str) -> bool {
    matches!(name, "accept_ownership" | "claim_ownership")
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

fn key_looks_like_pending(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("pending") || lower.contains("proposed") || lower.contains("nominee")
}

fn key_looks_like_admin(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("admin") || lower.contains("owner") || lower.contains("role")
}

fn extract_key_str(arg: &Expr) -> String {
    let inner = match arg {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    match inner {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            _ => String::new(),
        },
        Expr::Macro(m) => m.mac.tokens.to_string(),
        _ => String::new(),
    }
}

#[derive(Default)]
struct OwnershipScan {
    pending_read: bool,
    admin_write: bool,
    admin_write_line: usize,
    /// True if the pending read precedes the first admin write.
    pending_before_write: bool,
    admin_write_seen: bool,
}

impl<'ast> Visit<'ast> for OwnershipScan {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let method = i.method.to_string();
        if matches!(method.as_str(), "get" | "has" | "get_unchecked")
            && receiver_chain_contains_storage(&i.receiver)
        {
            if let Some(arg) = i.args.first() {
                let key = extract_key_str(arg);
                if key_looks_like_pending(&key) {
                    self.pending_read = true;
                    if !self.admin_write_seen {
                        self.pending_before_write = true;
                    }
                }
            }
        }
        if method == "set" && receiver_chain_contains_storage(&i.receiver) {
            if let Some(arg) = i.args.first() {
                let key = extract_key_str(arg);
                if key_looks_like_admin(&key) && !self.admin_write_seen {
                    self.admin_write = true;
                    self.admin_write_seen = true;
                    self.admin_write_line = i.span().start().line;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct OwnershipTransferCheck;

impl Check for OwnershipTransferCheck {
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
            if !is_accept_fn(&name) {
                continue;
            }
            let mut scan = OwnershipScan::default();
            scan.visit_block(&method.block);

            if !scan.admin_write {
                continue; // no admin write — nothing to guard
            }
            if scan.pending_before_write {
                continue; // safe: pending owner verified before write
            }
            let line = if scan.admin_write_line > 0 {
                scan.admin_write_line
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
                    "Method `{name}` writes a new admin/owner key without first reading the \
                     pending-owner key from storage. Any address can call this function and \
                     claim ownership. Read and verify the pending owner from storage before \
                     updating the admin key."
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
    fn flags_accept_ownership_without_pending_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env, new_owner: Address) {
        // BUG: writes admin without reading pending_owner first
        env.storage().instance().set(&symbol_short!("admin"), &new_owner);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OwnershipTransferCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("pending-owner"));
        Ok(())
    }

    #[test]
    fn flags_claim_ownership_without_pending_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn claim_ownership(env: Env, caller: Address) {
        env.storage().persistent().set(&symbol_short!("owner"), &caller);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OwnershipTransferCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_when_pending_read_precedes_write() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env) {
        let pending: Address = env.storage().instance()
            .get(&symbol_short!("pending_owner")).unwrap();
        env.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &pending);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OwnershipTransferCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_when_no_admin_write() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env) -> Address {
        env.storage().instance().get(&symbol_short!("pending_owner")).unwrap()
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OwnershipTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_private_fn() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    fn accept_ownership(env: Env, new_owner: Address) {
        env.storage().instance().set(&symbol_short!("admin"), &new_owner);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OwnershipTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

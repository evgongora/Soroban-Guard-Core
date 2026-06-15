//! Instance storage remove on critical key (self-destruct risk).
//!
//! Calling env.storage().instance().remove() on a key that holds critical contract state
//! (e.g. admin, owner, paused flag, total supply) without strict authorization and a
//! re-initialization guard can permanently brick the contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprLit, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "instance-remove-critical";

/// Critical state key patterns that should not be removed without authorization
const CRITICAL_PATTERNS: &[&str] = &["admin", "owner", "paused", "supply", "initialized"];

/// Flags storage().instance().remove() calls on keys whose literal name matches a
/// critical-state pattern without require_auth in the same function.
pub struct InstanceRemoveCriticalCheck;

impl Check for InstanceRemoveCriticalCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Check if function has require_auth
            let mut auth_scan = AuthScan {
                has_require_auth: false,
            };
            auth_scan.visit_block(&method.block);

            // Scan for instance().remove() calls on critical keys
            let mut v = RemoveVisitor {
                fn_name: fn_name.clone(),
                has_require_auth: auth_scan.has_require_auth,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

struct AuthScan {
    has_require_auth: bool,
}

impl Visit<'_> for AuthScan {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "require_auth" {
            self.has_require_auth = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct RemoveVisitor<'a> {
    fn_name: String,
    has_require_auth: bool,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for RemoveVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "remove" && is_instance_storage_call(i) {
            // Check if the key is a critical literal
            if let Some(key_str) = extract_key_literal(i) {
                let key_lower = key_str.to_lowercase();
                if CRITICAL_PATTERNS
                    .iter()
                    .any(|pattern| key_lower.contains(pattern))
                    && !self.has_require_auth
                {
                    self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Function `{}` calls storage().instance().remove() on critical key '{}' \
                                 without require_auth(). Removing critical state can permanently brick \
                                 the contract. Add strict authorization and re-initialization guards.",
                                self.fn_name, key_str
                            ),
                        });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_instance_storage_call(m: &ExprMethodCall) -> bool {
    receiver_chain_contains(&m.receiver, "instance")
        && receiver_chain_contains(&m.receiver, "storage")
}

fn receiver_chain_contains(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == name || receiver_chain_contains(&m.receiver, name),
        Expr::Field(f) => receiver_chain_contains(&f.base, name),
        _ => false,
    }
}

fn extract_key_literal(call: &ExprMethodCall) -> Option<String> {
    if let Some(first_arg) = call.args.first() {
        match first_arg {
            Expr::Lit(ExprLit {
                lit: Lit::Str(lit_str),
                ..
            }) => {
                return Some(lit_str.value());
            }
            Expr::Reference(r) => {
                match &*r.expr {
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(lit_str),
                        ..
                    }) => {
                        return Some(lit_str.value());
                    }
                    Expr::Call(c) => {
                        // Handle &Symbol::new(&env, "key") pattern where Symbol::new is a Call, not MethodCall
                        if let Expr::Path(p) = &*c.func {
                            if let Some(last_seg) = p.path.segments.last() {
                                if last_seg.ident == "new" && c.args.len() >= 2 {
                                    if let Some(Expr::Lit(ExprLit {
                                        lit: Lit::Str(lit_str),
                                        ..
                                    })) = c.args.iter().nth(1)
                                    {
                                        return Some(lit_str.value());
                                    }
                                }
                            }
                        }
                    }
                    Expr::MethodCall(m)
                        // Handle &Symbol::new(&env, "key") pattern
                        if m.method == "new" && m.args.len() >= 2 => {
                            if let Some(Expr::Lit(ExprLit {
                                lit: Lit::Str(lit_str),
                                ..
                            })) = m.args.iter().nth(1)
                            {
                                return Some(lit_str.value());
                            }
                        }
                    _ => {}
                }
            }
            Expr::Call(c) => {
                // Handle Symbol::new(&env, "key") pattern (without reference)
                if let Expr::Path(p) = &*c.func {
                    if let Some(last_seg) = p.path.segments.last() {
                        if last_seg.ident == "new" && c.args.len() >= 2 {
                            if let Some(Expr::Lit(ExprLit {
                                lit: Lit::Str(lit_str),
                                ..
                            })) = c.args.iter().nth(1)
                            {
                                return Some(lit_str.value());
                            }
                        }
                    }
                }
            }
            Expr::MethodCall(m)
                // Handle Symbol::new(&env, "key") pattern (without reference)
                if m.method == "new" && m.args.len() >= 2 => {
                    if let Some(Expr::Lit(ExprLit {
                        lit: Lit::Str(lit_str),
                        ..
                    })) = m.args.iter().nth(1)
                    {
                        return Some(lit_str.value());
                    }
                }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_remove_admin_without_auth() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn remove_admin(env: Env) {
        env.storage().instance().remove(&Symbol::new(&env, "admin"));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = InstanceRemoveCriticalCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn allows_remove_admin_with_auth() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn remove_admin(env: Env) {
        env.require_auth();
        env.storage().instance().remove(&Symbol::new(&env, "admin"));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = InstanceRemoveCriticalCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_remove_owner_without_auth() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn clear_owner(env: Env) {
        env.storage().instance().remove(&Symbol::new(&env, "owner"));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = InstanceRemoveCriticalCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_remove_non_critical_key() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn clear_cache(env: Env) {
        env.storage().instance().remove(&Symbol::new(&env, "cache"));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = InstanceRemoveCriticalCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

//! Unauth sensitive storage read (data exposure).
//!
//! A public function that reads and returns a sensitive storage value (e.g. admin address,
//! private key material, secret nonce) without require_auth exposes that data to any
//! on-chain observer or off-chain caller.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprLit, ExprMethodCall, File, Lit, ReturnType};

const CHECK_NAME: &str = "unauth-sensitive-read";

/// Sensitive key patterns that should not be exposed without authorization
const SENSITIVE_PATTERNS: &[&str] = &["admin", "owner", "secret", "key", "priv"];

/// Flags public functions that return a value read from storage under a key whose name
/// contains admin, owner, secret, key, or priv without any require_auth call.
pub struct UnauthSensitiveReadCheck;

impl Check for UnauthSensitiveReadCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Skip if function returns unit type ()
            if matches!(method.sig.output, ReturnType::Default) {
                continue;
            }

            // Check if function has require_auth
            let mut auth_scan = AuthScan {
                has_require_auth: false,
            };
            auth_scan.visit_block(&method.block);

            if auth_scan.has_require_auth {
                continue;
            }

            // Scan for storage get calls on sensitive keys
            let mut v = SensitiveReadVisitor {
                fn_name: fn_name.clone(),
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

struct SensitiveReadVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for SensitiveReadVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "get" && is_storage_call(i) {
            // Check if the key is a sensitive literal
            if let Some(key_str) = extract_key_literal(i) {
                let key_lower = key_str.to_lowercase();
                if SENSITIVE_PATTERNS
                    .iter()
                    .any(|pattern| key_lower.contains(pattern))
                {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Function `{}` reads and returns sensitive storage key '{}' without \
                             require_auth(). This exposes sensitive data to any caller. Add \
                             authorization checks before returning sensitive values.",
                            self.fn_name, key_str
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_storage_call(m: &ExprMethodCall) -> bool {
    receiver_chain_contains(&m.receiver, "storage")
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
    fn detects_unauth_admin_read() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "admin")).unwrap()
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = UnauthSensitiveReadCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn allows_auth_admin_read() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_admin(env: Env) -> Address {
        env.require_auth();
        env.storage().instance().get(&Symbol::new(&env, "admin")).unwrap()
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = UnauthSensitiveReadCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_secret_key_read() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_secret(env: Env) -> u64 {
        env.storage().persistent().get(&Symbol::new(&env, "secret_key")).unwrap()
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = UnauthSensitiveReadCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_non_sensitive_read() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_balance(env: Env) -> i128 {
        env.storage().persistent().get(&Symbol::new(&env, "balance")).unwrap()
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = UnauthSensitiveReadCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_void_function() {
        let code = r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn log_admin(env: Env) {
        let _admin = env.storage().instance().get(&Symbol::new(&env, "admin"));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = UnauthSensitiveReadCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

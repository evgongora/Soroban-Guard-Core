//! Detects `sha256(address + secret)` where both inputs may be known to an attacker.
//!
//! Using `env.crypto().sha256()` with an `Address` parameter concatenated with a
//! storage-read value is vulnerable: if the secret is also stored or emitted, an
//! attacker can reconstruct the committed value.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Local, Pat, Type};

const CHECK_NAME: &str = "weak-commitment-known";

/// Flags `env.crypto().sha256(...)` calls where the argument involves an `Address`
/// parameter and a storage-read value, making both inputs potentially known.
pub struct WeakCommitmentKnownCheck;

impl Check for WeakCommitmentKnownCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            // Collect Address-typed parameter names
            let addr_params: Vec<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    if let FnArg::Typed(pt) = arg {
                        if type_is_address(&pt.ty) {
                            if let Pat::Ident(pi) = &*pt.pat {
                                return Some(pi.ident.to_string());
                            }
                        }
                    }
                    None
                })
                .collect();

            let mut scan = Sha256Scan {
                fn_name,
                addr_params,
                storage_vars: Vec::new(),
                out: &mut out,
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

fn type_is_address(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "Address";
        }
    }
    false
}

struct Sha256Scan<'a> {
    fn_name: String,
    addr_params: Vec<String>,
    storage_vars: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for Sha256Scan<'_> {
    fn visit_local(&mut self, i: &'ast Local) {
        if let Some(init) = &i.init {
            if let Expr::MethodCall(m) = &*init.expr {
                if is_storage_get(m) {
                    let pat = match &i.pat {
                        Pat::Type(pt) => &*pt.pat,
                        p => p,
                    };
                    if let Pat::Ident(pi) = pat {
                        self.storage_vars.push(pi.ident.to_string());
                    }
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_sha256_call(i) {
            let arg_src = i
                .args
                .iter()
                .map(|e| e.to_token_stream().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let has_addr = self
                .addr_params
                .iter()
                .any(|p| arg_src.contains(p.as_str()));
            let has_storage_read = (arg_src.contains("storage") && arg_src.contains("get"))
                || self
                    .storage_vars
                    .iter()
                    .any(|v| arg_src.contains(v.as_str()));

            if has_addr && has_storage_read {
                let line = i.span().start().line;
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Method `{}` passes an `Address` parameter and a storage-read value \
                         to `sha256()`. If the secret is stored or emitted, an attacker can \
                         reconstruct the commitment. Use a random nonce instead.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_storage_get(m: &ExprMethodCall) -> bool {
    if !matches!(
        m.method.to_string().as_str(),
        "get" | "get_unchecked" | "unwrap" | "unwrap_or" | "unwrap_or_default"
    ) {
        return false;
    }
    // Check receiver chain for storage.get or unwrap wrapping storage.get
    fn contains_storage_get(expr: &Expr) -> bool {
        match expr {
            Expr::MethodCall(m) => {
                if m.method == "get" || m.method == "get_unchecked" {
                    return receiver_chain_has_storage(&m.receiver);
                }
                contains_storage_get(&m.receiver)
            }
            _ => false,
        }
    }
    fn receiver_chain_has_storage(expr: &Expr) -> bool {
        match expr {
            Expr::MethodCall(m) => m.method == "storage" || receiver_chain_has_storage(&m.receiver),
            _ => false,
        }
    }
    if (m.method == "get" || m.method == "get_unchecked") && receiver_chain_has_storage(&m.receiver)
    {
        return true;
    }
    contains_storage_get(&m.receiver)
}

fn is_sha256_call(m: &ExprMethodCall) -> bool {
    if m.method != "sha256" {
        return false;
    }
    if let Expr::MethodCall(inner) = &*m.receiver {
        return inner.method == "crypto";
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_sha256_with_address_and_storage_read() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn commit(env: Env, user: Address) {
        let secret = env.storage().instance().get(&user).unwrap();
        let hash = env.crypto().sha256(&(user, secret));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = WeakCommitmentKnownCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn allows_sha256_with_nonce_only() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn commit(env: Env, data: Bytes, nonce: Bytes) {
        let hash = env.crypto().sha256(&(data, nonce));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = WeakCommitmentKnownCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_without_storage_read() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn commit(env: Env, user: Address, secret: Bytes) {
        let hash = env.crypto().sha256(&(user, secret));
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = WeakCommitmentKnownCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}

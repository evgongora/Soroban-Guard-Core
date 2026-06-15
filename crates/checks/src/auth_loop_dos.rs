//! `require_auth()` called in a loop over a storage-backed Vec (DoS vector).
//!
//! Iterating a Vec retrieved from storage and calling `require_auth()` on each
//! element scales with list size. An attacker who can grow the list can make
//! every subsequent call prohibitively expensive, DoS-ing the contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, ExprMethodCall, File, Local, Pat};

const CHECK_NAME: &str = "auth-loop-dos";

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

/// True if the expression is (or unwraps) a storage `.get(...)` call.
fn expr_is_storage_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            let name = m.method.to_string();
            if matches!(
                name.as_str(),
                "get"
                    | "get_unchecked"
                    | "unwrap"
                    | "unwrap_or"
                    | "unwrap_or_else"
                    | "unwrap_or_default"
                    | "expect"
            ) {
                // Either this call itself is a storage get, or its receiver is.
                if matches!(name.as_str(), "get" | "get_unchecked")
                    && receiver_chain_contains_storage(&m.receiver)
                {
                    return true;
                }
                return expr_is_storage_get(&m.receiver);
            }
            false
        }
        _ => false,
    }
}

/// Visitor that detects `require_auth()` calls inside a for-loop body.
struct LoopBodyVisitor {
    found_require_auth: bool,
    line: usize,
}

impl<'ast> Visit<'ast> for LoopBodyVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if !self.found_require_auth
            && matches!(
                i.method.to_string().as_str(),
                "require_auth" | "require_auth_for_args"
            )
        {
            self.found_require_auth = true;
            self.line = i.span().start().line;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct AuthLoopVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
    storage_bindings: Vec<String>,
}

impl<'ast> Visit<'ast> for AuthLoopVisitor<'ast> {
    fn visit_local(&mut self, i: &'ast Local) {
        if let Some(init) = &i.init {
            if expr_is_storage_get(&init.expr) {
                let pat = match &i.pat {
                    Pat::Type(pt) => &*pt.pat,
                    p => p,
                };
                if let Pat::Ident(pi) = pat {
                    self.storage_bindings.push(pi.ident.to_string());
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        // Check if the iterable comes from storage (direct or via variable).
        let is_storage = expr_is_storage_get(&i.expr) || {
            if let Expr::Path(p) = &*i.expr {
                p.path
                    .get_ident()
                    .is_some_and(|id| self.storage_bindings.contains(&id.to_string()))
            } else {
                false
            }
        };
        if is_storage {
            let mut body_scan = LoopBodyVisitor {
                found_require_auth: false,
                line: 0,
            };
            body_scan.visit_block(&i.body);
            if body_scan.found_require_auth {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: body_scan.line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Method `{}` calls `require_auth()` inside a loop over a \
                         storage-backed Vec. The gas cost scales with the list size; an \
                         attacker who can append to the list can DoS the contract by making \
                         every call prohibitively expensive. Consider a single-signer or \
                         threshold pattern instead.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_for_loop(self, i);
    }
}

pub struct AuthLoopDosCheck;

impl Check for AuthLoopDosCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = AuthLoopVisitor {
                fn_name,
                out: &mut out,
                storage_bindings: Vec::new(),
            };
            v.visit_block(&method.block);
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
    fn flags_require_auth_in_loop_over_storage_vec() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn multi_auth(env: Env) {
        let signers: Vec<Address> = env.storage().persistent()
            .get(&symbol_short!("signers")).unwrap();
        for signer in signers {
            signer.require_auth();
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AuthLoopDosCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("DoS"));
        Ok(())
    }

    #[test]
    fn no_finding_for_loop_over_literal_range() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn process(env: Env, signer: Address) {
        for _ in 0..3u32 {
            signer.require_auth();
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AuthLoopDosCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_for_storage_loop_without_auth() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn tally(env: Env) -> u32 {
        let list: Vec<Address> = env.storage().persistent()
            .get(&symbol_short!("list")).unwrap();
        let mut count = 0u32;
        for _ in list {
            count += 1;
        }
        count
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AuthLoopDosCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_require_auth_for_args_in_storage_loop() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn approve_all(env: Env) {
        let approvers: Vec<Address> = env.storage().instance()
            .get(&symbol_short!("approvers")).unwrap_or_default();
        for approver in approvers {
            approver.require_auth_for_args(soroban_sdk::vec![&env]);
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AuthLoopDosCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}

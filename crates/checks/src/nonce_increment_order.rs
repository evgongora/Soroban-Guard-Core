//! Detects nonce incremented after an external call/transfer instead of before.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "nonce-increment-order";

pub struct NonceIncrementOrderCheck;

impl Check for NonceIncrementOrderCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let stmts = &method.block.stmts;

            // Collect statement indices for nonce-set and external calls
            let mut nonce_set_idx: Option<usize> = None;
            let mut earliest_external_idx: Option<usize> = None;

            for (idx, stmt) in stmts.iter().enumerate() {
                let mut sv = StmtVisitor::default();
                sv.visit_stmt(stmt);

                if sv.has_nonce_set && nonce_set_idx.is_none() {
                    nonce_set_idx = Some(idx);
                }
                if sv.has_external_call && earliest_external_idx.is_none() {
                    earliest_external_idx = Some(idx);
                }
            }

            // Flag if there is a nonce set AND an external call that comes BEFORE it
            if let (Some(set_idx), Some(ext_idx)) = (nonce_set_idx, earliest_external_idx) {
                if ext_idx < set_idx {
                    let line = stmts[ext_idx].span().start().line;
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "`{fn_name}` performs an external call or token transfer before \
                             writing the incremented nonce back to storage. A reentrant caller \
                             can reuse the same nonce. Increment and store the nonce before \
                             any external interaction."
                        ),
                    });
                }
            }
        }
        out
    }
}

#[derive(Default)]
struct StmtVisitor {
    has_nonce_set: bool,
    has_external_call: bool,
}

fn is_nonce_storage_set(m: &ExprMethodCall) -> bool {
    if m.method != "set" {
        return false;
    }
    // Check if any argument looks like a nonce key
    for arg in &m.args {
        if expr_contains_nonce(arg) {
            return true;
        }
    }
    false
}

fn expr_contains_nonce(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => {
            let s = p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            s.to_lowercase().contains("nonce")
        }
        Expr::Reference(r) => expr_contains_nonce(&r.expr),
        Expr::Lit(l) => {
            if let syn::Lit::Str(ls) = &l.lit {
                ls.value().to_lowercase().contains("nonce")
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_external_call(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    matches!(
        name.as_str(),
        "invoke_contract" | "transfer" | "transfer_from" | "call"
    )
}

impl Visit<'_> for StmtVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_nonce_storage_set(i) {
            self.has_nonce_set = true;
        }
        if is_external_call(i) {
            self.has_external_call = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_external_call_before_nonce_set() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn execute(env: soroban_sdk::Env, nonce: u64) {
        let stored: u64 = env.storage().persistent().get(&"nonce").unwrap_or(0);
        // external call BEFORE nonce update — vulnerable
        token.transfer(&env, &from, &to, &amount);
        env.storage().persistent().set(&"nonce", &(stored + 1));
    }
}
"#,
        )?;
        let hits = NonceIncrementOrderCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_nonce_set_before_external_call() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn execute(env: soroban_sdk::Env, nonce: u64) {
        let stored: u64 = env.storage().persistent().get(&"nonce").unwrap_or(0);
        env.storage().persistent().set(&"nonce", &(stored + 1));
        token.transfer(&env, &from, &to, &amount);
    }
}
"#,
        )?;
        let hits = NonceIncrementOrderCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_no_external_call() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn bump_nonce(env: soroban_sdk::Env) {
        let n: u64 = env.storage().persistent().get(&"nonce").unwrap_or(0);
        env.storage().persistent().set(&"nonce", &(n + 1));
    }
}
"#,
        )?;
        let hits = NonceIncrementOrderCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

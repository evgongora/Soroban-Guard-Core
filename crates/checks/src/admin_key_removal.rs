//! Detects `persistent().remove(key)` on admin/owner/operator keys without a
//! subsequent `persistent().set(key, …)` in the same function body.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Local, Pat};

const CHECK_NAME: &str = "admin-key-removal";

/// Render an expression to a string for heuristic key-name matching.
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
        _ => String::new(),
    }
}

fn extract_symbol_string(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Macro(m) => {
            let tokens = m.mac.tokens.to_string();
            let trimmed = tokens.trim().trim_matches('"');
            Some(trimmed.to_string())
        }
        Expr::Call(c) => {
            if let Some(Expr::Lit(l)) = c.args.last() {
                if let syn::Lit::Str(s) = &l.lit {
                    return Some(s.value());
                }
            }
            None
        }
        Expr::Lit(l) => {
            if let syn::Lit::Str(s) = &l.lit {
                Some(s.value())
            } else {
                None
            }
        }
        _ => None,
    }
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

fn is_persistent_remove(m: &ExprMethodCall) -> bool {
    m.method == "remove"
        && receiver_chain_contains(&m.receiver, "persistent")
        && receiver_chain_contains(&m.receiver, "storage")
}

fn is_persistent_set(m: &ExprMethodCall) -> bool {
    m.method == "set"
        && receiver_chain_contains(&m.receiver, "persistent")
        && receiver_chain_contains(&m.receiver, "storage")
}

pub struct AdminKeyRemovalCheck;

impl Check for AdminKeyRemovalCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = RemovalScan::default();
            scan.visit_block(&method.block);

            for (line, key_text) in &scan.removals {
                // Safe if any persistent().set() follows with a matching key name
                let replaced = scan.sets.iter().any(|set_key| {
                    let k = set_key.to_lowercase();
                    let r = key_text.to_lowercase();
                    // same variable / literal, or both are admin-ish names
                    k == r || (is_admin_name(&k) && is_admin_name(&r))
                });
                if !replaced {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: *line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "`{}` calls `persistent().remove({})` on an admin key without \
                             atomically replacing it with `persistent().set(…)`. \
                             The contract will be permanently left without an admin.",
                            fn_name, key_text
                        ),
                    });
                }
            }
        }
        out
    }
}

fn is_admin_name(s: &str) -> bool {
    s.contains("admin") || s.contains("owner") || s.contains("operator")
}

#[derive(Default)]
struct RemovalScan {
    /// (line, key_text) for each admin-key persistent().remove() found
    removals: Vec<(usize, String)>,
    /// key_text for each persistent().set() found after a removal
    sets: Vec<String>,
    seen_removal: bool,
    /// local variable → resolved symbol string (e.g. `key` → `"admin"`)
    var_bindings: HashMap<String, String>,
}

impl<'ast> Visit<'ast> for RemovalScan {
    fn visit_local(&mut self, i: &'ast Local) {
        if let Some(init) = &i.init {
            if let Some(s) = extract_symbol_string(&init.expr) {
                let pat = match &i.pat {
                    Pat::Type(pt) => &*pt.pat,
                    p => p,
                };
                if let Pat::Ident(pi) = pat {
                    self.var_bindings.insert(pi.ident.to_string(), s);
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_persistent_remove(i) {
            if let Some(key_arg) = i.args.first() {
                let raw = quote_expr(key_arg);
                let resolved = self.var_bindings.get(&raw).cloned().unwrap_or(raw);
                if is_admin_name(&resolved) {
                    self.removals.push((i.span().start().line, resolved));
                    self.seen_removal = true;
                }
            }
        } else if self.seen_removal && is_persistent_set(i) {
            if let Some(key_arg) = i.args.first() {
                let raw = quote_expr(key_arg);
                let resolved = self.var_bindings.get(&raw).cloned().unwrap_or(raw);
                self.sets.push(resolved);
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
    fn flags_remove_admin_without_set() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn remove_admin(env: Env) {
        let key = symbol_short!("admin");
        env.storage().persistent().remove(&key);
    }
}
"#,
        )?;
        let hits = AdminKeyRemovalCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_remove_followed_by_set() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn rotate_admin(env: Env, new_admin: Address) {
        let key = symbol_short!("admin");
        env.storage().persistent().remove(&key);
        env.storage().persistent().set(&key, &new_admin);
    }
}
"#,
        )?;
        let hits = AdminKeyRemovalCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_owner_key_removal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn clear_owner(env: Env) {
        env.storage().persistent().remove(&"owner");
    }
}
"#,
        )?;
        let hits = AdminKeyRemovalCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_non_admin_key_removal() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn clear_counter(env: Env) {
        let key = symbol_short!("counter");
        env.storage().persistent().remove(&key);
    }
}
"#,
        )?;
        let hits = AdminKeyRemovalCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_temporary_remove_of_admin_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn clear_temp(env: Env) {
        let key = symbol_short!("admin");
        env.storage().temporary().remove(&key);
    }
}
"#,
        )?;
        // temporary() is not persistent() — should not flag
        let hits = AdminKeyRemovalCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

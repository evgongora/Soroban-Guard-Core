//! `deposit` / `fund` / `add` functions accepting a negative `i128` amount without a guard.
//!
//! A caller passing a negative amount to a deposit function effectively withdraws
//! funds while appearing to deposit. The amount must be checked > 0 before use.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, FnArg, Macro, Pat, Type, Visibility};

fn extract_first_macro_arg(mac: &Macro) -> proc_macro2::TokenStream {
    let mut result = proc_macro2::TokenStream::new();
    for tt in mac.tokens.clone().into_iter() {
        if let proc_macro2::TokenTree::Punct(p) = &tt {
            if p.as_char() == ',' {
                break;
            }
        }
        result.extend(std::iter::once(tt));
    }
    result
}

const CHECK_NAME: &str = "negative-deposit";

const DEPOSIT_NAMES: &[&str] = &["deposit", "fund", "add", "add_funds", "deposit_funds"];

fn is_deposit_fn(name: &str) -> bool {
    DEPOSIT_NAMES.contains(&name)
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

/// Collect parameter names that are typed `i128` (or `&i128`).
fn i128_param_names(method: &syn::ImplItemFn) -> Vec<String> {
    let mut names = Vec::new();
    for arg in &method.sig.inputs {
        let FnArg::Typed(pt) = arg else { continue };
        let Pat::Ident(pi) = &*pt.pat else { continue };
        let ty_str = type_to_str(&pt.ty);
        if ty_str.contains("i128") {
            names.push(pi.ident.to_string());
        }
    }
    names
}

fn type_to_str(ty: &Type) -> String {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        Type::Reference(r) => type_to_str(&r.elem),
        _ => String::new(),
    }
}

#[derive(Default)]
struct DepositScan {
    has_positive_guard: bool,
    has_storage_set: bool,
    first_set_line: usize,
    set_seen: bool,
}

impl<'ast> Visit<'ast> for DepositScan {
    fn visit_macro(&mut self, i: &'ast Macro) {
        // Try parsing as a single expression first (assert!(cond))
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        } else {
            // For assert!(cond, "msg") style: extract tokens before the first top-level comma
            let first_arg = extract_first_macro_arg(i);
            if let Ok(expr) = syn::parse2::<Expr>(first_arg) {
                self.visit_expr(&expr);
            }
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        // Look for `amount > 0`, `amount >= 1`, `0 < amount`, `1 <= amount`
        // or assert!(amount > 0) — we catch the BinOp directly.
        if matches!(
            i.op,
            BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Lt(_) | BinOp::Le(_)
        ) {
            self.has_positive_guard = true;
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_set(i) && !self.set_seen {
            self.has_storage_set = true;
            self.set_seen = true;
            self.first_set_line = i.span().start().line;
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct NegativeDepositCheck;

impl Check for NegativeDepositCheck {
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
            if !is_deposit_fn(&name) {
                continue;
            }
            let i128_params = i128_param_names(method);
            if i128_params.is_empty() {
                continue;
            }
            let mut scan = DepositScan::default();
            scan.visit_block(&method.block);
            if !scan.has_storage_set {
                continue;
            }
            if scan.has_positive_guard {
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
                    "Method `{name}` accepts an `i128` amount parameter and writes to storage \
                     without a positive-value guard (`amount > 0`). A caller passing a \
                     negative amount can effectively withdraw funds while appearing to \
                     deposit. Add an explicit check that `amount > 0` before any storage write."
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
    fn flags_deposit_without_positive_guard() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        let bal: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        env.storage().persistent().set(&from, &(bal + amount));
    }
}
"#;
        let file = parse_file(src)?;
        let hits = NegativeDepositCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("amount > 0"));
        Ok(())
    }

    #[test]
    fn no_finding_when_positive_guard_present() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let bal: i128 = env.storage().persistent().get(&from).unwrap_or(0);
        env.storage().persistent().set(&from, &(bal + amount));
    }
}
"#;
        let file = parse_file(src)?;
        let hits = NegativeDepositCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn flags_fund_fn() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn fund(env: Env, account: Address, amount: i128) {
        env.storage().persistent().set(&account, &amount);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = NegativeDepositCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_for_non_deposit_fn() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, amount: i128) {
        env.storage().persistent().set(&from, &amount);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = NegativeDepositCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_when_no_i128_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, from: Address) {
        env.storage().persistent().set(&from, &true);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = NegativeDepositCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

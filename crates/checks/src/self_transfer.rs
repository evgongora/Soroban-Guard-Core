//! Transfer functions that do not assert `from != to`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File, FnArg, Macro, Pat, PatType, Type, TypePath};

const CHECK_NAME: &str = "self-transfer";

pub struct SelfTransferCheck;

impl Check for SelfTransferCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let name = method.sig.ident.to_string();
            if name != "transfer" {
                continue;
            }
            let address_params = address_param_names(&method.sig.inputs);
            if address_params.len() < 2 {
                continue;
            }
            let mut v = NeScan {
                names: &address_params,
                found: false,
            };
            v.visit_block(&method.block);
            if !v.found {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: name.clone(),
                    description: "`transfer` accepts `from` and `to` Address parameters but never \
                         asserts `from != to`. Self-transfers produce confusing accounting \
                         and event logs."
                        .to_string(),
                });
            }
        }
        out
    }
}

/// Returns the names of parameters whose type is `Address` (or ends in `Address`).
fn address_param_names(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<String> {
    inputs
        .iter()
        .filter_map(|arg| {
            let FnArg::Typed(PatType { pat, ty, .. }) = arg else {
                return None;
            };
            if !is_address_type(ty) {
                return None;
            }
            if let Pat::Ident(pi) = pat.as_ref() {
                Some(pi.ident.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_address_type(ty: &Type) -> bool {
    if let Type::Path(TypePath { path, .. }) = ty {
        path.segments.last().is_some_and(|s| s.ident == "Address")
    } else {
        false
    }
}

struct NeScan<'a> {
    names: &'a [String],
    found: bool,
}

impl<'ast> Visit<'ast> for NeScan<'_> {
    fn visit_macro(&mut self, i: &'ast Macro) {
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Ne(_)) {
            let left = expr_ident_name(&i.left);
            let right = expr_ident_name(&i.right);
            if let (Some(l), Some(r)) = (left, right) {
                if self.names.contains(&l) && self.names.contains(&r) {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_binary(self, i);
    }
}

fn expr_ident_name(expr: &syn::Expr) -> Option<String> {
    if let syn::Expr::Path(p) = expr {
        p.path.get_ident().map(|i| i.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_transfer_without_ne_check() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let _ = (env, from, to, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_when_ne_assert_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        assert!(from != to);
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_transfer_fn() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn send(env: Env, from: Address, to: Address, amount: i128) {
        let _ = (env, from, to, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_transfer_with_single_address() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        let _ = (env, to, amount);
    }
}
"#,
        )?;
        let hits = SelfTransferCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

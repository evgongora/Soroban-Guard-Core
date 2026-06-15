//! Detects transfer/mint/burn functions without zero-amount validation.
//!
//! Token transfer functions that do not guard against zero-amount transfers
//! can be exploited to emit spurious events or trigger unintended side effects.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File, FnArg, Pat, PatType};

const CHECK_NAME: &str = "zero-amount-transfer";

/// Flags functions named `transfer`, `mint`, or `burn` in `#[contractimpl]` blocks
/// that accept an amount parameter but contain no comparison of amount against 0.
pub struct ZeroAmountCheck;

impl Check for ZeroAmountCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Check if function name matches sensitive transfer functions
            if !matches!(fn_name.as_str(), "transfer" | "mint" | "burn") {
                continue;
            }

            // Check if function has an 'amount' parameter
            let has_amount_param = method.sig.inputs.iter().any(|input| {
                if let FnArg::Typed(PatType { pat, .. }) = input {
                    if let Pat::Ident(ident) = &**pat {
                        ident.ident == "amount"
                    } else {
                        false
                    }
                } else {
                    false
                }
            });

            if !has_amount_param {
                continue;
            }

            // Check if body validates amount > 0
            if !body_checks_amount_positive(&method.block) {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{}` accepts an 'amount' parameter but contains no check that \
                         amount > 0. Zero-amount transfers can emit spurious events or trigger \
                         unintended side effects.",
                        fn_name
                    ),
                });
            }
        }
        out
    }
}

fn body_checks_amount_positive(block: &syn::Block) -> bool {
    let mut scanner = AmountCheckScanner::default();
    scanner.visit_block(block);
    scanner.found_check
}

#[derive(Default)]
struct AmountCheckScanner {
    found_check: bool,
}

impl<'ast> Visit<'ast> for AmountCheckScanner {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        // Look for comparisons like amount > 0 or amount != 0
        let left_is_amount = expr_is_ident(i.left.as_ref(), "amount");
        let right_is_zero = expr_is_zero(i.right.as_ref());

        if left_is_amount && right_is_zero {
            match i.op {
                BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Ne(_) | BinOp::Lt(_) | BinOp::Le(_) => {
                    self.found_check = true;
                }
                _ => {}
            }
        }

        // Also check for 0 > amount patterns (unlikely but defensive)
        let left_is_zero = expr_is_zero(i.left.as_ref());
        let right_is_amount = expr_is_ident(i.right.as_ref(), "amount");

        if left_is_zero && right_is_amount {
            if let BinOp::Lt(_) | BinOp::Le(_) | BinOp::Ne(_) = i.op {
                self.found_check = true;
            }
        }

        visit::visit_expr_binary(self, i);
    }
}

fn expr_is_ident(expr: &Expr, name: &str) -> bool {
    if let Expr::Path(p) = expr {
        p.path.is_ident(name)
    } else {
        false
    }
}

fn expr_is_zero(expr: &Expr) -> bool {
    if let Expr::Lit(l) = expr {
        if let syn::Lit::Int(i) = &l.lit {
            i.base10_parse::<i32>().map(|n| n == 0).unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_transfer_without_amount_check() {
        let code = r#"
#[contractimpl]
impl TokenContract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i32) {
        env.storage().instance().set(&key, &amount);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = ZeroAmountCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].function_name, "transfer");
    }

    #[test]
    fn allows_transfer_with_amount_check() {
        let code = r#"
#[contractimpl]
impl TokenContract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i32) {
        if amount <= 0 {
            panic!("Amount must be positive");
        }
        env.storage().instance().set(&key, &amount);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = ZeroAmountCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_mint_without_validation() {
        let code = r#"
#[contractimpl]
impl TokenContract {
    pub fn mint(env: Env, to: Address, amount: i128) {
        emit_mint_event(env, amount);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = ZeroAmountCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function_name, "mint");
    }

    #[test]
    fn allows_mint_with_amount_check() {
        let code = r#"
#[contractimpl]
impl TokenContract {
    pub fn mint(env: Env, to: Address, amount: i128) {
        if amount > 0 {
            emit_mint_event(env, amount);
        }
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = ZeroAmountCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_function_without_amount_param() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn transfer(env: Env, from: Address, to: Address) {
        env.storage().instance().set(&key, &value);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = ZeroAmountCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

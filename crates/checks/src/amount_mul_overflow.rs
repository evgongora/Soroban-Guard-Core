//! Token amount multiplication used directly in transfer/mint/burn calls without checked_mul.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "amount-mul-overflow";

fn receiver_is_not_bare_env(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => !p.path.is_ident("env"),
        _ => true,
    }
}

fn is_mul_binary(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(b) => matches!(b.op, BinOp::Mul(_)),
        Expr::Reference(r) => is_mul_binary(&r.expr),
        Expr::Paren(p) => is_mul_binary(&p.expr),
        _ => false,
    }
}

fn is_token_amount_binary_arg(m: &ExprMethodCall) -> bool {
    match m.method.to_string().as_str() {
        "transfer" => m.args.iter().nth(2).map(is_mul_binary).unwrap_or(false),
        "burn" | "mint" => m.args.iter().nth(1).map(is_mul_binary).unwrap_or(false),
        _ => false,
    }
}

pub struct AmountMulOverflowCheck;

impl Check for AmountMulOverflowCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = AmountMulOverflowVisitor {
                fn_name,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct AmountMulOverflowVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for AmountMulOverflowVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_token_amount_binary_arg(i) && receiver_is_not_bare_env(&i.receiver) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` passes the result of `*` directly into `.{}` without `checked_mul`. \n                         Multiply token amounts with `checked_mul` or `saturating_mul` to avoid silent overflow.",
                    self.fn_name,
                    i.method
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        AmountMulOverflowCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_transfer_amount_binary_expression() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, token, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn pay(env: Env, token: Address, from: Address, to: Address, price: i128, qty: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&from, &to, &(price * qty));
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn flags_burn_amount_binary_expression() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, token, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn burn(env: Env, token: Address, from: Address, price: i128, qty: i128) {
        let client = token::Client::new(&env, &token);
        client.burn(&from, &(price * qty));
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_with_checked_mul_before_transfer() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, token, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn pay(env: Env, token: Address, from: Address, to: Address, price: i128, qty: i128) {
        let amount = price.checked_mul(qty).expect("overflow");
        let client = token::Client::new(&env, &token);
        client.transfer(&from, &to, &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_env_transfer() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn pay(env: Env, to: Address, price: i128, qty: i128) {
        env.transfer(&to, &(price * qty));
    }
}
"#);
        assert!(hits.is_empty());
    }
}

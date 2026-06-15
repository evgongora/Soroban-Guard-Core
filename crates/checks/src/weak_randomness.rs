//! Detects `env.ledger().timestamp()` / `env.ledger().sequence()` used as randomness.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File};

const CHECK_NAME: &str = "weak-randomness";

pub struct WeakRandomnessCheck;

impl Check for WeakRandomnessCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = LedgerRandVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true if `expr` is `*.ledger().timestamp()` or `*.ledger().sequence()`.
fn is_ledger_rand(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(r) => is_ledger_rand(&r.expr),
        Expr::MethodCall(outer) => {
            if !matches!(outer.method.to_string().as_str(), "timestamp" | "sequence") {
                return false;
            }
            let Expr::MethodCall(inner) = outer.receiver.as_ref() else {
                return false;
            };
            inner.method == "ledger"
        }
        _ => false,
    }
}

fn is_arithmetic_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_) | BinOp::Rem(_)
    )
}

struct LedgerRandVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for LedgerRandVisitor<'_> {
    /// Flag arithmetic that directly involves a ledger timestamp/sequence operand.
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if is_arithmetic_op(&i.op) && (is_ledger_rand(&i.left) || is_ledger_rand(&i.right)) {
            self.out.push(finding(i.span().start().line, &self.fn_name));
        }
        visit::visit_expr_binary(self, i);
    }

    /// Flag storage writes where the argument is a ledger timestamp/sequence call.
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();
        if method == "set" {
            if let Some(val_arg) = i.args.last() {
                if is_ledger_rand(val_arg) {
                    self.out.push(finding(i.span().start().line, &self.fn_name));
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn finding(line: usize, fn_name: &str) -> Finding {
    Finding {
        check_name: CHECK_NAME.to_string(),
        severity: Severity::Medium,
        file_path: String::new(),
        line,
        function_name: fn_name.to_string(),
        description: format!(
            "`env.ledger().timestamp()` or `env.ledger().sequence()` used as a randomness \
             source in `{fn_name}`. Validators can influence these values; use a VRF or \
             commit-reveal scheme instead."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_timestamp_in_arithmetic() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn roll(env: Env) -> u64 {
        env.ledger().timestamp() % 6
    }
}
"#,
        )?;
        let hits = WeakRandomnessCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_sequence_stored_as_seed() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn init(env: Env) {
        env.storage().instance().set(&Symbol::short("seed"), &env.ledger().sequence());
    }
}
"#,
        )?;
        let hits = WeakRandomnessCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_safe_contract() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn is_expired(env: Env, deadline: u64) -> bool {
        env.ledger().timestamp() > deadline
    }
}
"#,
        )?;
        // Comparison (>) is not arithmetic — should not flag.
        let hits = WeakRandomnessCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

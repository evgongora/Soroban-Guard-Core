//! Floating-point arithmetic (`f32`/`f64`) in contract methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprCast, File, Lit, Type, TypePath};

const CHECK_NAME: &str = "float-arithmetic";

pub struct FloatArithmeticCheck;

impl Check for FloatArithmeticCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = FloatVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_arithmetic(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Add(_)
            | BinOp::Sub(_)
            | BinOp::Mul(_)
            | BinOp::Div(_)
            | BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
    )
}

fn is_float_lit(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(el) if matches!(el.lit, Lit::Float(_)))
}

fn is_float_cast(expr: &Expr) -> bool {
    if let Expr::Cast(ExprCast { ty, .. }) = expr {
        if let Type::Path(TypePath { path, .. }) = ty.as_ref() {
            return path
                .segments
                .last()
                .is_some_and(|s| s.ident == "f32" || s.ident == "f64");
        }
    }
    false
}

fn operand_is_float(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(p) => operand_is_float(&p.expr),
        _ => is_float_lit(expr) || is_float_cast(expr),
    }
}

struct FloatVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for FloatVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if is_arithmetic(&i.op) && (operand_is_float(&i.left) || operand_is_float(&i.right)) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Floating-point arithmetic detected in `{}`. \
                     f32/f64 results can differ across host environments; \
                     use integer math for all financial calculations.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_binary(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_float_literal_arithmetic() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn fee(env: Env, amount: i128) -> f64 {
        let _ = env;
        amount as f64 * 0.01_f64
    }
}
"#,
        )?;
        let hits = FloatArithmeticCheck.run(&file, "");
        assert!(!hits.is_empty());
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_float_cast_arithmetic() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn ratio(env: Env, a: i128, b: i128) -> f32 {
        let _ = env;
        (a as f32) / (b as f32)
    }
}
"#,
        )?;
        let hits = FloatArithmeticCheck.run(&file, "");
        assert!(!hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_integer_only_arithmetic() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn fee(env: Env, amount: i128) -> i128 {
        let _ = env;
        amount * 100 / 10000
    }
}
"#,
        )?;
        let hits = FloatArithmeticCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

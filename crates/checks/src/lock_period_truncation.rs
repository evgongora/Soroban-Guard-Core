//! Detects `timestamp() + lock_period` result cast/stored as `u32` (truncation bypass).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprCast, File, Type};

const CHECK_NAME: &str = "lock-period-truncation";

/// Flags `env.ledger().timestamp() + x` expressions whose result is cast to `u32`
/// or assigned into a `u32`-typed `let` binding.
pub struct LockPeriodTruncationCheck;

impl Check for LockPeriodTruncationCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = Visitor {
                fn_name,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true if the expression is (or contains) `env.ledger().timestamp()`.
fn contains_timestamp(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "timestamp" {
                return true;
            }
            contains_timestamp(&m.receiver)
        }
        _ => false,
    }
}

fn is_timestamp_add(e: &ExprBinary) -> bool {
    matches!(e.op, BinOp::Add(_)) && (contains_timestamp(&e.left) || contains_timestamp(&e.right))
}

fn type_is_u32(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        tp.path.is_ident("u32")
    } else {
        false
    }
}

/// Strip parentheses and return the inner `ExprBinary` if present.
fn unwrap_to_binary(expr: &Expr) -> Option<&ExprBinary> {
    match expr {
        Expr::Binary(b) => Some(b),
        Expr::Paren(p) => unwrap_to_binary(&p.expr),
        _ => None,
    }
}

struct Visitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    // `(expr) as u32`
    fn visit_expr_cast(&mut self, i: &ExprCast) {
        if type_is_u32(&i.ty) {
            if let Some(bin) = unwrap_to_binary(&i.expr) {
                if is_timestamp_add(bin) {
                    self.out.push(finding(i.span().start().line, &self.fn_name));
                }
            }
        }
        visit::visit_expr_cast(self, i);
    }

    // `let unlock: u32 = timestamp() + period`
    fn visit_local(&mut self, i: &syn::Local) {
        if let syn::Pat::Type(pt) = &i.pat {
            if type_is_u32(&pt.ty) {
                if let Some(init) = &i.init {
                    if let Some(bin) = unwrap_to_binary(&init.expr) {
                        if is_timestamp_add(bin) {
                            self.out.push(finding(i.span().start().line, &self.fn_name));
                        }
                    }
                }
            }
        }
        visit::visit_local(self, i);
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
            "`{fn_name}` adds a lock/cooldown period to `env.ledger().timestamp()` and stores \
             the result as `u32`. After year 2106 the value wraps, silently bypassing the \
             time-lock. Use `u64` for all unlock timestamps."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_cast_to_u32() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn lock(env: soroban_sdk::Env, period: u64) {
        let unlock = (env.ledger().timestamp() + period) as u32;
        env.storage().instance().set(&1u32, &unlock);
    }
}
"#,
        )?;
        let hits = LockPeriodTruncationCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_u32_typed_binding() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn lock(env: soroban_sdk::Env, period: u64) {
        let unlock: u32 = env.ledger().timestamp() + period;
        env.storage().instance().set(&1u32, &unlock);
    }
}
"#,
        )?;
        let hits = LockPeriodTruncationCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_u64_binding() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn lock(env: soroban_sdk::Env, period: u64) {
        let unlock: u64 = env.ledger().timestamp() + period;
        env.storage().instance().set(&1u32, &unlock);
    }
}
"#,
        )?;
        let hits = LockPeriodTruncationCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
impl C {
    pub fn lock(env: soroban_sdk::Env, period: u64) {
        let unlock: u32 = env.ledger().timestamp() + period;
    }
}
"#,
        )?;
        let hits = LockPeriodTruncationCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

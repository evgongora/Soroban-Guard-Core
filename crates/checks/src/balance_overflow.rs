//! Balance overflow: persistent storage get → unchecked `+`/`+=` → storage set.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "balance-overflow";

/// Flags the pattern:
///   1. value read from `persistent().get(…)`
///   2. added with `+` or `+=` (not `checked_add`)
///   3. result written back via `persistent().set(…)`
///
/// All three must appear in the same function body (statement-order heuristic).
pub struct BalanceOverflowCheck;

impl Check for BalanceOverflowCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let stmts = &method.block.stmts;

            let has_persistent_get = stmts.iter().any(stmt_has_persistent_get);
            let has_persistent_set = stmts.iter().any(stmt_has_persistent_set);

            if has_persistent_get && has_persistent_set {
                let mut v = UncheckedAddVisitor {
                    fn_name: fn_name.clone(),
                    out: &mut out,
                };
                v.visit_block(&method.block);
            }
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn method_chain_contains(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == name {
                return true;
            }
            method_chain_contains(&m.receiver, name)
        }
        _ => false,
    }
}

fn is_persistent_storage_call(m: &ExprMethodCall) -> bool {
    method_chain_contains(&m.receiver, "persistent")
        && method_chain_contains(&m.receiver, "storage")
}

fn expr_has_persistent_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" && is_persistent_storage_call(m) {
                return true;
            }
            m.args.iter().any(expr_has_persistent_get) || expr_has_persistent_get(&m.receiver)
        }
        _ => false,
    }
}

fn expr_has_persistent_set(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "set" && is_persistent_storage_call(m) {
                return true;
            }
            expr_has_persistent_set(&m.receiver)
        }
        _ => false,
    }
}

fn stmt_has_persistent_get(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Local(l) => l
            .init
            .as_ref()
            .is_some_and(|i| expr_has_persistent_get(&i.expr)),
        Stmt::Expr(e, _) => expr_has_persistent_get(e),
        _ => false,
    }
}

fn stmt_has_persistent_set(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(e, _) => expr_has_persistent_set(e),
        _ => false,
    }
}

fn is_unchecked_add(e: &ExprBinary) -> bool {
    matches!(e.op, BinOp::Add(_) | BinOp::AddAssign(_))
}

fn expr_is_checked_add_call(expr: &Expr) -> bool {
    if let Expr::MethodCall(m) = expr {
        return m.method == "checked_add";
    }
    false
}

// ── visitor ──────────────────────────────────────────────────────────────────

struct UncheckedAddVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for UncheckedAddVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if is_unchecked_add(i) && !expr_is_checked_add_call(&Expr::Binary(i.clone())) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`{}` reads a balance from persistent storage and adds to it with `{}` \
                     without `checked_add`. A large deposit can overflow the balance to a \
                     negative or zero value, effectively stealing funds.",
                    self.fn_name,
                    match &i.op {
                        BinOp::Add(_) => "+",
                        _ => "+=",
                    }
                ),
            });
        }
        visit::visit_expr_binary(self, i);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    const VULNERABLE: &str = r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const BAL: Symbol = symbol_short!("bal");

#[contractimpl]
impl C {
    pub fn deposit(env: Env, amount: i128) {
        let bal: i128 = env.storage().persistent().get(&BAL).unwrap_or(0);
        let new_bal = bal + amount;
        env.storage().persistent().set(&BAL, &new_bal);
    }
}
"#;

    const SAFE: &str = r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const BAL: Symbol = symbol_short!("bal");

#[contractimpl]
impl C {
    pub fn deposit(env: Env, amount: i128) {
        let bal: i128 = env.storage().persistent().get(&BAL).unwrap_or(0);
        let new_bal = bal.checked_add(amount).expect("overflow");
        env.storage().persistent().set(&BAL, &new_bal);
    }
}
"#;

    #[test]
    fn flags_unchecked_add_on_persistent_balance() -> Result<(), syn::Error> {
        let file = parse_file(VULNERABLE)?;
        let hits = BalanceOverflowCheck.run(&file, "");
        assert!(!hits.is_empty(), "expected at least one finding");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_checked_add_on_persistent_balance() -> Result<(), syn::Error> {
        let file = parse_file(SAFE)?;
        let hits = BalanceOverflowCheck.run(&file, "");
        assert!(hits.is_empty(), "expected no findings, got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_add_without_storage_pattern() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn add(_env: Env, a: i128, b: i128) -> i128 { a + b }
}
"#,
        )?;
        // No persistent get+set pair → check should not fire
        let hits = BalanceOverflowCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn flags_add_assign_variant() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
#[contract] pub struct C;
const BAL: Symbol = symbol_short!("b");
#[contractimpl]
impl C {
    pub fn deposit(env: Env, amount: i128) {
        let mut bal: i128 = env.storage().persistent().get(&BAL).unwrap_or(0);
        bal += amount;
        env.storage().persistent().set(&BAL, &bal);
    }
}
"#,
        )?;
        let hits = BalanceOverflowCheck.run(&file, "");
        assert!(!hits.is_empty(), "expected finding for +=");
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }
}

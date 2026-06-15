//! Detects persistent storage write before fallible operation (partial state update).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Expr, ExprTry, File, Stmt};

const CHECK_NAME: &str = "partial-write-on-error";

/// Flags #[contractimpl] functions that write to env.storage().persistent().set(...) before a ? operator or return Err(...) expression.
pub struct PartialWriteOnErrorCheck;

impl Check for PartialWriteOnErrorCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scanner = StatementScanner::default();
            scanner.visit_block(&method.block);

            for write_idx in &scanner.persistent_writes {
                for error_idx in &scanner.error_points {
                    if write_idx < error_idx {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: scanner.lines[*write_idx],
                            function_name: fn_name.clone(),
                            description: format!(
                                "Method `{}` writes to persistent storage before a fallible operation. \
                                 If the operation fails, the contract will be left in a partially-updated state.",
                                fn_name
                            ),
                        });
                        break; // Only report once per function
                    }
                }
            }
        }
        out
    }
}

#[derive(Default)]
struct StatementScanner {
    statements: Vec<Stmt>,
    lines: Vec<usize>,
    persistent_writes: Vec<usize>,
    error_points: Vec<usize>,
}

impl Visit<'_> for StatementScanner {
    fn visit_block(&mut self, i: &Block) {
        for (idx, stmt) in i.stmts.iter().enumerate() {
            self.statements.push(stmt.clone());
            self.lines.push(stmt.span().start().line);

            if let Stmt::Expr(expr, _) = stmt {
                if is_persistent_write(expr) {
                    self.persistent_writes.push(idx);
                }
                if is_error_point(expr) {
                    self.error_points.push(idx);
                }
            }

            // Also check for error points in nested expressions
            self.visit_stmt(stmt);
        }
    }
}

fn is_persistent_write(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "set" && receiver_chain_contains_persistent(&m.receiver) {
                return true;
            }
            false
        }
        _ => false,
    }
}

fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "persistent" {
                return true;
            }
            receiver_chain_contains_persistent(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent(&f.base),
        _ => false,
    }
}

fn is_error_point(expr: &Expr) -> bool {
    match expr {
        Expr::Try(ExprTry { .. }) => true, // ? operator
        Expr::Return(ret) => {
            if let Some(expr) = &ret.expr {
                is_return_err(expr)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_return_err(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                if path.path.segments.last().is_some_and(|s| s.ident == "Err") {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(PartialWriteOnErrorCheck.run(&file, src))
    }

    #[test]
    fn flags_persistent_write_before_try() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), ()> {
        // Write before fallible operation
        env.storage().persistent().set(&from, &0i128);
        // Fallible operation
        from.require_auth()?;
        Ok(())
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "transfer");
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_persistent_write_before_return_err() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), ()> {
        // Write before return Err
        env.storage().persistent().set(&from, &0i128);
        return Err(());
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_when_write_after_error() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), ()> {
        // Fallible operation first
        from.require_auth()?;
        // Write after
        env.storage().persistent().set(&from, &0i128);
        Ok(())
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_no_persistent_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), ()> {
        // Only temporary storage
        env.storage().temporary().set(&from, &0i128);
        from.require_auth()?;
        Ok(())
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}

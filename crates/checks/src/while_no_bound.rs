//! `while` loops whose condition depends on storage or a user-supplied parameter
//! and that lack a bounded exit.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprBinary, ExprBreak, ExprWhile, File, FnArg, Pat};

const CHECK_NAME: &str = "while-no-bound";

/// Flags `#[contractimpl]` methods with a `while` loop whose condition depends on storage
/// or a function parameter and whose body shows no evidence of a capped exit (a `break`
/// paired with a comparison guard). Such loops have no guaranteed iteration bound and can
/// exhaust the Soroban instruction limit.
pub struct WhileNoBoundCheck;

impl Check for WhileNoBoundCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let params: HashSet<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    if let FnArg::Typed(pat_type) = arg {
                        if let Pat::Ident(pat_ident) = &*pat_type.pat {
                            return Some(pat_ident.ident.to_string());
                        }
                    }
                    None
                })
                .collect();

            let mut visitor = WhileVisitor {
                fn_name,
                params,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct WhileVisitor<'a> {
    fn_name: String,
    params: HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for WhileVisitor<'_> {
    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        if self.condition_is_unbounded_candidate(&i.cond) && !body_has_capped_exit(&i.body) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.while_token.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "While loop in `{}` has a condition that depends on storage or a \
                     user-supplied parameter but no bounded exit (no `break` paired with a \
                     comparison guard). On Soroban this can iterate unboundedly and exhaust \
                     the instruction limit. Add a counter capped against a maximum and `break`.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_while(self, i);
    }
}

impl WhileVisitor<'_> {
    fn condition_is_unbounded_candidate(&self, cond: &Expr) -> bool {
        let cond_str = cond.to_token_stream().to_string();
        if cond_str.contains("storage") || receiver_chain_contains_storage(cond) {
            return true;
        }
        self.params.iter().any(|param| ident_in_tokens(&cond_str, param))
    }
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
        Expr::Binary(b) => {
            receiver_chain_contains_storage(&b.left) || receiver_chain_contains_storage(&b.right)
        }
        Expr::Unary(u) => receiver_chain_contains_storage(&u.expr),
        Expr::Paren(p) => receiver_chain_contains_storage(&p.expr),
        _ => false,
    }
}

fn ident_in_tokens(tokens: &str, ident: &str) -> bool {
    tokens
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == ident)
}

fn body_has_capped_exit(body: &Block) -> bool {
    let mut visitor = ExitEvidenceVisitor {
        has_break: false,
        has_comparison: false,
    };
    visitor.visit_block(body);
    visitor.has_break && visitor.has_comparison
}

struct ExitEvidenceVisitor {
    has_break: bool,
    has_comparison: bool,
}

impl<'ast> Visit<'ast> for ExitEvidenceVisitor {
    fn visit_expr_break(&mut self, i: &'ast ExprBreak) {
        self.has_break = true;
        visit::visit_expr_break(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(
            i.op,
            BinOp::Ge(_) | BinOp::Gt(_) | BinOp::Le(_) | BinOp::Lt(_)
        ) {
            self.has_comparison = true;
        }
        visit::visit_expr_binary(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_while_storage_condition_without_bound() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn drain(env: Env) {
        while env.storage().instance().get::<_, i128>(&COUNT).unwrap() > 0 {
            let _ = 1;
        }
    }
}
"#,
        )?;
        let hits = WhileNoBoundCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "drain");
        Ok(())
    }

    #[test]
    fn passes_while_with_counter_and_break() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn drain(env: Env) {
        let mut i = 0;
        while env.storage().instance().get::<_, i128>(&COUNT).unwrap() > 0 {
            i += 1;
            if i >= MAX {
                break;
            }
        }
    }
}
"#,
        )?;
        let hits = WhileNoBoundCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_while_param_condition_without_bound() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn run(env: Env, n: u32) {
        let _ = env;
        while n > 0 {
            let _ = 1;
        }
    }
}
"#,
        )?;
        let hits = WhileNoBoundCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "run");
        Ok(())
    }

    #[test]
    fn passes_while_local_literal_condition() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn run(env: Env) {
        let _ = env;
        let mut i = 0;
        while i < 10 {
            i += 1;
        }
    }
}
"#,
        )?;
        let hits = WhileNoBoundCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;

pub struct C;

impl C {
    pub fn drain(env: Env) {
        while env.storage().instance().get::<_, i128>(&COUNT).unwrap() > 0 {
            let _ = 1;
        }
    }
}
"#,
        )?;
        let hits = WhileNoBoundCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

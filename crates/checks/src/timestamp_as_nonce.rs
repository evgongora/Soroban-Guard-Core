//! Using `env.ledger().timestamp()` as a nonce or unique identifier.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Local, Pat};

const CHECK_NAME: &str = "timestamp-as-nonce";

/// Flags `#[contractimpl]` methods that treat `env.ledger().timestamp()` as a
/// unique nonce or identifier: it is the close time of the *current ledger*
/// and is identical for every transaction within that ledger.
pub struct TimestampAsNonceCheck;

impl Check for TimestampAsNonceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let mut scan = FuncBodyScan::default();
            scan.visit_block(&method.block);
            let Some(line) = scan.first_line else {
                continue;
            };
            let fn_name = method.sig.ident.to_string();
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` derives a nonce/identifier from `env.ledger().timestamp()`. \
                     The ledger timestamp is the close time of the current ledger and is identical \
                     for every transaction in that ledger, so two transactions can collide on the \
                     same value, enabling replay. Use a monotonically incrementing counter in \
                     storage or `env.prng()` instead."
                ),
            });
        }
        out
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
        _ => false,
    }
}

/// Matches the `env.ledger().timestamp()` chain: a method call named
/// `"timestamp"` whose receiver is itself a method call named `"ledger"`,
/// mirroring `is_env_require_auth` in `auth.rs`, which matches `Expr::Path`
/// on the base receiver.
fn is_ledger_timestamp_call(m: &ExprMethodCall) -> bool {
    if m.method != "timestamp" {
        return false;
    }
    let Expr::MethodCall(receiver) = &*m.receiver else {
        return false;
    };
    if receiver.method != "ledger" {
        return false;
    }
    matches!(&*receiver.receiver, Expr::Path(p) if p.path.is_ident("env"))
}

/// Whether `expr` is, or contains anywhere in its subtree, an
/// `env.ledger().timestamp()` chain. Structural/textual — not dataflow.
fn expr_contains_timestamp_chain(expr: &Expr) -> bool {
    #[derive(Default)]
    struct Finder(bool);

    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if is_ledger_timestamp_call(i) {
                self.0 = true;
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut finder = Finder::default();
    finder.visit_expr(expr);
    finder.0
}

fn ident_looks_like_nonce(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("nonce") || lower.contains("id") || lower.contains("unique_id")
}

#[derive(Default)]
struct FuncBodyScan {
    first_line: Option<usize>,
}

impl FuncBodyScan {
    fn flag(&mut self, line: usize) {
        if self.first_line.is_none() {
            self.first_line = Some(line);
        }
    }
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_local(&mut self, i: &'ast Local) {
        if let Some(init) = &i.init {
            if expr_contains_timestamp_chain(&init.expr) {
                let pat = match &i.pat {
                    Pat::Type(pt) => &*pt.pat,
                    p => p,
                };
                if let Pat::Ident(pi) = pat {
                    if ident_looks_like_nonce(&pi.ident.to_string()) {
                        self.flag(i.span().start().line);
                    }
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set" && receiver_chain_contains_storage(&i.receiver) {
            let direct_timestamp_arg = i.args.iter().any(expr_contains_timestamp_chain);
            if direct_timestamp_arg {
                self.flag(i.span().start().line);
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(TimestampAsNonceCheck.run(&file, src))
    }

    #[test]
    fn flags_timestamp_stored_directly_as_storage_key() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env) {
        env.storage().persistent().set(&env.ledger().timestamp(), &true);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "record");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_timestamp_assigned_to_nonce_binding() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env) {
        let nonce = env.ledger().timestamp();
        env.storage().persistent().set(&nonce, &true);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "record");
        Ok(())
    }

    #[test]
    fn flags_timestamp_assigned_to_id_binding() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env) {
        let request_id = env.ledger().timestamp();
        let _ = request_id;
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "record");
        Ok(())
    }

    #[test]
    fn flags_timestamp_assigned_to_unique_id_binding() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env) {
        let unique_id = env.ledger().timestamp();
        let _ = unique_id;
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_timestamp_assigned_to_unrelated_binding() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env) {
        let close_time = env.ledger().timestamp();
        let _ = close_time;
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_timestamp_used_for_expiry_not_nonce() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

const MIN_DURATION: u64 = 3600;

#[contractimpl]
impl Contract {
    pub fn set_expiry(env: Env) {
        let expiry = env.ledger().timestamp() + MIN_DURATION;
        env.storage().instance().set(&"expiry", &expiry);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_counter_based_nonce() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn record(env: Env) {
        let counter: u64 = env.storage().instance().get(&symbol_short!("CNT")).unwrap_or(0);
        let nonce = counter + 1;
        env.storage().persistent().set(&nonce, &true);
        env.storage().instance().set(&symbol_short!("CNT"), &nonce);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::Env;

pub struct Contract;

impl Contract {
    pub fn record(env: Env) {
        let nonce = env.ledger().timestamp();
        env.storage().persistent().set(&nonce, &true);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}

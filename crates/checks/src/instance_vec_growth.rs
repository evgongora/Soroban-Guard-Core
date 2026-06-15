//! Vec in instance storage grows unboundedly without a length cap.
//!
//! Detects the pattern: read Vec from `instance()` storage → `push_back` /
//! `push_front` → write back to `instance()` storage, without a `.len()`
//! comparison before the push. An unbounded Vec will eventually exceed the
//! maximum instance storage entry size, permanently bricking the contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Macro};

const CHECK_NAME: &str = "instance-vec-growth";

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

fn receiver_chain_contains_instance(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "instance" {
                return true;
            }
            receiver_chain_contains_instance(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_instance(&f.base),
        _ => false,
    }
}

fn is_instance_get(m: &ExprMethodCall) -> bool {
    matches!(m.method.to_string().as_str(), "get" | "get_unchecked")
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_instance(&m.receiver)
}

fn is_instance_set(m: &ExprMethodCall) -> bool {
    m.method == "set"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_instance(&m.receiver)
}

fn is_vec_push(m: &ExprMethodCall) -> bool {
    matches!(m.method.to_string().as_str(), "push_back" | "push_front")
}

fn is_len_check(m: &ExprMethodCall) -> bool {
    m.method == "len"
}

#[derive(Default)]
struct VecGrowthScan {
    instance_get: bool,
    vec_push: bool,
    vec_push_line: usize,
    instance_set: bool,
    len_check: bool,
}

impl<'ast> Visit<'ast> for VecGrowthScan {
    fn visit_macro(&mut self, i: &'ast Macro) {
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_instance_get(i) {
            self.instance_get = true;
        }
        if is_vec_push(i) && !self.vec_push {
            self.vec_push = true;
            self.vec_push_line = i.span().start().line;
        }
        if is_instance_set(i) {
            self.instance_set = true;
        }
        if is_len_check(i) {
            self.len_check = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn scan_block(block: &Block) -> VecGrowthScan {
    let mut s = VecGrowthScan::default();
    s.visit_block(block);
    s
}

pub struct InstanceVecGrowthCheck;

impl Check for InstanceVecGrowthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let scan = scan_block(&method.block);
            if scan.instance_get && scan.vec_push && scan.instance_set && !scan.len_check {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: scan.vec_push_line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` reads a Vec from `instance()` storage, pushes an \
                         element, and writes it back without checking `.len()` first. An \
                         unbounded Vec will eventually exceed the maximum instance storage \
                         entry size, permanently bricking the contract. Enforce a maximum \
                         length before appending."
                    ),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_unbounded_push_to_instance_vec() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, vec, Env, Vec};
pub struct C;
const PARTICIPANTS: soroban_sdk::Symbol = symbol_short!("parts");
#[contractimpl]
impl C {
    pub fn register(env: Env, addr: soroban_sdk::Address) {
        let mut list: Vec<soroban_sdk::Address> = env
            .storage()
            .instance()
            .get(&PARTICIPANTS)
            .unwrap_or(vec![&env]);
        list.push_back(addr);
        env.storage().instance().set(&PARTICIPANTS, &list);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = InstanceVecGrowthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("unbounded"));
        Ok(())
    }

    #[test]
    fn no_finding_when_len_checked() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, vec, Env, Vec};
pub struct C;
const PARTICIPANTS: soroban_sdk::Symbol = symbol_short!("parts");
const MAX: u32 = 100;
#[contractimpl]
impl C {
    pub fn register(env: Env, addr: soroban_sdk::Address) {
        let mut list: Vec<soroban_sdk::Address> = env
            .storage()
            .instance()
            .get(&PARTICIPANTS)
            .unwrap_or(vec![&env]);
        assert!(list.len() < MAX);
        list.push_back(addr);
        env.storage().instance().set(&PARTICIPANTS, &list);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = InstanceVecGrowthCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_for_persistent_vec() -> Result<(), syn::Error> {
        // Uses persistent(), not instance() — out of scope for this check.
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, vec, Env, Vec};
pub struct C;
const KEY: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn append(env: Env, val: u32) {
        let mut v: Vec<u32> = env
            .storage()
            .persistent()
            .get(&KEY)
            .unwrap_or(vec![&env]);
        v.push_back(val);
        env.storage().persistent().set(&KEY, &v);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = InstanceVecGrowthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_when_no_push() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Vec};
pub struct C;
const KEY: soroban_sdk::Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn reset(env: Env) {
        let v: Vec<u32> = env.storage().instance().get(&KEY).unwrap();
        env.storage().instance().set(&KEY, &v);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = InstanceVecGrowthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

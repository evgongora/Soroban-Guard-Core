//! Detects storage writes of unbounded Vec/Map parameters without size guard.
//!
//! Flags `env.storage().persistent().set(key, value)` (or temporary/instance) where
//! `value` is (or derives from) a function parameter typed as `Vec<_>` or `Map<_, _>`
//! and no preceding `.len()` comparison on that parameter exists.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, Ident, Type};

const CHECK_NAME: &str = "unbounded-input-storage";

/// Flags storage set calls where the value argument is a Vec/Map parameter without
/// a preceding length guard.
pub struct UnboundedInputStorageCheck;

impl Check for UnboundedInputStorageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let vec_map_params = collect_vec_map_params(&method.sig.inputs);
            if vec_map_params.is_empty() {
                continue;
            }
            let mut scan = UnboundedInputStorageScan {
                fn_name,
                out: &mut out,
                vec_map_params: &vec_map_params,
                len_checked: HashSet::new(),
                derived_params: HashSet::new(),
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

struct UnboundedInputStorageScan<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
    vec_map_params: &'a HashSet<Ident>,
    len_checked: HashSet<Ident>,
    derived_params: HashSet<Ident>,
}

impl<'ast> Visit<'ast> for UnboundedInputStorageScan<'_> {
    fn visit_local(&mut self, i: &'ast syn::Local) {
        if let Some(init) = &i.init {
            if let Expr::MethodCall(m) = &*init.expr {
                if m.method == "clone" {
                    if let Some(src_ident) = extract_ident(&m.receiver) {
                        if self.vec_map_params.contains(src_ident)
                            || self.derived_params.contains(src_ident)
                        {
                            if let syn::Pat::Ident(pi) = &i.pat {
                                self.derived_params.insert(pi.ident.clone());
                            }
                        }
                    }
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // Check for storage set calls
        if i.method == "set" && is_storage_receiver(&i.receiver) {
            // set(key, value) - value is second argument (index 1)
            if let Some(value_arg) = i.args.iter().nth(1) {
                if let Some(ident) = extract_ident(value_arg) {
                    let is_param =
                        self.vec_map_params.contains(ident) || self.derived_params.contains(ident);
                    let is_checked = self.len_checked.contains(ident)
                        || self
                            .derived_params
                            .iter()
                            .any(|d| self.len_checked.contains(d))
                        || self
                            .vec_map_params
                            .iter()
                            .any(|p| self.len_checked.contains(p));
                    if is_param && !is_checked {
                        let line = i.span().start().line;
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` writes Vec/Map parameter `{}` directly to storage \\\n\
                                 without a preceding size guard (`.len()` comparison). This may cause \\\n\
                                 the storage entry to exceed ledger limits and brick the contract.",
                                self.fn_name, ident
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        // Check if this binary expression is a comparison involving a .len() call on a parameter
        if is_comparison_op(&i.op) {
            if let Some(ident) = len_call_ident(&i.left) {
                if self.vec_map_params.contains(ident) {
                    self.len_checked.insert(ident.clone());
                }
            }
            if let Some(ident) = len_call_ident(&i.right) {
                if self.vec_map_params.contains(ident) {
                    self.len_checked.insert(ident.clone());
                }
            }
        }
        visit::visit_expr_binary(self, i);
    }
}

/// Extract an identifier from an expression, handling references and clone.
fn extract_ident(expr: &Expr) -> Option<&Ident> {
    match expr {
        Expr::Path(path) => path.path.get_ident(),
        Expr::Reference(addr) => extract_ident(&addr.expr),
        Expr::MethodCall(m) if m.method == "clone" => extract_ident(&m.receiver),
        _ => None,
    }
}

/// If expr is a `.len()` method call, return the identifier of the receiver (parameter).
fn len_call_ident(expr: &Expr) -> Option<&Ident> {
    if let Expr::MethodCall(m) = expr {
        if m.method == "len" {
            return extract_ident(&m.receiver);
        }
    }
    None
}

/// Check if a binary operator is a comparison (less, greater, equal, etc.).
fn is_comparison_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Eq(_) | BinOp::Ne(_)
    )
}

/// Collect identifiers of parameters whose type is Vec<_> or Map<_, _>.
fn collect_vec_map_params(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
) -> HashSet<Ident> {
    let mut set = HashSet::new();
    for input in inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                let ident = pat_ident.ident.clone();
                if is_vec_or_map_type(&pat_type.ty) {
                    set.insert(ident);
                }
            }
        }
    }
    set
}

fn is_vec_or_map_type(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                let ident = &segment.ident;
                ident == "Vec" || ident == "Map"
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_storage_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            // Check for .storage() call
            if m.method == "storage" {
                return true;
            }
            is_storage_receiver(&m.receiver)
        }
        Expr::Field(f) => is_storage_receiver(&f.base),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_unbounded_vec_param() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_items(env: Env, items: Vec<u32>) {
        env.storage().persistent().set(&Symbol::new(&env, "items"), &items);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_unbounded_map_param() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_map(env: Env, data: Map<u32, u32>) {
        env.storage().persistent().set(&Symbol::new(&env, "data"), &data);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_vec_param_clone() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_vec_clone(env: Env, items: Vec<u32>) {
        let cloned = items.clone();
        env.storage().persistent().set(&Symbol::new(&env, "items"), &cloned);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_with_len_guard() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_items(env: Env, items: Vec<u32>) {
        if items.len() < 100 {
            env.storage().persistent().set(&Symbol::new(&env, "items"), &items);
        }
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_param_is_not_vec_map() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_u32(env: Env, value: u32) {
        env.storage().persistent().set(&Symbol::new(&env, "value"), &value);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_storage_set_uses_local_vec() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_local(env: Env) {
        let items = Vec::new(&env);
        env.storage().persistent().set(&Symbol::new(&env, "items"), &items);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn flags_temporary_storage() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_temp(env: Env, items: Vec<u32>) {
        env.storage().temporary().set(&Symbol::new(&env, "items"), &items);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_instance_storage() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_instance(env: Env, items: Vec<u32>) {
        env.storage().instance().set(&Symbol::new(&env, "items"), &items);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn len_call_used_in_comparison_detected() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn store_with_guard(env: Env, items: Vec<u32>) {
        if items.len() >= 10 {
            // guard present, should not flag
        }
        env.storage().persistent().set(&Symbol::new(&env, "items"), &items);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = UnboundedInputStorageCheck;
        let findings = check.run(&file, "");
        // Since there is a len comparison, we consider it guarded (len_checked).
        // This test expects no findings.
        assert!(findings.is_empty());
        Ok(())
    }
}

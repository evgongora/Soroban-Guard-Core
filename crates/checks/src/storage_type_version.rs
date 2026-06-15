//! Flags inconsistent use of storage types across different versions or incompatible types.
//!
//! Storage types should be consistent across the contract. Mixing different versions
//! or incompatible types can lead to unexpected behavior and security vulnerabilities.

use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "storage-type-version";

/// Flags inconsistent use of storage types in the same contract.
/// Detects mixing of different storage types (e.g., persistent vs instance) or versions.
pub struct StorageTypeVersionCheck;

impl Check for StorageTypeVersionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        let mut storage_types = std::collections::HashSet::new();

        for item in &file.items {
            match item {
                syn::Item::Fn(func) => {
                    let mut v = StorageTypeVisitor {
                        storage_types: &mut storage_types,
                    };
                    v.visit_item_fn(func);
                }
                syn::Item::Impl(impl_block) => {
                    for impl_item in &impl_block.items {
                        if let syn::ImplItem::Fn(func) = impl_item {
                            let mut v = StorageTypeVisitor {
                                storage_types: &mut storage_types,
                            };
                            v.visit_impl_item_fn(func);
                        }
                    }
                }
                _ => {}
            }
        }

        if storage_types.len() > 1 {
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: 0,
                function_name: String::new(),
                description: format!("Contract uses multiple storage types: {:?}. Consider using a consistent storage tier for better predictability and security.", storage_types),
            });
        }

        out
    }
}

struct StorageTypeVisitor<'a> {
    storage_types: &'a mut std::collections::HashSet<String>,
}

impl<'a> Visit<'a> for StorageTypeVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if i.method == "persistent" || i.method == "instance" || i.method == "temporary" {
            if let Expr::MethodCall(mc) = &*i.receiver {
                if mc.method == "storage" {
                    self.storage_types.insert(i.method.to_string());
                }
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
        Ok(StorageTypeVersionCheck.run(&file, src))
    }

    #[test]
    fn flags_mixed_storage_types() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn mixed_storage(env: Env) {
        // Uses both persistent and instance storage
        env.storage().persistent().set(&KEY, &1);
        env.storage().instance().set(&KEY, &2);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_single_storage_type() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn single_storage(env: Env) {
        // Only uses persistent storage
        env.storage().persistent().set(&KEY, &1);
        env.storage().persistent().set(&KEY2, &2);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}

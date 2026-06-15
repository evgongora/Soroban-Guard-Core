//! Detects linear `.iter().any(…)` scans over a storage-backed `Vec` used as a whitelist.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "linear-whitelist-scan";

/// Flags `.iter().any(…)` chains in functions that also read from storage,
/// indicating an O(n) whitelist membership check that can be DoS'd.
pub struct LinearWhitelistScanCheck;

impl Check for LinearWhitelistScanCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // First pass: does this function read from storage?
            let mut storage_scan = StorageScan::default();
            storage_scan.visit_block(&method.block);
            if !storage_scan.has_storage_get {
                continue;
            }

            // Second pass: find .iter().any(…) calls
            let mut v = Visitor {
                fn_name,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[derive(Default)]
struct StorageScan {
    has_storage_get: bool,
}

impl Visit<'_> for StorageScan {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let name = i.method.to_string();
        if matches!(name.as_str(), "get" | "get_unchecked") {
            // Check if receiver chain contains "storage"
            if receiver_has_storage(&i.receiver) {
                self.has_storage_get = true;
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn receiver_has_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_has_storage(&m.receiver)
        }
        _ => false,
    }
}

struct Visitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        // Detect `.iter().any(…)` — receiver is `.iter()` call
        if i.method == "any" {
            if let Expr::MethodCall(iter_call) = &*i.receiver {
                if iter_call.method == "iter" {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "`{}` performs a linear `.iter().any(…)` scan over a storage-backed Vec. \
                             An attacker who can grow the list makes every call O(n), enabling DoS. \
                             Use a `Map<Address, bool>` for O(1) membership checks.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_iter_any_on_storage_vec() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn is_allowed(env: soroban_sdk::Env, caller: soroban_sdk::Address) -> bool {
        let list: soroban_sdk::Vec<soroban_sdk::Address> =
            env.storage().persistent().get(&1u32).unwrap_or_default();
        list.iter().any(|a| a == caller)
    }
}
"#,
        )?;
        let hits = LinearWhitelistScanCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_map_contains_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn is_allowed(env: soroban_sdk::Env, caller: soroban_sdk::Address) -> bool {
        let map: soroban_sdk::Map<soroban_sdk::Address, bool> =
            env.storage().persistent().get(&1u32).unwrap_or_default();
        map.contains_key(caller)
    }
}
"#,
        )?;
        let hits = LinearWhitelistScanCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
impl C {
    pub fn check(env: soroban_sdk::Env, caller: soroban_sdk::Address) -> bool {
        let list: soroban_sdk::Vec<soroban_sdk::Address> =
            env.storage().persistent().get(&1u32).unwrap_or_default();
        list.iter().any(|a| a == caller)
    }
}
"#,
        )?;
        let hits = LinearWhitelistScanCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

//! Same storage key written with different value types across functions.
//!
//! `set(key, value)` called with the same string literal key in two or more
//! functions of the same `#[contractimpl]` block but with structurally different
//! value expressions causes silent type confusion on reads.

use crate::util::is_contractimpl;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, ImplItem, Item};

const CHECK_NAME: &str = "storage-type-confusion";

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

fn extract_key_literal(arg: &Expr) -> Option<String> {
    let inner = match arg {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    match inner {
        Expr::Lit(l) => {
            if let syn::Lit::Str(s) = &l.lit {
                return Some(s.value());
            }
            None
        }
        // symbol_short!("key") macro
        Expr::Macro(m) => {
            let tokens = m.mac.tokens.to_string();
            // Extract the string literal from the macro tokens.
            let trimmed = tokens.trim().trim_matches('"');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
            None
        }
        _ => None,
    }
}

/// Produce a coarse type hint string from a value expression.
fn value_type_hint(expr: &Expr) -> String {
    let inner = match expr {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    match inner {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Int(i) => {
                let suffix = i.suffix();
                if suffix.is_empty() {
                    "int_lit".to_string()
                } else {
                    suffix.to_string()
                }
            }
            syn::Lit::Bool(_) => "bool".to_string(),
            syn::Lit::Str(_) => "str".to_string(),
            _ => "lit".to_string(),
        },
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_else(|| "path".to_string()),
        Expr::Call(c) => {
            if let Expr::Path(p) = &*c.func {
                p.path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_else(|| "call".to_string())
            } else {
                "call".to_string()
            }
        }
        Expr::Cast(c) => {
            // `val as i128` → "i128"
            match &*c.ty {
                syn::Type::Path(p) => p
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_else(|| "cast".to_string()),
                _ => "cast".to_string(),
            }
        }
        _ => "expr".to_string(),
    }
}

#[derive(Debug)]
struct SetEntry {
    key: String,
    type_hint: String,
    fn_name: String,
    line: usize,
}

struct SetCollector {
    fn_name: String,
    entries: Vec<SetEntry>,
}

impl<'ast> Visit<'ast> for SetCollector {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "set" && receiver_chain_contains_storage(&i.receiver) && i.args.len() >= 2 {
            if let Some(key) = extract_key_literal(&i.args[0]) {
                let hint = value_type_hint(&i.args[1]);
                self.entries.push(SetEntry {
                    key,
                    type_hint: hint,
                    fn_name: self.fn_name.clone(),
                    line: i.span().start().line,
                });
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct StorageTypeConfusionCheck;

impl Check for StorageTypeConfusionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        for item in &file.items {
            let Item::Impl(item_impl) = item else {
                continue;
            };
            if !is_contractimpl(item_impl) {
                continue;
            }

            // Collect all set entries across all functions in this impl block.
            let mut all_entries: Vec<SetEntry> = Vec::new();
            for impl_item in &item_impl.items {
                let ImplItem::Fn(method) = impl_item else {
                    continue;
                };
                let fn_name = method.sig.ident.to_string();
                let mut collector = SetCollector {
                    fn_name,
                    entries: vec![],
                };
                collector.visit_block(&method.block);
                all_entries.extend(collector.entries);
            }

            // Group by key; flag if the same key has different type hints.
            let keys: Vec<String> = {
                let mut ks: Vec<String> = all_entries.iter().map(|e| e.key.clone()).collect();
                ks.sort();
                ks.dedup();
                ks
            };

            for key in &keys {
                let entries_for_key: Vec<&SetEntry> =
                    all_entries.iter().filter(|e| &e.key == key).collect();
                if entries_for_key.len() < 2 {
                    continue;
                }
                let first_hint = &entries_for_key[0].type_hint;
                let mismatch = entries_for_key
                    .iter()
                    .skip(1)
                    .find(|e| &e.type_hint != first_hint);
                if let Some(second) = mismatch {
                    let first = entries_for_key[0];
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: second.line,
                        function_name: second.fn_name.clone(),
                        description: format!(
                            "Storage key `{key}` is written with type `{}` in `{}` (line {}) \
                             but with type `{}` in `{}` (line {}). Readers expecting one type \
                             will deserialize garbage when the other type was stored.",
                            first.type_hint,
                            first.fn_name,
                            first.line,
                            second.type_hint,
                            second.fn_name,
                            second.line,
                        ),
                    });
                }
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
    fn flags_same_key_different_types() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_addr(env: Env, addr: Address) {
        env.storage().instance().set(&"owner", &addr);
    }
    pub fn set_count(env: Env) {
        env.storage().instance().set(&"owner", &42i128);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = StorageTypeConfusionCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("owner"));
        Ok(())
    }

    #[test]
    fn no_finding_when_same_key_same_type() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_a(env: Env, addr: Address) {
        env.storage().instance().set(&"owner", &addr);
    }
    pub fn set_b(env: Env, addr: Address) {
        env.storage().instance().set(&"owner", &addr);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = StorageTypeConfusionCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_for_different_keys() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_a(env: Env, addr: Address) {
        env.storage().instance().set(&"admin", &addr);
    }
    pub fn set_b(env: Env) {
        env.storage().instance().set(&"count", &0u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = StorageTypeConfusionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_single_writer() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_a(env: Env) {
        env.storage().instance().set(&"count", &0u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = StorageTypeConfusionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

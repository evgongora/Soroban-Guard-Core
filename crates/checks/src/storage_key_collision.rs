//! Flags potential storage key collisions where different keys have similar names that could lead to accidental overwrites.
//!
//! Storage keys should be unique and descriptive. Similar key names (e.g., "owner", "owner_addr", "owner_address")
//! can lead to accidental overwrites if developers use the wrong key in different contexts.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "storage-key-collision";

/// Flags storage keys that have similar names and may cause accidental overwrites.
/// Detects patterns like "owner", "owner_addr", "owner_address" in the same contract.
pub struct StorageKeyCollisionCheck;

impl Check for StorageKeyCollisionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // Collect all storage keys used in the contract
        let mut keys = Vec::new();

        // Look for storage set calls with string literal or path keys
        for item in &file.items {
            match item {
                syn::Item::Fn(func) => {
                    let mut v = KeyVisitor { keys: &mut keys };
                    v.visit_item_fn(func);
                }
                syn::Item::Impl(impl_block) => {
                    for impl_item in &impl_block.items {
                        if let syn::ImplItem::Fn(func) = impl_item {
                            let mut v = KeyVisitor { keys: &mut keys };
                            v.visit_impl_item_fn(func);
                        }
                    }
                }
                _ => {}
            }
        }

        // Check for similar keys
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                let key1 = &keys[i].0;
                let key2 = &keys[j].0;

                // Check for similarity: same prefix or suffix, or one is substring of another
                if key1.len() >= 3
                    && key2.len() >= 3
                    && (key1.to_lowercase().starts_with(&key2.to_lowercase())
                        || key2.to_lowercase().starts_with(&key1.to_lowercase())
                        || key1.to_lowercase().contains(&key2.to_lowercase())
                        || key2.to_lowercase().contains(&key1.to_lowercase()))
                {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: keys[i].1,
                        function_name: String::new(),
                        description: format!("Potential storage key collision between '{}' and '{}'. Consider using more distinct key names to avoid accidental overwrites.", key1, key2),
                    });
                }
            }
        }

        out
    }
}

struct KeyVisitor<'a> {
    keys: &'a mut Vec<(String, usize)>,
}

impl<'a> Visit<'a> for KeyVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if i.method == "set" {
            if let Some(arg) = i.args.first() {
                if let Some(key) = extract_key_name(arg) {
                    self.keys.push((key, i.span().start().line));
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn extract_key_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(r) => extract_key_name(&r.expr),
        Expr::Lit(l) => {
            if let syn::Lit::Str(s) = &l.lit {
                Some(s.value())
            } else {
                None
            }
        }
        Expr::Path(p) => p.path.get_ident().map(|id| id.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(StorageKeyCollisionCheck.run(&file, src))
    }

    #[test]
    fn flags_similar_keys() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const OWNER: soroban_sdk::Symbol = symbol_short!("owner");
const OWNER_ADDR: soroban_sdk::Symbol = symbol_short!("owner_addr");

#[contractimpl]
impl C {
    pub fn store_owner(env: Env, owner: soroban_sdk::Address) {
        env.storage().persistent().set(&OWNER, &owner);
        env.storage().persistent().set(&OWNER_ADDR, &owner);
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
    fn passes_when_keys_are_distinct() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const OWNER: soroban_sdk::Symbol = symbol_short!("owner");
const BALANCE: soroban_sdk::Symbol = symbol_short!("balance");

#[contractimpl]
impl C {
    pub fn store_data(env: Env, owner: soroban_sdk::Address, balance: i128) {
        env.storage().persistent().set(&OWNER, &owner);
        env.storage().persistent().set(&BALANCE, &balance);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}

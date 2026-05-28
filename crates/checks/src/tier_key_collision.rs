//! Detects the same string-literal key used in both temporary and
//! persistent/instance storage across any functions in a contract.
//!
//! When the same key string is shared between `temporary()` and
//! `persistent()`/`instance()` storage, reads from one tier will never see
//! writes to the other, producing stale or empty results.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "tier-key-collision";

/// Flags contracts where the same string-literal key is used with both
/// `temporary()` and `persistent()`/`instance()` storage (across all functions).
pub struct TierKeyCollisionCheck;

impl Check for TierKeyCollisionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        // key -> list of (tier, line, fn_name)
        let mut key_uses: HashMap<String, Vec<(String, usize, String)>> = HashMap::new();

        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = KeyCollector {
                fn_name: fn_name.clone(),
                key_uses: &mut key_uses,
            };
            visitor.visit_block(&method.block);
        }

        let mut out = Vec::new();

        for (key, uses) in &key_uses {
            let has_temp = uses.iter().any(|(t, _, _)| t == "temporary");
            let has_persistent = uses
                .iter()
                .any(|(t, _, _)| matches!(t.as_str(), "persistent" | "instance"));

            if has_temp && has_persistent {
                for (tier, line, fn_name) in uses {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: *line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Key `{}` is used in both temporary and persistent/instance storage \
                             (tier `{}` here). Reads from one tier will never see writes to the \
                             other, causing stale or empty results.",
                            key, tier
                        ),
                    });
                }
            }
        }

        out
    }
}

struct KeyCollector<'a> {
    fn_name: String,
    key_uses: &'a mut HashMap<String, Vec<(String, usize, String)>>,
}

impl<'a> Visit<'_> for KeyCollector<'a> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let method_name = i.method.to_string();
        if matches!(method_name.as_str(), "set" | "get" | "remove" | "has") {
            if let Some((tier, key)) = extract_tier_and_key(&i.receiver, &i.args) {
                let line = i.span().start().line;
                self.key_uses
                    .entry(key)
                    .or_default()
                    .push((tier, line, self.fn_name.clone()));
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn extract_tier_and_key(
    receiver: &Expr,
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<(String, String)> {
    let tier = extract_tier(receiver)?;
    let key = extract_string_key(args)?;
    Some((tier, key))
}

fn extract_tier(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => {
            let method = m.method.to_string();
            if matches!(method.as_str(), "persistent" | "instance" | "temporary") {
                return Some(method);
            }
            extract_tier(&m.receiver)
        }
        Expr::Field(f) => extract_tier(&f.base),
        _ => None,
    }
}

fn extract_string_key(
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<String> {
    args.iter().next().and_then(|arg| match arg {
        // "literal"
        Expr::Lit(lit_expr) => match &lit_expr.lit {
            Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        // &"literal"
        Expr::Reference(r) => match &*r.expr {
            Expr::Lit(lit_expr) => match &lit_expr.lit {
                Lit::Str(s) => Some(s.value()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_same_key_in_temp_and_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store_temp(env: Env) {
        env.storage().temporary().set("session", &1u32);
    }
    pub fn store_persistent(env: Env) {
        env.storage().persistent().set("session", &1u32);
    }
}
"#,
        )?;
        let hits = TierKeyCollisionCheck.run(&file, "");
        assert_eq!(hits.len(), 2, "expected 2 findings, got {:?}", hits);
        assert!(hits.iter().all(|f| f.severity == Severity::Medium));
        Ok(())
    }

    #[test]
    fn flags_same_key_in_temp_and_instance() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn write(env: Env) {
        env.storage().temporary().set("nonce", &42u32);
        env.storage().instance().set("nonce", &42u32);
    }
}
"#,
        )?;
        let hits = TierKeyCollisionCheck.run(&file, "");
        assert_eq!(hits.len(), 2);
        Ok(())
    }

    #[test]
    fn passes_same_key_same_tier() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn write(env: Env) {
        env.storage().persistent().set("balance", &100u32);
    }
    pub fn read(env: Env) -> u32 {
        env.storage().persistent().get("balance").unwrap_or(0)
    }
}
"#,
        )?;
        let hits = TierKeyCollisionCheck.run(&file, "");
        assert!(hits.is_empty(), "expected no findings, got {:?}", hits);
        Ok(())
    }

    #[test]
    fn passes_different_keys_different_tiers() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn write(env: Env) {
        env.storage().temporary().set("session_key", &1u32);
        env.storage().persistent().set("balance_key", &100u32);
    }
}
"#,
        )?;
        let hits = TierKeyCollisionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_temp_only() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn write(env: Env) {
        env.storage().temporary().set("token", &1u32);
    }
    pub fn read(env: Env) -> u32 {
        env.storage().temporary().get("token").unwrap_or(0)
    }
}
"#,
        )?;
        let hits = TierKeyCollisionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_cross_function_collision() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn init(env: Env) {
        env.storage().persistent().set("config", &true);
    }
    pub fn reset(env: Env) {
        // Bug: uses temporary for the same "config" key
        env.storage().temporary().set("config", &false);
    }
}
"#,
        )?;
        let hits = TierKeyCollisionCheck.run(&file, "");
        assert_eq!(hits.len(), 2);
        // Each finding should reference the correct function
        let fn_names: Vec<&str> = hits.iter().map(|f| f.function_name.as_str()).collect();
        assert!(fn_names.contains(&"init"));
        assert!(fn_names.contains(&"reset"));
        Ok(())
    }
}

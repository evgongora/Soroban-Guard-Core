//! Map used with excessive distinct string literal keys (key explosion).
//!
//! Using a Map with a large or unbounded set of string literal keys (more than ~10 distinct
//! literals in the same function) instead of a typed struct or enum key is a code smell.
//! It bypasses Soroban's type-safe storage key system and makes storage layout hard to audit.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::visit::{self, Visit};
use syn::{Expr, ExprLit, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "map-key-explosion";
const MAX_DISTINCT_KEYS: usize = 8;

/// Detects functions that insert into a Map with more than 8 distinct string literal keys
/// in the same function body. This pattern indicates potential key explosion and bypasses
/// Soroban's type-safe storage key system.
pub struct MapKeyExplosionCheck;

impl Check for MapKeyExplosionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = MapKeyVisitor {
                string_keys: HashSet::new(),
            };
            v.visit_block(&method.block);
            if v.string_keys.len() > MAX_DISTINCT_KEYS {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: method.sig.ident.span().start().line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{}` uses Map with {} distinct string literal keys (threshold: {}). \
                         This 'key explosion' pattern bypasses Soroban's type-safe storage system. \
                         Consider using a typed struct or enum key for better type safety and auditability.",
                        fn_name, v.string_keys.len(), MAX_DISTINCT_KEYS
                    ),
                });
            }
        }
        out
    }
}

fn is_map_set_call(m: &ExprMethodCall) -> bool {
    if m.method != "set" {
        return false;
    }
    // Check if receiver is a Map type (simplified check)
    // In a real implementation, you'd check the type more thoroughly
    true
}

fn extract_string_literal_key(call: &ExprMethodCall) -> Option<String> {
    if call.args.len() >= 2 {
        if let Some(Expr::Lit(ExprLit {
            lit: Lit::Str(lit_str),
            ..
        })) = call.args.first()
        {
            return Some(lit_str.value());
        }
    }
    None
}

struct MapKeyVisitor {
    string_keys: HashSet<String>,
}

impl Visit<'_> for MapKeyVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_map_set_call(i) {
            if let Some(key) = extract_string_literal_key(i) {
                self.string_keys.insert(key);
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
    fn detects_excessive_string_keys() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn vulnerable_key_explosion(env: Env) {
        let mut map = Map::new(&env);
        map.set("key1", 1);
        map.set("key2", 2);
        map.set("key3", 3);
        map.set("key4", 4);
        map.set("key5", 5);
        map.set("key6", 6);
        map.set("key7", 7);
        map.set("key8", 8);
        map.set("key9", 9); // This makes it 9 keys
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MapKeyExplosionCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn allows_few_string_keys() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_few_keys(env: Env) {
        let mut map = Map::new(&env);
        map.set("key1", 1);
        map.set("key2", 2);
        map.set("key3", 3);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MapKeyExplosionCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_non_string_keys() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_typed_keys(env: Env) {
        let mut map = Map::new(&env);
        map.set(Key::First, 1);
        map.set(Key::Second, 2);
        map.set(Key::Third, 3);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MapKeyExplosionCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_exactly_eight_keys() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn exactly_eight_keys(env: Env) {
        let mut map = Map::new(&env);
        map.set("key1", 1);
        map.set("key2", 2);
        map.set("key3", 3);
        map.set("key4", 4);
        map.set("key5", 5);
        map.set("key6", 6);
        map.set("key7", 7);
        map.set("key8", 8);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MapKeyExplosionCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty()); // Exactly 8 should be allowed
    }
}

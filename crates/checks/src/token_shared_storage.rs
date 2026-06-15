//! Detects token contracts that share storage namespace with governance/staking logic.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "token-shared-storage";

const TOKEN_KEYS: &[&str] = &["balance", "allowance", "total_supply"];
const GOV_KEYS: &[&str] = &["vote", "proposal", "stake", "reward"];

/// Flags files where storage keys contain both token-domain terms
/// (balance/allowance/total_supply) and governance/staking terms
/// (vote/proposal/stake/reward), indicating a shared namespace collision risk.
pub struct TokenSharedStorageCheck;

impl Check for TokenSharedStorageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut collector = KeyCollector {
            token_keys: Vec::new(),
            gov_keys: Vec::new(),
            first_line: None,
        };
        collector.visit_file(file);

        if !collector.token_keys.is_empty() && !collector.gov_keys.is_empty() {
            let line = collector.first_line.unwrap_or(1);
            return vec![Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line,
                function_name: String::new(),
                description: format!(
                    "Token storage keys ({}) and governance/staking keys ({}) share the same \
                     storage namespace. This risks key collisions and unintended data corruption. \
                     Separate token and non-token logic into distinct contracts or storage domains.",
                    collector.token_keys.join(", "),
                    collector.gov_keys.join(", "),
                ),
            }];
        }

        Vec::new()
    }
}

struct KeyCollector {
    token_keys: Vec<String>,
    gov_keys: Vec<String>,
    first_line: Option<usize>,
}

impl Visit<'_> for KeyCollector {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        // Look for .set(&"key", ...) or .get(&"key") calls on storage
        if matches!(
            i.method.to_string().as_str(),
            "set" | "get" | "has" | "remove"
        ) {
            if let Some(first_arg) = i.args.first() {
                if let Some(key) = extract_string_key(first_arg) {
                    let lower = key.to_lowercase();
                    if TOKEN_KEYS.iter().any(|k| lower.contains(k)) {
                        if self.first_line.is_none() {
                            self.first_line = Some(i.span().start().line);
                        }
                        if !self.token_keys.contains(&key) {
                            self.token_keys.push(key);
                        }
                    } else if GOV_KEYS.iter().any(|k| lower.contains(k)) {
                        if self.first_line.is_none() {
                            self.first_line = Some(i.span().start().line);
                        }
                        if !self.gov_keys.contains(&key) {
                            self.gov_keys.push(key);
                        }
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn extract_string_key(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(r) => extract_string_key(&r.expr),
        Expr::Lit(lit) => {
            if let syn::Lit::Str(s) = &lit.lit {
                Some(s.value())
            } else {
                None
            }
        }
        // Also handle symbol_short!("key") — just look at string literals anywhere
        Expr::Macro(m) => {
            let tokens = m.mac.tokens.to_string();
            // Extract quoted string from macro tokens
            let s: String = tokens.chars().collect();
            if let Some(start) = s.find('"') {
                if let Some(end) = s[start + 1..].find('"') {
                    return Some(s[start + 1..start + 1 + end].to_string());
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        TokenSharedStorageCheck.run(&file, src)
    }

    #[test]
    fn flags_mixed_token_and_governance_keys() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env) {
        env.storage().instance().set(&"balance_user", &100i128);
        env.storage().instance().set(&"proposal_id", &1u32);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn flags_token_and_stake_keys() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env) {
        env.storage().persistent().set(&"allowance_key", &50i128);
        env.storage().persistent().set(&"stake_amount", &200i128);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn does_not_flag_token_only() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env) {
        env.storage().instance().set(&"balance_key", &100i128);
        env.storage().instance().set(&"allowance_key", &50i128);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn does_not_flag_governance_only() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env) {
        env.storage().instance().set(&"vote_count", &10u32);
        env.storage().instance().set(&"proposal_id", &1u32);
    }
}
"#);
        assert!(hits.is_empty());
    }
}

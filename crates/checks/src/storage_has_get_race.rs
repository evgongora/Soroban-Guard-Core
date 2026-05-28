//! Detects TTL race: `has(key)` and `get(key)` on the same storage tier with intervening
//! host calls that could allow the entry to expire between the check and the read.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "storage-ttl-has-get-race";

/// Flags functions that call `has(key)` then later call `get(key)` on the same storage tier
/// with at least one intervening host call, creating a window where the TTL may expire.
pub struct StorageHasGetRaceCheck;

impl Check for StorageHasGetRaceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = RaceVisitor {
                fn_name,
                has_seen: Vec::new(),
                call_count_since_has: 0,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn storage_tier(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::MethodCall(m) => {
            let name = m.method.to_string();
            match name.as_str() {
                "persistent" => Some("persistent"),
                "temporary" => Some("temporary"),
                "instance" => Some("instance"),
                _ => storage_tier(&m.receiver),
            }
        }
        _ => None,
    }
}

fn receiver_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "storage" || receiver_contains_storage(&m.receiver),
        _ => false,
    }
}

fn is_storage_has(m: &ExprMethodCall) -> Option<&'static str> {
    if m.method == "has" && receiver_contains_storage(&m.receiver) {
        return storage_tier(&m.receiver);
    }
    None
}

fn is_storage_get(m: &ExprMethodCall) -> Option<&'static str> {
    if m.method == "get" && receiver_contains_storage(&m.receiver) {
        return storage_tier(&m.receiver);
    }
    None
}

// ── visitor ──────────────────────────────────────────────────────────────────

/// Tracks (tier, call_count_at_has) pairs seen so far in the function.
struct RaceVisitor<'a> {
    fn_name: String,
    /// (tier, host-call count when `has` was seen)
    has_seen: Vec<(&'static str, usize)>,
    call_count_since_has: usize,
    out: &'a mut Vec<Finding>,
}

/// Minimum number of intervening method calls to consider a "race window".
const RACE_THRESHOLD: usize = 1;

impl Visit<'_> for RaceVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if let Some(tier) = is_storage_has(i) {
            self.has_seen.push((tier, self.call_count_since_has));
            // Don't recurse into the storage chain — sub-calls are not host calls.
            return;
        }
        if let Some(get_tier) = is_storage_get(i) {
            let race = self.has_seen.iter().any(|(has_tier, count_at_has)| {
                *has_tier == get_tier
                    && (self.call_count_since_has - count_at_has) >= RACE_THRESHOLD
            });
            if race {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "`{}` calls `has()` then `get()` on `{}` storage with intervening host \
                         calls. The TTL may expire between the check and the read, causing an \
                         unexpected panic. Use `get()` directly with `unwrap_or_default()`, or \
                         extend the TTL immediately after `has()`.",
                        self.fn_name, get_tier
                    ),
                });
            }
            // Don't recurse into the storage chain.
            return;
        }
        // Only count non-storage method calls as potential host calls in the gap.
        if !receiver_contains_storage(i) {
            self.call_count_since_has += 1;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        StorageHasGetRaceCheck.run(&file, src)
    }

    #[test]
    fn flags_has_then_host_call_then_get() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn read(env: Env, key: u32) {
        if env.storage().persistent().has(&key) {
            env.current_contract_address(); // intervening host call
            let _v = env.storage().persistent().get(&key);
        }
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn no_flag_when_get_immediately_follows_has() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn read(env: Env, key: u32) {
        if env.storage().persistent().has(&key) {
            let _v = env.storage().persistent().get(&key);
        }
    }
}
"#);
        // has and get are adjacent — no intervening calls counted
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn no_flag_without_has() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn read(env: Env, key: u32) {
        let _v = env.storage().persistent().get(&key);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_flag_different_tiers() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn read(env: Env, key: u32) {
        if env.storage().temporary().has(&key) {
            env.current_contract_address();
            let _v = env.storage().persistent().get(&key);
        }
    }
}
"#);
        // has on temporary, get on persistent — different tiers, no race
        assert!(hits.is_empty());
    }
}

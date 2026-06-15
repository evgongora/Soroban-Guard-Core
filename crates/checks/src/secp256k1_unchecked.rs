//! `env.crypto().secp256k1_recover(...)` result not compared against a trusted key.
//!
//! If the recovered public key is never compared (via `==`) against a stored
//! trusted key, the recovery result is meaningless and provides no authentication.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, Pat};

const CHECK_NAME: &str = "secp256k1-unchecked";

fn is_secp256k1_recover(m: &ExprMethodCall) -> bool {
    if m.method != "secp256k1_recover" {
        return false;
    }
    // Receiver must be a crypto() call chain.
    receiver_chain_contains_crypto(&m.receiver)
}

fn receiver_chain_contains_crypto(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "crypto" {
                return true;
            }
            receiver_chain_contains_crypto(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_crypto(&f.base),
        _ => false,
    }
}

/// Collect all local binding names that are assigned from `secp256k1_recover`.
fn collect_recover_bindings(block: &syn::Block) -> Vec<String> {
    let mut collector = RecoverBindingCollector { bindings: vec![] };
    collector.visit_block(block);
    collector.bindings
}

struct RecoverBindingCollector {
    bindings: Vec<String>,
}

impl<'ast> Visit<'ast> for RecoverBindingCollector {
    fn visit_local(&mut self, i: &'ast syn::Local) {
        // let <pat> = <init>;
        if let Some(init) = &i.init {
            let mut finder = RecoverCallFinder { found: false };
            finder.visit_expr(&init.expr);
            if finder.found {
                // Extract the binding name from the pattern (unwrap Pat::Type).
                let pat = match &i.pat {
                    Pat::Type(pt) => &*pt.pat,
                    p => p,
                };
                if let Pat::Ident(pi) = pat {
                    self.bindings.push(pi.ident.to_string());
                }
            }
        }
        visit::visit_local(self, i);
    }
}

struct RecoverCallFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for RecoverCallFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_secp256k1_recover(i) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Check whether any of the given binding names appear in an `==` comparison.
fn bindings_are_eq_compared(block: &syn::Block, bindings: &[String]) -> bool {
    let mut checker = EqCompareChecker {
        bindings,
        found: false,
    };
    checker.visit_block(block);
    checker.found
}

struct EqCompareChecker<'a> {
    bindings: &'a [String],
    found: bool,
}

fn expr_contains_binding(expr: &Expr, bindings: &[String]) -> bool {
    match expr {
        Expr::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                return bindings.contains(&seg.ident.to_string());
            }
            false
        }
        Expr::Reference(r) => expr_contains_binding(&r.expr, bindings),
        Expr::MethodCall(m) => expr_contains_binding(&m.receiver, bindings),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for EqCompareChecker<'_> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Eq(_) | BinOp::Ne(_))
            && (expr_contains_binding(&i.left, self.bindings)
                || expr_contains_binding(&i.right, self.bindings))
        {
            self.found = true;
        }
        visit::visit_expr_binary(self, i);
    }

    // Also catch assert_eq! / assert_ne! macros (both Stmt::Macro and Expr::Macro forms).
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let mac_name = i
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(mac_name.as_str(), "assert_eq" | "assert_ne" | "require") {
            let tokens = i.tokens.to_string();
            if self.bindings.iter().any(|b| tokens.contains(b.as_str())) {
                self.found = true;
            }
        }
        visit::visit_macro(self, i);
    }
}

pub struct Secp256k1UncheckedCheck;

impl Check for Secp256k1UncheckedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Find all secp256k1_recover call sites (inline, not just let bindings).
            let mut inline_finder = InlineRecoverFinder {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            // We'll do a two-pass approach: collect bindings, then check comparisons.
            let bindings = collect_recover_bindings(&method.block);
            if bindings.is_empty() {
                // Check for inline (non-bound) recover calls.
                inline_finder.visit_block(&method.block);
                continue;
            }
            if !bindings_are_eq_compared(&method.block, &bindings) {
                // Find the line of the first recover call.
                let mut line_finder = RecoverLineFinder { line: 0 };
                line_finder.visit_block(&method.block);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: line_finder.line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` calls `secp256k1_recover()` but the recovered \
                         public key is never compared (`==`) against a trusted key. The \
                         recovery result provides no authentication guarantee unless verified \
                         against a stored or expected public key."
                    ),
                });
            }
        }
        out
    }
}

struct RecoverLineFinder {
    line: usize,
}

impl<'ast> Visit<'ast> for RecoverLineFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line == 0 && is_secp256k1_recover(i) {
            self.line = i.span().start().line;
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Flag inline secp256k1_recover calls that are not assigned to any binding.
struct InlineRecoverFinder<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for InlineRecoverFinder<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_secp256k1_recover(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` calls `secp256k1_recover()` but the result is not stored \
                     or compared against a trusted key. The recovery provides no \
                     authentication guarantee.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_recover_result_not_compared() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn verify(env: Env, msg: Bytes, sig: Bytes) {
        let _recovered = env.crypto().secp256k1_recover(&msg, &sig, 0);
        // BUG: recovered key is never compared to anything
    }
}
"#;
        let file = parse_file(src)?;
        let hits = Secp256k1UncheckedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("secp256k1_recover"));
        Ok(())
    }

    #[test]
    fn no_finding_when_result_eq_compared() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Bytes, BytesN, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn verify(env: Env, msg: Bytes, sig: Bytes) {
        let recovered: BytesN<65> = env.crypto().secp256k1_recover(&msg, &sig, 0);
        let trusted: BytesN<65> = env.storage().persistent()
            .get(&symbol_short!("pubkey")).unwrap();
        assert_eq!(recovered, trusted);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = Secp256k1UncheckedCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_when_result_compared_with_eq_op() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Bytes, BytesN, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn verify(env: Env, msg: Bytes, sig: Bytes) {
        let recovered: BytesN<65> = env.crypto().secp256k1_recover(&msg, &sig, 0);
        let trusted: BytesN<65> = env.storage().persistent()
            .get(&symbol_short!("pubkey")).unwrap();
        if recovered == trusted {
            // authorized
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = Secp256k1UncheckedCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn flags_inline_recover_not_bound() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn verify(env: Env, msg: Bytes, sig: Bytes) {
        // result discarded entirely
        let _ = env.crypto().secp256k1_recover(&msg, &sig, 0);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = Secp256k1UncheckedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}

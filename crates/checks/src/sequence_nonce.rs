//! Using `env.ledger().sequence()` as a replay-protection nonce without storing the last-used sequence number in persistent storage provides no replay protection.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File};

const CHECK_NAME: &str = "sequence-nonce";

/// Detects `env.ledger().sequence()` used in comparisons (>, >=, ==) without a subsequent
/// `env.storage().persistent().set(...)` call in the same function body.
pub struct SequenceNonceCheck;

impl Check for SequenceNonceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = SequenceVisitor {
                sequence_used_in_comparison: false,
                persistent_set_called: false,
            };
            v.visit_block(&method.block);
            if v.sequence_used_in_comparison && !v.persistent_set_called {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: method.sig.ident.span().start().line,
                    function_name: fn_name,
                    description: "Function uses `env.ledger().sequence()` in a comparison but does not store the sequence value in persistent storage. This provides no replay protection as the same transaction can be replayed in the same ledger window.".to_string(),
                });
            }
        }
        out
    }
}

fn is_sequence_call(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "sequence" {
                // Check if receiver is ledger()
                if let Expr::MethodCall(ledger_call) = &*m.receiver {
                    if ledger_call.method == "ledger" {
                        // Check if receiver is env
                        if let Expr::Path(p) = &*ledger_call.receiver {
                            return p.path.is_ident("env");
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn is_persistent_set_call(m: &ExprMethodCall) -> bool {
    if m.method != "set" {
        return false;
    }
    // Check if receiver chain contains storage().persistent()
    receiver_chain_contains_persistent(&m.receiver)
}

fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "persistent" {
                return true;
            }
            receiver_chain_contains_persistent(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent(&f.base),
        _ => false,
    }
}

struct SequenceVisitor {
    sequence_used_in_comparison: bool,
    persistent_set_called: bool,
}

impl Visit<'_> for SequenceVisitor {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        // Check if left or right side is sequence() call
        if is_sequence_call(&i.left) || is_sequence_call(&i.right) {
            // Check if it's a comparison operator
            match i.op {
                BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Eq(_) => {
                    self.sequence_used_in_comparison = true;
                }
                _ => {}
            }
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_persistent_set_call(i) {
            self.persistent_set_called = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_sequence_comparison_without_persistent_set() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn vulnerable_nonce(env: Env, nonce: u32) {
        if env.ledger().sequence() == nonce {
            // do something
        }
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = SequenceNonceCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn allows_sequence_comparison_with_persistent_set() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_nonce(env: Env, nonce: u32) {
        if env.ledger().sequence() == nonce {
            env.storage().persistent().set(&DataKey::LastNonce, &nonce);
        }
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = SequenceNonceCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_sequence_without_comparison() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn just_sequence(env: Env) {
        let seq = env.ledger().sequence();
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = SequenceNonceCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

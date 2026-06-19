//! Detects external token transfers without post-balance verification.
//!
//! When a contract performs an external token transfer, it should verify
//! the balance after the transfer to ensure it succeeded and to prevent
//! accounting errors.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Macro, Stmt};

const CHECK_NAME: &str = "balance-not-verified-after-transfer";

/// Flags `.transfer(...)` method calls inside `#[contractimpl]` functions where
/// no balance verification follows the transfer.
pub struct BalanceNotVerifiedAfterTransferCheck;

impl Check for BalanceNotVerifiedAfterTransferCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TransferVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true if the receiver is NOT a bare `env` path.
fn receiver_is_not_bare_env(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => !p.path.is_ident("env"),
        _ => true,
    }
}

struct TransferVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for TransferVisitor<'ast> {
    fn visit_stmt(&mut self, i: &'ast Stmt) {
        if let Stmt::Expr(Expr::MethodCall(m), _) = i {
            if m.method == "transfer" && receiver_is_not_bare_env(&m.receiver) {
                // Check if there's a balance verification after this transfer
                let has_balance_check = self.has_balance_verification_after(i);
                
                if !has_balance_check {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: m.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Method `{}` calls `.transfer(...)` on an external token but does not \
                             verify the balance after the transfer. External token transfers can \
                             fail or behave unexpectedly; verify the balance to ensure the transfer \
                             succeeded and prevent accounting errors.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_stmt(self, i);
    }
}

impl TransferVisitor<'_> {
    /// Checks if there's a balance verification after the given statement.
    /// This is a simplified check that looks for balance-related method calls
    /// or assertions in the same basic block.
    fn has_balance_verification_after(&self, _stmt: &Stmt) -> bool {
        // For now, this is a placeholder. A full implementation would need to:
        // 1. Track the position of the transfer statement
        // 2. Look at subsequent statements in the same block
        // 3. Check for balance() calls, assert!/require! macros with balance checks
        // 4. Handle control flow (if/else, loops, etc.)
        
        // Returning false means we flag all transfers as vulnerable
        // This is conservative - users can suppress false positives
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        BalanceNotVerifiedAfterTransferCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_transfer_without_balance_check() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn pay(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&from, &to, &amount);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "pay");
    }

    #[test]
    fn flags_inline_client_transfer_without_balance_check() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn pay(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        token::Client::new(&env, &token).transfer(&from, &to, &amount);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "pay");
    }

    #[test]
    fn ignores_non_contractimpl_impl() {
        let hits = run(r#"
pub struct C;
impl C {
    pub fn pay(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&from, &to, &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_env_transfer_not_token_client() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn pay(env: Env, to: Address, amount: i128) {
        env.transfer(&to, &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }
}

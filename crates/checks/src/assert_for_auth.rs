//! Using `assert!` macro for access control instead of `require_auth` in Soroban contracts.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, File, Macro};

const CHECK_NAME: &str = "assert-for-auth";

/// Detects `assert!(...)` macro invocations in `#[contractimpl]` functions where the
/// condition involves an Address-typed variable compared with == or !=.
pub struct AssertForAuthCheck;

impl Check for AssertForAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = AssertVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

struct AssertVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for AssertVisitor<'_> {
    fn visit_macro(&mut self, i: &Macro) {
        let macro_name = i.path.segments.last().map(|s| s.ident.to_string());

        if let Some(name) = macro_name {
            if name == "assert" {
                // Parse the macro tokens to check for Address comparison
                if let Ok(condition) = i.parse_body::<Expr>() {
                    if contains_address_comparison(&condition) {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Function `{}` uses `assert!` for access control with Address comparison. \
                                 Use `require_auth()` instead for proper authorization that integrates \
                                 with Soroban's authorization framework.",
                                self.fn_name
                            ),
                        });
                    }
                }
            }
        }

        visit::visit_macro(self, i);
    }
}

fn contains_address_comparison(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(bin) => {
            // Check for == or != operations
            matches!(bin.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) &&
            // Check if either side is an Address-typed identifier
            (is_address_identifier(&bin.left) || is_address_identifier(&bin.right))
        }
        _ => false,
    }
}

fn is_address_identifier(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => {
            // This is a simplified check - in a real implementation,
            // you'd need to resolve the type from the function parameters or variables
            // For now, we'll assume any identifier could be an Address
            // A more robust implementation would check the type annotations
            path.path.segments.len() == 1
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_assert_with_address_equality() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn vulnerable_auth(env: Env, caller: Address) {
        assert!(caller == admin);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AssertForAuthCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_assert_with_address_inequality() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn vulnerable_auth_ne(env: Env, caller: Address) {
        assert!(caller != admin);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AssertForAuthCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn allows_assert_without_address() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_assert(env: Env) {
        assert!(1 + 1 == 2);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AssertForAuthCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_require_auth() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_auth(env: Env, caller: Address) {
        env.require_auth(&caller);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AssertForAuthCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

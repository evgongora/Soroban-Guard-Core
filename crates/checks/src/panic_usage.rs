//! Detects `panic!` and `unreachable!` macro invocations in contract impl blocks.
//!
//! Panicking in Soroban contracts causes transaction abort with unhelpful errors.
//! Contracts should use Err returns or Soroban's `panic_with_error!` macro for
//! structured error reporting.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{File, Macro};

const CHECK_NAME: &str = "panic-usage";

/// Flags `panic!(...)`  and `unreachable!(...)`  macro invocations inside
/// `#[contractimpl]` function bodies.
pub struct PanicUsageCheck;

impl Check for PanicUsageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = PanicMacroScan {
                fn_name,
                out: &mut out,
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

struct PanicMacroScan<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for PanicMacroScan<'_> {
    fn visit_macro(&mut self, i: &'ast Macro) {
        let macro_name = i.path.segments.last().map(|s| s.ident.to_string());

        if let Some(name) = macro_name {
            if matches!(name.as_str(), "panic" | "unreachable") {
                let line = i.span().start().line;
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Method `{}` contains `{}!` macro. Panicking in Soroban contracts causes \
                         transaction abort with unhelpful errors. Use Err returns or \
                         `panic_with_error!` for structured error reporting.",
                        self.fn_name, name
                    ),
                });
            }
        }

        visit::visit_macro(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_panic_in_contractimpl() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn risky_op(env: Env) {
        panic!("This is bad");
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = PanicUsageCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].function_name, "risky_op");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn detects_unreachable_in_contractimpl() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn impossible(env: Env) {
        unreachable!("This should never happen");
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = PanicUsageCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn allows_err_returns() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_op(env: Env) -> Result<bool, Error> {
        Err(Error::InvalidInput)
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = PanicUsageCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_panic_outside_contractimpl() {
        let code = r#"
fn regular_function() {
    panic!("This is fine outside contracts");
}

#[contractimpl]
impl MyContract {
    pub fn safe(env: Env) {}
}
        "#;
        let file = parse_file(code).unwrap();
        let check = PanicUsageCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

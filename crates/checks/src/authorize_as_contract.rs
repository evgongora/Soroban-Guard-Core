//! Authorize current contract without prior require_auth.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "authorize-as-contract";

/// Detects `env.authorize_as_current_contract(...)` calls in `#[contractimpl]` functions
/// without a preceding `require_auth` or `require_auth_for_args` call in the same function body.
pub struct AuthorizeAsContractCheck;

impl Check for AuthorizeAsContractCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = AuthCallScan {
                require_auth_found: false,
                authorize_found: false,
            };
            scan.visit_block(&method.block);
            if scan.authorize_found && !scan.require_auth_found {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: method.sig.ident.span().start().line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{}` calls `env.authorize_as_current_contract(...)` without prior `require_auth()` or `require_auth_for_args()`. This may allow unauthorized callers to escalate contract authorization.",
                        fn_name
                    ),
                });
            }
        }
        out
    }
}

fn is_require_auth_call(m: &ExprMethodCall) -> bool {
    (m.method == "require_auth" || m.method == "require_auth_for_args")
        && matches!(&*m.receiver, Expr::Path(p) if p.path.is_ident("env"))
}

fn is_authorize_current_contract_call(m: &ExprMethodCall) -> bool {
    m.method == "authorize_as_current_contract"
        && matches!(&*m.receiver, Expr::Path(p) if p.path.is_ident("env"))
}

struct AuthCallScan {
    require_auth_found: bool,
    authorize_found: bool,
}

impl<'ast> Visit<'ast> for AuthCallScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_require_auth_call(i) {
            self.require_auth_found = true;
        }
        if is_authorize_current_contract_call(i) {
            self.authorize_found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_authorize_without_require_auth() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn vulnerable_authorize(env: Env) {
        env.authorize_as_current_contract();
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AuthorizeAsContractCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn allows_authorize_with_require_auth() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_authorize(env: Env, admin: Address) {
        env.require_auth(&admin);
        env.authorize_as_current_contract();
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AuthorizeAsContractCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_authorize_with_require_auth_for_args() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn safe_authorize_args(env: Env, admin: Address) {
        env.require_auth_for_args((admin, 123));
        env.authorize_as_current_contract();
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = AuthorizeAsContractCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}

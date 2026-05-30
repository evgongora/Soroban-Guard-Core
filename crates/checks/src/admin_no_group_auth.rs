//! Detects contracts where more than 2 distinct `#[contractimpl]` functions each
//! independently call `require_auth` on a value read from the same admin storage
//! key, instead of using a shared helper.  Duplicated auth logic is error-prone:
//! a future change to the auth pattern must be replicated everywhere.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "admin-no-group-auth";

/// Heuristic: a local variable whose name contains "admin" or "owner" and on
/// which `.require_auth()` is called is considered an "admin auth call".
pub struct AdminNoGroupAuthCheck;

impl Check for AdminNoGroupAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut functions_with_admin_auth: Vec<(String, usize)> = Vec::new();

        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = AdminAuthScan::default();
            scan.visit_block(&method.block);
            if scan.has_admin_require_auth {
                let line = method.sig.fn_token.span().start().line;
                functions_with_admin_auth.push((fn_name, line));
            }
        }

        if functions_with_admin_auth.len() > 2 {
            // Report on the first function that starts the pattern.
            let (first_fn, first_line) = &functions_with_admin_auth[0];
            let all_fns: Vec<&str> = functions_with_admin_auth
                .iter()
                .map(|(n, _)| n.as_str())
                .collect();
            vec![Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: *first_line,
                function_name: first_fn.clone(),
                description: format!(
                    "{} functions ({}) each independently call `require_auth` on an admin/owner \
                     value. Extract a shared `assert_admin(env)` helper to avoid duplicated \
                     auth logic that must be kept in sync.",
                    functions_with_admin_auth.len(),
                    all_fns.join(", ")
                ),
            }]
        } else {
            vec![]
        }
    }
}

#[derive(Default)]
struct AdminAuthScan {
    has_admin_require_auth: bool,
}

impl<'ast> Visit<'ast> for AdminAuthScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "require_auth" || i.method == "require_auth_for_args" {
            // Check if the receiver references an admin/owner variable.
            let receiver_text = receiver_to_string(&i.receiver);
            if is_admin_name(&receiver_text) {
                self.has_admin_require_auth = true;
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn receiver_to_string(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        syn::Expr::MethodCall(m) => receiver_to_string(&m.receiver),
        syn::Expr::Reference(r) => receiver_to_string(&r.expr),
        _ => String::new(),
    }
}

fn is_admin_name(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("admin") || lower.contains("owner") || lower.contains("operator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_three_functions_with_admin_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn pause(env: Env) {
        let admin: Address = env.storage().instance().get(&"admin").unwrap();
        admin.require_auth();
    }
    pub fn unpause(env: Env) {
        let admin: Address = env.storage().instance().get(&"admin").unwrap();
        admin.require_auth();
    }
    pub fn set_fee(env: Env, fee: u32) {
        let admin: Address = env.storage().instance().get(&"admin").unwrap();
        admin.require_auth();
    }
}
"#,
        )?;
        let hits = AdminNoGroupAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_two_functions_with_admin_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn pause(env: Env) {
        let admin: Address = env.storage().instance().get(&"admin").unwrap();
        admin.require_auth();
    }
    pub fn unpause(env: Env) {
        let admin: Address = env.storage().instance().get(&"admin").unwrap();
        admin.require_auth();
    }
}
"#,
        )?;
        let hits = AdminNoGroupAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_no_admin_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, user: Address) {
        user.require_auth();
    }
    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();
    }
    pub fn transfer(env: Env, user: Address) {
        user.require_auth();
    }
}
"#,
        )?;
        let hits = AdminNoGroupAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

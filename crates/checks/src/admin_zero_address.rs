//! Detects `set_admin` / `transfer_ownership` functions that accept an `Address`
//! parameter but never validate it (no comparison, no `require_auth` on the new
//! address, no panic/assert on it).  Passing the all-zeros Stellar address
//! effectively renounces ownership with no recovery path.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, Visibility};

const CHECK_NAME: &str = "admin-zero-address";

/// Function names that set a new admin/owner from a parameter.
const ADMIN_SETTER_NAMES: &[&str] = &[
    "set_admin",
    "set_owner",
    "transfer_ownership",
    "update_admin",
    "change_admin",
    "change_owner",
    "set_manager",
];

pub struct AdminZeroAddressCheck;

impl Check for AdminZeroAddressCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            if !ADMIN_SETTER_NAMES.contains(&fn_name.as_str()) {
                continue;
            }

            // Collect Address-typed parameter names (heuristic: any param that
            // isn't `env` and whose type path ends in "Address").
            let addr_params: Vec<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    if let FnArg::Typed(pt) = arg {
                        let type_str = type_to_string(&pt.ty);
                        if type_str.ends_with("Address") {
                            if let Pat::Ident(pi) = &*pt.pat {
                                return Some(pi.ident.to_string());
                            }
                        }
                    }
                    None
                })
                .collect();

            if addr_params.is_empty() {
                continue;
            }

            // Check whether the body validates any of those params.
            let mut scan = ValidationScan::new(addr_params);
            scan.visit_block(&method.block);

            if !scan.validated {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "`{fn_name}` sets the admin/owner from a parameter without validating \
                         it. Passing the zero/default address permanently renounces ownership \
                         with no recovery path. Add a sentinel check or call \
                         `new_admin.require_auth()` before storing."
                    ),
                });
            }
        }
        out
    }
}

fn type_to_string(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(tp) => tp
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        syn::Type::Reference(r) => type_to_string(&r.elem),
        _ => String::new(),
    }
}

/// Looks for any validation of the address params:
/// - `param.require_auth()`
/// - a binary comparison involving the param (`==`, `!=`)
/// - `assert!` / `panic!` / `require!` containing the param name
/// - any `if` condition referencing the param
struct ValidationScan {
    params: Vec<String>,
    validated: bool,
}

impl ValidationScan {
    fn new(params: Vec<String>) -> Self {
        Self {
            params,
            validated: false,
        }
    }

    fn param_in_expr(&self, expr: &Expr) -> bool {
        let text = expr_to_string(expr);
        self.params.iter().any(|p| text.contains(p.as_str()))
    }
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::MethodCall(m) => {
            format!("{}.{}", expr_to_string(&m.receiver), m.method)
        }
        Expr::Binary(b) => {
            format!("{} {}", expr_to_string(&b.left), expr_to_string(&b.right))
        }
        Expr::Reference(r) => expr_to_string(&r.expr),
        _ => String::new(),
    }
}

impl<'ast> Visit<'ast> for ValidationScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // new_admin.require_auth()
        if (i.method == "require_auth" || i.method == "require_auth_for_args")
            && self.param_in_expr(&i.receiver)
        {
            self.validated = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        // any `if` whose condition references the param
        if self.param_in_expr(&i.cond) {
            self.validated = true;
        }
        visit::visit_expr_if(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast syn::ExprBinary) {
        // direct comparison: new_admin == zero_addr
        if self.param_in_expr(&i.left) || self.param_in_expr(&i.right) {
            self.validated = true;
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_macro(&mut self, i: &'ast syn::ExprMacro) {
        let mac_name = i
            .mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(mac_name.as_str(), "assert" | "panic" | "require") {
            let tokens = i.mac.tokens.to_string();
            if self.params.iter().any(|p| tokens.contains(p.as_str())) {
                self.validated = true;
            }
        }
        visit::visit_expr_macro(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_set_admin_without_validation() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&"admin", &new_admin);
    }
}
"#,
        )?;
        let hits = AdminZeroAddressCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_when_require_auth_on_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        new_admin.require_auth();
        env.storage().instance().set(&"admin", &new_admin);
    }
}
"#,
        )?;
        let hits = AdminZeroAddressCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_if_check_on_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        if new_admin == Address::default() { panic!("zero"); }
        env.storage().instance().set(&"admin", &new_admin);
    }
}
"#,
        )?;
        let hits = AdminZeroAddressCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_setter_fn() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&"admin").unwrap()
    }
}
"#,
        )?;
        let hits = AdminZeroAddressCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

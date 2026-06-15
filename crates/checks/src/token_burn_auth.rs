//! Detects token Client::burn called without require_auth on from address.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, PatType, Type};

const CHECK_NAME: &str = "token-burn-auth";

/// Flags .burn(from, amount) method calls inside #[contractimpl] functions where from is a function parameter
/// and no from.require_auth() or require_auth_for_args call precedes it in the same function body.
pub struct TokenBurnAuthCheck;

impl Check for TokenBurnAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scanner = AuthScanner::new(&method.sig.inputs);
            scanner.visit_block(&method.block);

            for burn_call in &scanner.burn_calls {
                if !scanner.has_auth_for(&burn_call.from_param) {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: burn_call.line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Method `{}` calls `burn({}, ...)` without prior `require_auth()` on the `from` address. \
                             This allows burning tokens from arbitrary addresses without authorization.",
                            fn_name, burn_call.from_param
                        ),
                    });
                }
            }
        }
        out
    }
}

#[derive(Clone)]
struct BurnCall {
    from_param: String,
    line: usize,
}

struct AuthScanner<'a> {
    inputs: &'a syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
    auth_calls: Vec<String>, // parameter names that have been authorized
    burn_calls: Vec<BurnCall>,
}

impl<'a> AuthScanner<'a> {
    fn new(inputs: &'a syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> Self {
        Self {
            inputs,
            auth_calls: Vec::new(),
            burn_calls: Vec::new(),
        }
    }

    fn has_auth_for(&self, param_name: &str) -> bool {
        self.auth_calls.contains(&param_name.to_string())
    }
}

impl<'a> Visit<'a> for AuthScanner<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        // Check for require_auth calls (from.require_auth() - no args, receiver is the address)
        if i.method == "require_auth" {
            if let Some(param_name) = extract_param_name(&i.receiver) {
                self.auth_calls.push(param_name);
            }
        }

        // Check for require_auth_for_args calls
        if i.method == "require_auth_for_args" {
            // This authorizes all arguments, so mark all Address parameters as authorized
            for arg in self.inputs {
                if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                    if is_address_type(ty) {
                        if let Some(param_name) = extract_param_name_from_pat(pat) {
                            self.auth_calls.push(param_name);
                        }
                    }
                }
            }
        }

        // Check for burn calls
        if i.method == "burn" && is_token_client_call(&i.receiver) {
            if let Some(from_arg) = i.args.first() {
                if let Some(param_name) = extract_param_name(from_arg) {
                    self.burn_calls.push(BurnCall {
                        from_param: param_name,
                        line: i.span().start().line,
                    });
                }
            }
        }

        visit::visit_expr_method_call(self, i);
    }
}

fn is_token_client_call(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "client" || is_token_client_call(&m.receiver),
        Expr::Field(_) => true,
        Expr::Path(_) => true,
        _ => false,
    }
}

fn extract_param_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(|ident| ident.to_string()),
        Expr::Reference(r) => extract_param_name(&r.expr),
        _ => None,
    }
}

fn extract_param_name_from_pat(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
        _ => None,
    }
}

fn is_address_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => {
            if let Some(ident) = tp.path.get_ident() {
                ident == "Address"
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(TokenBurnAuthCheck.run(&file, src))
    }

    #[test]
    fn flags_burn_without_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn burn_tokens(env: Env, token: Address, from: Address, amount: i128) {
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        // ❌ Burn without require_auth on from
        token_client.burn(&from, &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "burn_tokens");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_auth_before_burn() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn burn_tokens(env: Env, token: Address, from: Address, amount: i128) {
        // ✅ Auth first
        from.require_auth();
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.burn(&from, &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_with_require_auth_for_args() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn burn_tokens(env: Env, token: Address, from: Address, amount: i128) {
        // ✅ require_auth_for_args authorizes all Address params
        env.require_auth_for_args((token, from, amount));
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.burn(&from, &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}

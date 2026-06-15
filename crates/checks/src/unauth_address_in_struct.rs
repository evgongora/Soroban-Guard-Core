//! Address field in stored struct sourced from unauthenticated parameter.
//!
//! `storage().set(key, MyStruct { owner: addr, .. })` where `addr` comes from
//! a function parameter without a preceding `require_auth` on that address
//! allows an attacker to register arbitrary addresses as owners of stored records.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, ExprStruct, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "unauth-address-in-struct";

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn type_last_ident(ty: &Type) -> String {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        Type::Reference(r) => type_last_ident(&r.elem),
        _ => String::new(),
    }
}

/// Collect parameter names typed `Address`.
fn address_param_names(method: &syn::ImplItemFn) -> Vec<String> {
    let mut names = Vec::new();
    for arg in &method.sig.inputs {
        let FnArg::Typed(pt) = arg else { continue };
        let Pat::Ident(pi) = &*pt.pat else { continue };
        if type_last_ident(&pt.ty) == "Address" {
            names.push(pi.ident.to_string());
        }
    }
    names
}

fn expr_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        Expr::Reference(r) => expr_ident(&r.expr),
        _ => None,
    }
}

/// True if any field value in the struct literal is one of the address params.
fn struct_contains_address_param(es: &ExprStruct, addr_params: &[String]) -> bool {
    for field in &es.fields {
        if let Some(name) = expr_ident(&field.expr) {
            if addr_params.contains(&name) {
                return true;
            }
        }
    }
    false
}

fn value_arg_contains_struct_with_addr(arg: &Expr, addr_params: &[String]) -> bool {
    let inner = match arg {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    match inner {
        Expr::Struct(es) => struct_contains_address_param(es, addr_params),
        _ => false,
    }
}

#[derive(Default)]
struct AuthScan {
    has_require_auth: bool,
}

impl<'ast> Visit<'ast> for AuthScan {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if matches!(
            i.method.to_string().as_str(),
            "require_auth" | "require_auth_for_args"
        ) {
            self.has_require_auth = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct UnauthStructVisitor<'a> {
    fn_name: String,
    addr_params: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for UnauthStructVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set"
            && receiver_chain_contains_storage(&i.receiver)
            && i.args.len() >= 2
            && value_arg_contains_struct_with_addr(&i.args[1], &self.addr_params)
        {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` stores a struct containing an `Address` field \
                             sourced from a function parameter without calling \
                             `require_auth()` on that address. An attacker can register \
                             arbitrary addresses as owners of stored records. Call \
                             `require_auth()` on the address parameter before the write.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct UnauthAddressInStructCheck;

impl Check for UnauthAddressInStructCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let addr_params = address_param_names(method);
            if addr_params.is_empty() {
                continue;
            }
            // Check if any require_auth is present.
            let mut auth_scan = AuthScan::default();
            auth_scan.visit_block(&method.block);
            if auth_scan.has_require_auth {
                continue;
            }
            let mut v = UnauthStructVisitor {
                fn_name,
                addr_params,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_struct_with_unauthed_address() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
struct Record { owner: Address, amount: i128 }
#[contractimpl]
impl C {
    pub fn register(env: Env, owner: Address, amount: i128) {
        // BUG: owner not authenticated
        env.storage().persistent().set(
            &symbol_short!("rec"),
            &Record { owner, amount },
        );
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnauthAddressInStructCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].description.contains("require_auth"));
        Ok(())
    }

    #[test]
    fn no_finding_when_require_auth_present() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
struct Record { owner: Address, amount: i128 }
#[contractimpl]
impl C {
    pub fn register(env: Env, owner: Address, amount: i128) {
        owner.require_auth();
        env.storage().persistent().set(
            &symbol_short!("rec"),
            &Record { owner, amount },
        );
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnauthAddressInStructCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_when_no_address_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
struct Record { amount: i128 }
#[contractimpl]
impl C {
    pub fn register(env: Env, amount: i128) {
        env.storage().persistent().set(&symbol_short!("rec"), &Record { amount });
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnauthAddressInStructCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

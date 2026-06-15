//! Detects swap/trade/exchange functions that accept a slippage parameter without capping it.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use proc_macro2::TokenTree;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{BinOp, Expr, ExprBinary, ExprMacro, File, FnArg, Pat, Visibility};

const CHECK_NAME: &str = "uncapped-slippage";

const SWAP_FN_NAMES: &[&str] = &["swap", "trade", "exchange"];
const SLIPPAGE_PARAM_NAMES: &[&str] = &["slippage", "slippage_bps", "max_slippage"];

pub struct UncappedSlippageCheck;

impl Check for UncappedSlippageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            if !SWAP_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }
            // Find a slippage parameter
            let slippage_param = method.sig.inputs.iter().find_map(|arg| {
                if let FnArg::Typed(pt) = arg {
                    if let Pat::Ident(pi) = &*pt.pat {
                        let name = pi.ident.to_string();
                        if SLIPPAGE_PARAM_NAMES.contains(&name.as_str()) {
                            return Some(name);
                        }
                    }
                }
                None
            });
            let Some(param) = slippage_param else {
                continue;
            };

            // Check AST for a `<= …` guard on the slippage param
            let mut v = LeGuardVisitor {
                param: &param,
                found: false,
            };
            v.visit_block(&method.block);

            // Fallback: check source text for `param <=` (catches assert! and similar macros)
            if !v.found {
                let fn_start = method.sig.fn_token.span().start().line.saturating_sub(1);
                let fn_end = method.block.brace_token.span.close().start().line;
                let body_src: String = source
                    .lines()
                    .enumerate()
                    .filter(|(i, _)| *i >= fn_start && *i <= fn_end)
                    .map(|(_, l)| l)
                    .collect::<Vec<_>>()
                    .join("\n");
                let pattern = format!("{param} <=");
                let pattern2 = format!("{param}<=");
                if body_src.contains(&pattern) || body_src.contains(&pattern2) {
                    v.found = true;
                }
            }

            if !v.found {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: method.sig.fn_token.span().start().line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "`{fn_name}` accepts `{param}` but never asserts `{param} <= MAX`. \
                         A caller can pass 100% slippage, disabling price protection and \
                         enabling sandwich attacks."
                    ),
                });
            }
        }
        out
    }
}

struct LeGuardVisitor<'a> {
    param: &'a str,
    found: bool,
}

fn expr_is_ident(expr: &Expr, name: &str) -> bool {
    if let Expr::Path(p) = expr {
        p.path.is_ident(name)
    } else {
        false
    }
}

impl Visit<'_> for LeGuardVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        if matches!(i.op, BinOp::Le(_)) && expr_is_ident(&i.left, self.param) {
            self.found = true;
        }
        syn::visit::visit_expr_binary(self, i);
    }

    // Also detect `assert!(slippage <= MAX)` — the `<=` lives inside a macro token stream
    fn visit_expr_macro(&mut self, i: &ExprMacro) {
        if tokens_contain_le_guard(i.mac.tokens.clone(), self.param) {
            self.found = true;
        }
        syn::visit::visit_expr_macro(self, i);
    }
}

/// Returns true if the token stream contains `<param_name> <=` (as consecutive tokens).
fn tokens_contain_le_guard(tokens: proc_macro2::TokenStream, param: &str) -> bool {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    for window in tokens.windows(2) {
        if let (TokenTree::Ident(id), TokenTree::Punct(p)) = (&window[0], &window[1]) {
            if id == param && p.as_char() == '<' {
                return true; // `<=` is two puncts `<` then `=` in proc_macro2
            }
        }
    }
    // Also handle the case where `<=` is a single joint punct sequence
    for window in tokens.windows(3) {
        if let (TokenTree::Ident(id), TokenTree::Punct(p1), TokenTree::Punct(p2)) =
            (&window[0], &window[1], &window[2])
        {
            if id == param && p1.as_char() == '<' && p2.as_char() == '=' {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_swap_without_cap() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn swap(env: soroban_sdk::Env, amount: i128, slippage: u32) {
        let out = amount - (amount * slippage as i128 / 10000);
        env.storage().instance().set(&1u32, &out);
    }
}
"#,
        )?;
        let hits = UncappedSlippageCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_swap_with_cap() -> Result<(), syn::Error> {
        let src = r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn swap(env: soroban_sdk::Env, amount: i128, slippage: u32) {
        assert!(slippage <= 1000);
        let out = amount - (amount * slippage as i128 / 10000);
        env.storage().instance().set(&1u32, &out);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UncappedSlippageCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unrelated_fn_name() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: soroban_sdk::Env, amount: i128, slippage: u32) {
        let _ = (env, amount, slippage);
    }
}
"#,
        )?;
        let hits = UncappedSlippageCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

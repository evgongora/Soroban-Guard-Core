//! Detects error enum used with panic_with_error! missing #[contracterror] attribute.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{File, ItemEnum, Macro};

const CHECK_NAME: &str = "contracterror-attr";

/// Flags panic_with_error!(&env, MyError::Variant) calls where MyError lacks both #[contracterror] and #[repr(u32)].
pub struct ContracterrorAttrCheck;

impl Check for ContracterrorAttrCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut collector = ErrorCollector::default();
        collector.visit_file(file);

        let mut out = Vec::new();
        for usage in &collector.panic_with_error_usages {
            if let Some(enum_item) = collector.enums.get(&usage.enum_name) {
                if !has_contracterror_attr(enum_item) && !has_repr_u32_attr(enum_item) {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: usage.line,
                        function_name: usage.function_name.clone(),
                        description: format!(
                            "panic_with_error! uses enum `{}` which lacks both #[contracterror] and #[repr(u32)] attributes. \
                             Without these, the Soroban host cannot map the error to a structured error code.",
                            usage.enum_name
                        ),
                    });
                }
            }
        }
        out
    }
}

#[derive(Default)]
struct ErrorCollector {
    panic_with_error_usages: Vec<PanicWithErrorUsage>,
    enums: std::collections::HashMap<String, ItemEnum>,
}

#[derive(Clone)]
struct PanicWithErrorUsage {
    enum_name: String,
    line: usize,
    function_name: String,
}

impl Visit<'_> for ErrorCollector {
    fn visit_item_enum(&mut self, i: &ItemEnum) {
        self.enums.insert(i.ident.to_string(), i.clone());
        visit::visit_item_enum(self, i);
    }

    fn visit_macro(&mut self, i: &Macro) {
        if let Some(last_seg) = i.path.segments.last() {
            if last_seg.ident == "panic_with_error" {
                if let Some(enum_name) = extract_enum_name_from_panic_with_error(&i.tokens) {
                    self.panic_with_error_usages.push(PanicWithErrorUsage {
                        enum_name,
                        line: i.span().start().line,
                        function_name: String::new(),
                    });
                }
            }
        }
        visit::visit_macro(self, i);
    }

    fn visit_item_fn(&mut self, i: &syn::ItemFn) {
        let fn_name = i.sig.ident.to_string();
        for usage in &mut self.panic_with_error_usages {
            if usage.line >= i.span().start().line && usage.line <= i.span().end().line {
                usage.function_name = fn_name.clone();
            }
        }
        visit::visit_item_fn(self, i);
    }

    fn visit_impl_item_fn(&mut self, i: &syn::ImplItemFn) {
        let fn_name = i.sig.ident.to_string();
        for usage in &mut self.panic_with_error_usages {
            if usage.line >= i.span().start().line && usage.line <= i.span().end().line {
                usage.function_name = fn_name.clone();
            }
        }
        visit::visit_impl_item_fn(self, i);
    }
}

fn extract_enum_name_from_panic_with_error(tokens: &proc_macro2::TokenStream) -> Option<String> {
    let mut iter = tokens.clone().into_iter();
    // Skip past the first argument (up to and including the first comma)
    for token in iter.by_ref() {
        if let proc_macro2::TokenTree::Punct(p) = token {
            if p.as_char() == ',' {
                break;
            }
        }
    }

    // Now collect the enum path
    let mut path_parts = Vec::new();
    while let Some(token) = iter.next() {
        match token {
            proc_macro2::TokenTree::Ident(ident) => {
                path_parts.push(ident.to_string());
            }
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ':' => {
                // Skip ::
                let _ = iter.next(); // consume second :
            }
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' || p.as_char() == ')' => {
                break;
            }
            _ => {}
        }
    }

    if path_parts.len() >= 2 {
        Some(path_parts[path_parts.len() - 2].clone()) // Get the enum name (second to last)
    } else if path_parts.len() == 1 {
        Some(path_parts[0].clone())
    } else {
        None
    }
}

fn has_contracterror_attr(item_enum: &ItemEnum) -> bool {
    item_enum.attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "contracterror")
    })
}

fn has_repr_u32_attr(item_enum: &ItemEnum) -> bool {
    item_enum.attrs.iter().any(|attr| {
        if attr
            .path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "repr")
        {
            if let syn::Meta::List(meta_list) = &attr.meta {
                meta_list.tokens.to_string().contains("u32")
            } else {
                false
            }
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(ContracterrorAttrCheck.run(&file, src))
    }

    #[test]
    fn flags_missing_contracterror_attr() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, panic_with_error, Env};

#[contract]
pub struct Contract;

#[derive(Debug)]
pub enum MyError {
    InsufficientBalance,
}

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, amount: i128) {
        panic_with_error!(&env, MyError::InsufficientBalance);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_with_contracterror_attr() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, panic_with_error, contracterror, Env};

#[contract]
pub struct Contract;

#[contracterror]
#[derive(Debug)]
pub enum MyError {
    InsufficientBalance,
}

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, amount: i128) {
        panic_with_error!(&env, MyError::InsufficientBalance);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_with_repr_u32_attr() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, panic_with_error, Env};

#[contract]
pub struct Contract;

#[repr(u32)]
#[derive(Debug)]
pub enum MyError {
    InsufficientBalance,
}

#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, amount: i128) {
        panic_with_error!(&env, MyError::InsufficientBalance);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}

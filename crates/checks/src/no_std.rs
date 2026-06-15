//! Detects `std::` / `::std::` path usage in Soroban contracts.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{File, UseTree};

const CHECK_NAME: &str = "no-std-violation";

pub struct NoStdCheck;

impl Check for NoStdCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut v = StdVisitor { out: Vec::new() };
        v.visit_file(file);
        v.out
    }
}

struct StdVisitor {
    out: Vec<Finding>,
}

impl<'ast> Visit<'ast> for StdVisitor {
    fn visit_use_tree(&mut self, i: &'ast UseTree) {
        if let UseTree::Path(p) = i {
            if p.ident == "std" {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: p.ident.span().start().line,
                    function_name: String::new(),
                    description: "`use std::` detected. Soroban contracts must be compiled with \
                         `#![no_std]`; `std` paths are unavailable in WASM targets."
                        .to_string(),
                });
            }
        }
        visit::visit_use_tree(self, i);
    }

    fn visit_expr_path(&mut self, i: &'ast syn::ExprPath) {
        let segs = &i.path.segments;
        if segs.first().is_some_and(|s| s.ident == "std") && segs.len() > 1 {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: String::new(),
                description:
                    "`std::` path expression detected. Soroban contracts must be compiled \
                     with `#![no_std]`; `std` paths are unavailable in WASM targets."
                        .to_string(),
            });
        }
        visit::visit_expr_path(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_use_std() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use std::collections::HashMap;
pub struct C;
"#,
        )?;
        let hits = NoStdCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_std_path_expr() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub fn f() {
    let _m = std::collections::HashMap::<u32, u32>::new();
}
"#,
        )?;
        let hits = NoStdCheck.run(&file, "");
        assert!(!hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_no_std_contract() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn hello(_env: Env) {}
}
"#,
        )?;
        let hits = NoStdCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

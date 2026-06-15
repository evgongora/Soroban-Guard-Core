//! `Bytes` used instead of `BytesN<N>` for fixed-size cryptographic parameters.
//!
//! Parameters named `wasm_hash`, `public_key`, `signature`, `hash`, or `seed`
//! must be exactly N bytes. Using variable-length `Bytes` allows callers to
//! pass incorrectly-sized inputs that will panic or produce wrong results.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::{File, FnArg, Pat, Type};

const CHECK_NAME: &str = "bytes-not-bytesn";

const SENSITIVE_PARAM_NAMES: &[&str] = &[
    "wasm_hash",
    "public_key",
    "signature",
    "hash",
    "seed",
    "pubkey",
    "sig",
    "key_hash",
];

fn param_name_is_sensitive(name: &str) -> bool {
    let lower = name.to_lowercase();
    SENSITIVE_PARAM_NAMES
        .iter()
        .any(|s| lower == *s || lower.contains(s))
}

fn type_is_plain_bytes(ty: &Type) -> bool {
    match ty {
        Type::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                // `Bytes` with no angle-bracket args → plain variable-length Bytes
                return seg.ident == "Bytes" && matches!(seg.arguments, syn::PathArguments::None);
            }
            false
        }
        Type::Reference(r) => type_is_plain_bytes(&r.elem),
        _ => false,
    }
}

pub struct BytesNotBytesNCheck;

impl Check for BytesNotBytesNCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            for arg in &method.sig.inputs {
                let FnArg::Typed(pt) = arg else { continue };
                let Pat::Ident(pi) = &*pt.pat else { continue };
                let param_name = pi.ident.to_string();
                if !param_name_is_sensitive(&param_name) {
                    continue;
                }
                if type_is_plain_bytes(&pt.ty) {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: pi.ident.span().start().line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Parameter `{param_name}` in `{fn_name}` uses `Bytes` \
                             (variable-length) instead of `BytesN<N>` (fixed-length). \
                             Callers can pass incorrectly-sized inputs that will panic or \
                             produce wrong results at runtime. Use `BytesN<32>` for hashes \
                             or `BytesN<64>` for signatures."
                        ),
                    });
                }
            }
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
    fn flags_bytes_for_hash_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn verify(env: Env, hash: Bytes) -> bool { true }
}
"#;
        let file = parse_file(src)?;
        let hits = BytesNotBytesNCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("BytesN"));
        Ok(())
    }

    #[test]
    fn flags_bytes_for_signature_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn submit(env: Env, signature: Bytes) {}
}
"#;
        let file = parse_file(src)?;
        let hits = BytesNotBytesNCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_for_bytesn_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, BytesN, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn verify(env: Env, hash: BytesN<32>) -> bool { true }
}
"#;
        let file = parse_file(src)?;
        let hits = BytesNotBytesNCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_for_non_sensitive_bytes_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, data: Bytes) {}
}
"#;
        let file = parse_file(src)?;
        let hits = BytesNotBytesNCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}

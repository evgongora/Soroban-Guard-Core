#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Bytes, Env};

#[contract]
pub struct BytesOversizedVulnerable;

const KEY: soroban_sdk::Symbol = symbol_short!("blob");

#[contractimpl]
impl BytesOversizedVulnerable {
    /// BUG: `data` is user-controlled and its length is never checked.
    /// A caller can pass a slice that exceeds the ledger entry size limit,
    /// causing the storage write to fail or corrupt slot layouts.
    pub fn store(env: Env, data: &[u8]) {
        // No length validation — user controls how large `data` is.
        let b = Bytes::from_slice(&env, data); // ❌ oversized input not rejected
        env.storage().persistent().set(&KEY, &b);
    }
}

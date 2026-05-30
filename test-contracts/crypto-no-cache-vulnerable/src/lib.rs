#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct CryptoNoCacheVulnerable;

#[contractimpl]
impl CryptoNoCacheVulnerable {
    pub fn verify(env: Env, data: Bytes) -> bool {
        // ❌ env.crypto() called 3 times — should be cached
        let h1 = env.crypto().sha256(&data);
        let h2 = env.crypto().sha256(&data);
        let h3 = env.crypto().keccak256(&data);
        h1 == h2 && h3.len() > 0
    }
}

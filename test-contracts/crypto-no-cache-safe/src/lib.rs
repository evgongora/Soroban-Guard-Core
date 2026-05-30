#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct CryptoNoCacheSafe;

#[contractimpl]
impl CryptoNoCacheSafe {
    pub fn verify(env: Env, data: Bytes) -> bool {
        // ✅ env.crypto() cached in a local variable
        let crypto = env.crypto();
        let h1 = crypto.sha256(&data);
        let h2 = crypto.sha256(&data);
        let h3 = crypto.keccak256(&data);
        h1 == h2 && h3.len() > 0
    }
}

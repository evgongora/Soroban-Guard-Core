#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct Sha256EmptyVulnerable;

#[contractimpl]
impl Sha256EmptyVulnerable {
    pub fn commit(env: Env) {
        let _hash = env.crypto().sha256(&Bytes::new(&env));
    }
}

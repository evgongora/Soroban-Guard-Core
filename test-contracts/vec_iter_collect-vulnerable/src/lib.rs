#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct VecIterCollectVulnerable;

#[contractimpl]
impl VecIterCollectVulnerable {
    pub fn copy_vec(env: Env, v: Vec<u32>) -> Vec<u32> {
        // ❌ Vulnerable: unnecessary iter().collect() doubles memory
        v.iter().collect::<Vec<_>>()
    }
}

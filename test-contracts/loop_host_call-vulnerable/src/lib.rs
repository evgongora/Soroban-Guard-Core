#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct LoopHostCallVulnerable;

#[contractimpl]
impl LoopHostCallVulnerable {
    pub fn store_values(env: Env, n: u32) {
        // ❌ Vulnerable: storage I/O on every iteration exhausts budget
        for i in 0..n {
            env.storage().instance().set(&i, &(i * 2));
        }
    }

    pub fn read_values(env: Env, keys: Vec<u32>) {
        // ❌ Vulnerable: storage reads in loop
        for key in keys {
            let _val = env.storage().instance().get(&key);
        }
    }
}

#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct LoopHostCallSafe;

#[contractimpl]
impl LoopHostCallSafe {
    pub fn store_values_safe(env: Env, n: u32) {
        // ✅ Safe: build data in memory, then store once
        let mut data: Vec<(u32, u32)> = Vec::new(&env);
        for i in 0..n {
            data.push_back((i, i * 2));
        }
        env.storage().instance().set(&0u32, &data);
    }

    pub fn process_values(env: Env, values: Vec<u32>) {
        // ✅ Safe: process in memory without storage I/O in loop
        for val in values {
            let _result = val * 2;
            // process result
        }
    }
}

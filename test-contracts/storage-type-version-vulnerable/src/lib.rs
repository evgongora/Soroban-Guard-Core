#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    pub fn store_as_u32(env: Env) {
        // ❌ Storing as u32
        env.storage()
            .instance()
            .set(&symbol_short!("value"), &42u32);
    }

    pub fn retrieve_as_u64(env: Env) -> u64 {
        // ❌ Retrieving as u64 - type mismatch!
        env.storage()
            .instance()
            .get::<_, u64>(&symbol_short!("value"))
            .unwrap_or(0)
    }
}

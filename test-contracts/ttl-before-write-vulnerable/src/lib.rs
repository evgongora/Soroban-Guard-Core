#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    pub fn extend_only(env: Env) {
        // ❌ Extending TTL without writing first - no-op
        env.storage()
            .instance()
            .extend_ttl(&symbol_short!("key"), 100, 200);
    }

    pub fn wrong_order(env: Env, val: u32) {
        // ❌ Extending TTL before writing
        env.storage()
            .instance()
            .extend_ttl(&symbol_short!("data"), 100, 200);
        env.storage()
            .instance()
            .set(&symbol_short!("data"), &val);
    }
}

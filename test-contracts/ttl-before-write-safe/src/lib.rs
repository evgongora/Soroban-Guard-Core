#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct SafeContract;

#[contractimpl]
impl SafeContract {
    pub fn write_and_extend(env: Env, val: u32) {
        // ✅ Writing first, then extending TTL
        env.storage()
            .instance()
            .set(&symbol_short!("key"), &val);
        env.storage()
            .instance()
            .extend_ttl(&symbol_short!("key"), 100, 200);
    }

    pub fn correct_order(env: Env, val: u32) {
        // ✅ Set before extend_ttl
        env.storage()
            .instance()
            .set(&symbol_short!("data"), &val);
        env.storage()
            .instance()
            .extend_ttl(&symbol_short!("data"), 100, 200);
    }
}

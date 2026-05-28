#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    pub fn update_state(env: Env, value: u32) {
        // ❌ Writing to instance storage without checking init status
        env.storage()
            .instance()
            .set(&symbol_short!("state"), &value);
    }

    pub fn modify_counter(env: Env) {
        // ❌ No has() guard before set
        env.storage()
            .instance()
            .set(&symbol_short!("counter"), &42u32);
    }
}

#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    pub fn update_balance(env: Env, amount: u32) {
        // ❌ Overwriting persistent storage without reading existing value
        env.storage()
            .persistent()
            .set(&symbol_short!("balance"), &amount);
    }

    pub fn store_data(env: Env, data: u64) {
        // ❌ No get/has check before set
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "data"), &data);
    }
}

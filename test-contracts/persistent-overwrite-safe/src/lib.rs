#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct SafeContract;

#[contractimpl]
impl SafeContract {
    pub fn update_balance(env: Env, amount: u32) {
        // ✅ Reading existing value before updating
        let _old = env
            .storage()
            .persistent()
            .get::<_, u32>(&symbol_short!("balance"));
        env.storage()
            .persistent()
            .set(&symbol_short!("balance"), &amount);
    }

    pub fn store_data(env: Env, data: u64) {
        // ✅ Checking if key exists before setting
        if env
            .storage()
            .persistent()
            .has(&Symbol::new(&env, "data"))
        {
            env.storage()
                .persistent()
                .set(&Symbol::new(&env, "data"), &data);
        }
    }
}

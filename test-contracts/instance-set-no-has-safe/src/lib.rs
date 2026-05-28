#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct SafeContract;

#[contractimpl]
impl SafeContract {
    pub fn initialize(env: Env, value: u32) {
        // ✅ Initializer function (skipped by check)
        env.storage()
            .instance()
            .set(&symbol_short!("state"), &value);
    }

    pub fn update_state(env: Env, value: u32) {
        // ✅ Checking init status before updating
        if env.storage().instance().has(&symbol_short!("state")) {
            env.storage()
                .instance()
                .set(&symbol_short!("state"), &value);
        }
    }

    pub fn modify_counter(env: Env) {
        // ✅ Guarded with has()
        if env.storage().instance().has(&symbol_short!("counter")) {
            env.storage()
                .instance()
                .set(&symbol_short!("counter"), &42u32);
        }
    }
}

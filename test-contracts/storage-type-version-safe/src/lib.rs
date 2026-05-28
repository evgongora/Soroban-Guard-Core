#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct SafeContract;

#[contractimpl]
impl SafeContract {
    pub fn store_as_u32(env: Env) {
        // ✅ Storing as u32
        env.storage()
            .instance()
            .set(&symbol_short!("value"), &42u32);
    }

    pub fn retrieve_as_u32(env: Env) -> u32 {
        // ✅ Retrieving as u32 - consistent type
        env.storage()
            .instance()
            .get::<_, u32>(&symbol_short!("value"))
            .unwrap_or(0)
    }
}

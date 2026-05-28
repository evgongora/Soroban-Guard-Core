#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct RuntimeSymbolSafe;

/// Safe: compile-time constant — validated at compile time, zero runtime cost.
const KEY: Symbol = symbol_short!("counter");

#[contractimpl]
impl RuntimeSymbolSafe {
    pub fn get_key(_env: Env) -> Symbol {
        KEY
    }

    pub fn increment(env: Env) {
        let n: u32 = env.storage().instance().get(&KEY).unwrap_or(0);
        env.storage().instance().set(&KEY, &(n + 1));
    }
}

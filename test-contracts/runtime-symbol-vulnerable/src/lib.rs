#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct RuntimeSymbolVulnerable;

const KEY: Symbol = symbol_short!("count");

#[contractimpl]
impl RuntimeSymbolVulnerable {
    /// BUG: Symbol::from_str defers validation to runtime.
    /// A misspelled name is only caught when the contract executes on-chain.
    pub fn get_key(env: Env) -> Symbol {
        Symbol::from_str(&env, "counter")
    }

    pub fn increment(env: Env) {
        let n: u32 = env.storage().instance().get(&KEY).unwrap_or(0);
        env.storage().instance().set(&KEY, &(n + 1));
    }
}

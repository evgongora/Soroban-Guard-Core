#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct I128ToU64Safe;

const KEY: soroban_sdk::Symbol = symbol_short!("balance");

#[contractimpl]
impl I128ToU64Safe {
    /// Safe: uses try_from to detect overflow/negative values before converting.
    pub fn deposit(env: Env, amount: i128) {
        let stored = u64::try_from(amount).expect("amount out of u64 range");
        env.storage().instance().set(&KEY, &stored);
    }

    pub fn get_balance(env: Env) -> u64 {
        env.storage().instance().get(&KEY).unwrap_or(0u64)
    }
}

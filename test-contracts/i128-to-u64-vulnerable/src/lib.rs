#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct I128ToU64Vulnerable;

const KEY: soroban_sdk::Symbol = symbol_short!("balance");

#[contractimpl]
impl I128ToU64Vulnerable {
    /// BUG: `amount as u64` silently truncates if amount > u64::MAX or is negative.
    /// Token amounts in Soroban are i128; casting without a range check can wrap
    /// to an unexpected value.
    pub fn deposit(env: Env, amount: i128) {
        let stored: u64 = amount as u64; // ❌ silent truncation
        env.storage().instance().set(&KEY, &stored);
    }

    pub fn get_balance(env: Env) -> u64 {
        env.storage().instance().get(&KEY).unwrap_or(0u64)
    }
}

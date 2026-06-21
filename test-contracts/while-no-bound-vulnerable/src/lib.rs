#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

const COUNT: Symbol = symbol_short!("COUNT");

#[contract]
pub struct WhileNoBoundVulnerable;

#[contractimpl]
impl WhileNoBoundVulnerable {
    pub fn drain(env: Env) {
        while env.storage().instance().get::<_, i128>(&COUNT).unwrap() > 0 {
            let current = env.storage().instance().get::<_, i128>(&COUNT).unwrap();
            env.storage().instance().set(&COUNT, &(current - 1));
        }
    }
}

#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

const COUNT: Symbol = symbol_short!("COUNT");
const MAX: u32 = 100;

#[contract]
pub struct WhileNoBoundSafe;

#[contractimpl]
impl WhileNoBoundSafe {
    pub fn drain(env: Env) {
        let mut i = 0;
        while env.storage().instance().get::<_, i128>(&COUNT).unwrap() > 0 {
            let current = env.storage().instance().get::<_, i128>(&COUNT).unwrap();
            env.storage().instance().set(&COUNT, &(current - 1));
            i += 1;
            if i >= MAX {
                break;
            }
        }
    }
}

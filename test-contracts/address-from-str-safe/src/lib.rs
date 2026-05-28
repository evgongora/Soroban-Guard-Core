#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AddressFromStrSafe;

const KEY: soroban_sdk::Symbol = symbol_short!("owner");

#[contractimpl]
impl AddressFromStrSafe {
    /// Safe: accepts a typed Address parameter — the SDK validates it before
    /// the function is called, so no runtime panic is possible.
    pub fn set_owner(env: Env, owner: Address) {
        env.storage().instance().set(&KEY, &owner);
    }

    pub fn get_owner(env: Env) -> Address {
        env.storage().instance().get(&KEY).unwrap()
    }
}

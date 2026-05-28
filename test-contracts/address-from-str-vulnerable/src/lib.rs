#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, String};

#[contract]
pub struct AddressFromStrVulnerable;

const KEY: soroban_sdk::Symbol = symbol_short!("owner");

#[contractimpl]
impl AddressFromStrVulnerable {
    /// BUG: Address::from_str panics on invalid input.
    /// Any caller can trigger a contract panic by passing a malformed address string,
    /// causing a denial of service.
    pub fn set_owner(env: Env, raw_addr: String) {
        let owner = Address::from_str(&env, &raw_addr); // ❌ panics on invalid input
        env.storage().instance().set(&KEY, &owner);
    }
}

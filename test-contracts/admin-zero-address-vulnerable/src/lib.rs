#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AdminZeroAddressVulnerable;

#[contractimpl]
impl AdminZeroAddressVulnerable {
    /// ❌ Accepts any address as the new admin without validation.
    /// Passing the zero/default address permanently renounces ownership.
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .instance()
            .set(&symbol_short!("admin"), &new_admin);
    }
}

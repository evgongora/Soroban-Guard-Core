#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AdminZeroAddressSafe;

#[contractimpl]
impl AdminZeroAddressSafe {
    /// ✅ Requires the new admin to authenticate, proving they control the key.
    /// This prevents accidentally setting the admin to an uncontrolled address.
    pub fn set_admin(env: Env, new_admin: Address) {
        new_admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("admin"), &new_admin);
    }
}

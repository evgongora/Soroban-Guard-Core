#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AdminNoGroupAuthVulnerable;

#[contractimpl]
impl AdminNoGroupAuthVulnerable {
    /// ❌ Each admin function independently reads the admin key and calls
    /// require_auth. If the auth logic ever changes it must be updated in
    /// every function — a maintenance hazard.
    pub fn pause(env: Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("paused"), &true);
    }

    pub fn unpause(env: Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("paused"), &false);
    }

    pub fn set_fee(env: Env, fee: u32) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("fee"), &fee);
    }
}

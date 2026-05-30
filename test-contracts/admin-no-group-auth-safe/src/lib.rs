#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct AdminNoGroupAuthSafe;

fn assert_admin(env: &Env) {
    let admin: Address = env
        .storage()
        .instance()
        .get(&symbol_short!("admin"))
        .unwrap();
    admin.require_auth();
}

#[contractimpl]
impl AdminNoGroupAuthSafe {
    /// ✅ All admin functions delegate to a single shared helper.
    /// Auth logic only needs to be updated in one place.
    pub fn pause(env: Env) {
        assert_admin(&env);
        env.storage()
            .instance()
            .set(&symbol_short!("paused"), &true);
    }

    pub fn unpause(env: Env) {
        assert_admin(&env);
        env.storage()
            .instance()
            .set(&symbol_short!("paused"), &false);
    }

    pub fn set_fee(env: Env, fee: u32) {
        assert_admin(&env);
        env.storage()
            .instance()
            .set(&symbol_short!("fee"), &fee);
    }
}

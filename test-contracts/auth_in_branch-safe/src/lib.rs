#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AuthInBranchSafe;

#[contractimpl]
impl AuthInBranchSafe {
    /// ✅ Auth in all branches — passes `auth-in-branch`.
    pub fn conditional_transfer(env: Env, user: Address, is_admin: bool, amount: i128) {
        if is_admin {
            user.require_auth();
        } else {
            user.require_auth();
        }
        let _ = (env, amount);
    }
}

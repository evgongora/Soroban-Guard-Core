#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AuthInBranchVulnerable;

#[contractimpl]
impl AuthInBranchVulnerable {
    /// ❌ Auth only in if branch, not in else — should trigger `auth-in-branch` (High).
    pub fn conditional_transfer(env: Env, user: Address, is_admin: bool, amount: i128) {
        if is_admin {
            user.require_auth();
        } else {
            let _ = (env, amount);
        }
    }
}

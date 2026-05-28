#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct AuthUntrustedStorageSafe;

#[contractimpl]
impl AuthUntrustedStorageSafe {
    /// ✅ Requires auth on parameter, not storage value — passes `auth-untrusted-storage`.
    pub fn protected_fn(env: Env, admin: Address) {
        admin.require_auth();
        let _ = env;
    }
}

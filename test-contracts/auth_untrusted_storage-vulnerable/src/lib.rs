#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct AuthUntrustedStorageVulnerable;

#[contractimpl]
impl AuthUntrustedStorageVulnerable {
    /// ❌ Requires auth on admin read from storage — should trigger `auth-untrusted-storage` (High).
    pub fn protected_fn(env: Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "admin"))
            .unwrap();
        admin.require_auth();
    }
}

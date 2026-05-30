#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SigVerifyInvertedVulnerable;

#[contractimpl]
impl SigVerifyInvertedVulnerable {
    // ❌ Inverted: allows access when signature is INVALID
    pub fn auth(env: Env) {
        if !env.crypto().ed25519_verify(&env, &(), &()) {
            return;
        }
    }

    // ❌ Equivalent: == false also inverts the check
    pub fn auth2(env: Env) {
        if env.crypto().ed25519_verify(&env, &(), &()) == false {
            return;
        }
    }
}

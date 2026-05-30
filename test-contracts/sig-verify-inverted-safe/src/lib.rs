#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SigVerifyInvertedSafe;

#[contractimpl]
impl SigVerifyInvertedSafe {
    // ✅ Correct: allows access only when signature is VALID
    pub fn auth(env: Env) {
        if env.crypto().ed25519_verify(&env, &(), &()) {
            return;
        }
    }
}

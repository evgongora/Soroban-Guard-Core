#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct TimestampAsNonceVulnerable;

#[contractimpl]
impl TimestampAsNonceVulnerable {
    /// ❌ Ledger timestamp used as a unique nonce / storage key — every
    /// transaction in the same ledger gets the same value, enabling replay.
    pub fn record(env: Env) {
        let nonce = env.ledger().timestamp();
        env.storage().persistent().set(&nonce, &true);
    }
}

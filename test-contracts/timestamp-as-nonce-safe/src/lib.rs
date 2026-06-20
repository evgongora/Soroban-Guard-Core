#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

const COUNTER: Symbol = symbol_short!("CNT");

#[contract]
pub struct TimestampAsNonceSafe;

#[contractimpl]
impl TimestampAsNonceSafe {
    /// Nonce derived from a monotonically incrementing storage counter —
    /// unique per call, unlike the ledger close time.
    pub fn record(env: Env) {
        let counter: u64 = env.storage().instance().get(&COUNTER).unwrap_or(0);
        let nonce = counter + 1;
        env.storage().persistent().set(&nonce, &true);
        env.storage().instance().set(&COUNTER, &nonce);
    }
}

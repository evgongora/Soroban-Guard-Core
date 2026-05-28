#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Bytes, Env};

#[contract]
pub struct BytesOversizedSafe;

const KEY: soroban_sdk::Symbol = symbol_short!("blob");
const MAX_LEN: u32 = 128;

#[contractimpl]
impl BytesOversizedSafe {
    /// Safe: length is validated before constructing the Bytes value.
    pub fn store(env: Env, data: Bytes) {
        assert!(data.len() <= MAX_LEN, "data exceeds maximum allowed size");
        env.storage().persistent().set(&KEY, &data);
    }
}

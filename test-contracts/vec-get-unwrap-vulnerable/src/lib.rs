#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct VecGetUnwrapVulnerable;

#[contractimpl]
impl VecGetUnwrapVulnerable {
    /// BUG: no bounds check before `.unwrap()` — panics if `idx >= v.len()`.
    pub fn get_item(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        v.get(idx).unwrap()
    }

    /// BUG: same issue with `.expect(...)`.
    pub fn get_item_expect(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        v.get(idx).expect("index out of bounds")
    }
}

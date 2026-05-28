#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct VecGetUnwrapSafe;

#[contractimpl]
impl VecGetUnwrapSafe {
    /// ✅ Uses `if let` — no panic on out-of-bounds.
    pub fn get_item(_env: Env, v: Vec<u32>, idx: u32) -> u32 {
        if let Some(val) = v.get(idx) {
            val
        } else {
            0
        }
    }

    /// ✅ Uses `unwrap_or` — safe fallback.
    pub fn get_item_or_default(_env: Env, v: Vec<u32>, idx: u32) -> u32 {
        v.get(idx).unwrap_or(0)
    }
}

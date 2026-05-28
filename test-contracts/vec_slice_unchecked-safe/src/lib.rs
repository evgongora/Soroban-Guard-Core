#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct VecSliceUncheckedSafe;

#[contractimpl]
impl VecSliceUncheckedSafe {
    pub fn slice_safe(env: Env, v: Vec<u32>, start: u32, end: u32) -> Vec<u32> {
        // ✅ Safe: bounds checking before slice
        let len = v.len();
        if start > end || end > len {
            return Vec::new(&env);
        }
        v.slice(start, end)
    }
}

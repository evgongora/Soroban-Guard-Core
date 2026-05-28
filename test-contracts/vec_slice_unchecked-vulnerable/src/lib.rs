#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct VecSliceUncheckedVulnerable;

#[contractimpl]
impl VecSliceUncheckedVulnerable {
    pub fn slice_unchecked(env: Env, v: Vec<u32>, start: u32, end: u32) -> Vec<u32> {
        // ❌ Vulnerable: no bounds checking on user-provided start/end
        v.slice(start, end)
    }
}

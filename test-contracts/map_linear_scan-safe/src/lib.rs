#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Map};

#[contract]
pub struct MapLinearScanSafe;

#[contractimpl]
impl MapLinearScanSafe {
    pub fn get_value(env: Env, m: Map<u32, u32>, key: u32) -> Option<u32> {
        // ✅ Safe: O(1) direct lookup
        m.get(key)
    }

    pub fn iterate_all_keys(env: Env, m: Map<u32, u32>) {
        // ✅ Safe: just iterating keys without nested get
        for key in m.keys() {
            // process key
        }
    }
}

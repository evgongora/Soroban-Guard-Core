#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Map};

#[contract]
pub struct MapLinearScanVulnerable;

#[contractimpl]
impl MapLinearScanVulnerable {
    pub fn find_value(env: Env, m: Map<u32, u32>, target: u32) -> Option<u32> {
        // ❌ Vulnerable: O(n) linear scan instead of O(1) direct lookup
        for key in m.keys() {
            if let Some(val) = m.get(key) {
                if val == target {
                    return Some(val);
                }
            }
        }
        None
    }
}

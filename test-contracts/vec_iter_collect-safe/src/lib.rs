#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct VecIterCollectSafe;

#[contractimpl]
impl VecIterCollectSafe {
    pub fn use_vec_directly(env: Env, v: Vec<u32>) -> Vec<u32> {
        // ✅ Safe: use the original Vec directly
        v
    }

    pub fn iterate_without_collect(env: Env, v: Vec<u32>) {
        // ✅ Safe: iterate without collecting
        for item in v.iter() {
            // process item
        }
    }
}

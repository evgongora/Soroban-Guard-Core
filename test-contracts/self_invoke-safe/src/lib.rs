#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SelfInvokeSafe;

#[contractimpl]
impl SelfInvokeSafe {
    /// ✅ Calls internal function directly instead of via invoke_contract.
    pub fn process(env: Env, x: i32) -> i32 {
        Self::internal_process(env, x)
    }

    pub fn internal_process(_env: Env, x: i32) -> i32 {
        x * 2
    }
}

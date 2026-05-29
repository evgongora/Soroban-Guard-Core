#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct SelfInvokeVulnerable;

#[contractimpl]
impl SelfInvokeVulnerable {
    /// ❌ Calls itself inefficiently via invoke_contract instead of directly.
    pub fn process(env: Env, x: i32) -> i32 {
        let result = env.invoke_contract::<i32>(
            &env.current_contract_address(),
            &Symbol::new(&env, "internal_process"),
            &x,
        );
        result
    }

    pub fn internal_process(env: Env, x: i32) -> i32 {
        x * 2
    }
}

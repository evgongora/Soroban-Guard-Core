#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Bytes, Env};

#[contract]
pub struct DeployNoEventSafe;

#[contractimpl]
impl DeployNoEventSafe {
    /// ✅ Emits an event after deploying a sub-contract so indexers can track it.
    pub fn deploy_sub(env: Env, wasm_hash: Bytes) {
        let addr = env.deployer().deploy(wasm_hash, ());
        env.storage().persistent().set(&"sub_contract", &addr);
        env.events().publish((symbol_short!("deployed"),), addr);
    }
}

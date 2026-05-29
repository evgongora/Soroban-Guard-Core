#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct DeployNoEventVulnerable;

#[contractimpl]
impl DeployNoEventVulnerable {
    /// ❌ Deploys a sub-contract without emitting an event — invisible to indexers.
    pub fn deploy_sub(env: Env, wasm_hash: Bytes) {
        let addr = env.deployer().deploy(wasm_hash, ());
        env.storage().persistent().set(&"sub_contract", &addr);
    }
}

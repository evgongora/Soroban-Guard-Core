#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct UpgradeNoEventVulnerable;

#[contractimpl]
impl UpgradeNoEventVulnerable {
    /// ❌ Upgrades WASM without emitting an event — undetectable upgrade vulnerability.
    pub fn upgrade(env: Env, new_wasm: Bytes) {
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}

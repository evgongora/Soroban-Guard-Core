#![no_std]
use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct UpgradeNoSchemaVersionVulnerable;

#[contractimpl]
impl UpgradeNoSchemaVersionVulnerable {
    /// Upgrades WASM with no schema/version key written anywhere — new code
    /// cannot detect it is reading data serialized by an older layout.
    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
    }
}

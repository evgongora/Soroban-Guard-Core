#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, BytesN, Env};

#[contract]
pub struct UpgradeNoSchemaVersionSafe;

const SCHEMA_VERSION: soroban_sdk::Symbol = symbol_short!("ver");

#[contractimpl]
impl UpgradeNoSchemaVersionSafe {
    pub fn init(env: Env) {
        env.storage().instance().set(&SCHEMA_VERSION, &1u32);
    }

    /// Upgrades WASM and bumps the schema version key so new code can detect
    /// the layout it is reading.
    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
        env.storage().instance().set(&SCHEMA_VERSION, &2u32);
    }
}

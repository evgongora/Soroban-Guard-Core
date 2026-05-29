#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Bytes, Env};

#[contract]
pub struct UpgradeNoEventSafe;

#[contractimpl]
impl UpgradeNoEventSafe {
    /// ✅ Emits an event after upgrading WASM so the critical operation is auditable.
    pub fn upgrade(env: Env, new_wasm: Bytes) {
        env.deployer().update_current_contract_wasm(new_wasm.clone());
        env.events().publish((symbol_short!("upgraded"),), new_wasm);
    }
}

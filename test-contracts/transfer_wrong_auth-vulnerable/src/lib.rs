#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TransferWrongAuthVulnerable;

#[contractimpl]
impl TransferWrongAuthVulnerable {
    /// ❌ Requires auth on `to` instead of `from` — should trigger `transfer-wrong-auth` (High).
    pub fn transfer(_env: Env, _from: Address, to: Address, _amount: i128) {
        to.require_auth();
    }
}

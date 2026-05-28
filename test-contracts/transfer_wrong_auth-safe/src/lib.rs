#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct TransferWrongAuthSafe;

#[contractimpl]
impl TransferWrongAuthSafe {
    /// ✅ Requires auth on `from` — passes `transfer-wrong-auth`.
    pub fn transfer(_env: Env, from: Address, _to: Address, _amount: i128) {
        from.require_auth();
    }
}

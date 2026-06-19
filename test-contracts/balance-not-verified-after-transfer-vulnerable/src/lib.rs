#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct BalanceNotVerifiedAfterTransferVulnerable;

#[contractimpl]
impl BalanceNotVerifiedAfterTransferVulnerable {
    /// Calls token::Client::transfer but does not verify the balance after the transfer.
    /// If the transfer fails or behaves unexpectedly, the contract proceeds without
    /// verification, causing potential accounting errors -- should trigger the check.
    pub fn pay(env: Env, token_addr: Address, from: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&from, &to, &amount);
        // No balance verification after transfer
    }
}

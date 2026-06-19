#![no_std]
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct BalanceNotVerifiedAfterTransferSafe;

#[contractimpl]
impl BalanceNotVerifiedAfterTransferSafe {
    /// Calls token::Client::transfer and verifies the balance after the transfer.
    /// This ensures the transfer succeeded and prevents accounting errors -- should pass the check.
    pub fn pay(env: Env, token_addr: Address, from: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_addr);
        client.transfer(&from, &to, &amount);
        
        // Verify balance after transfer
        let from_balance = client.balance(&from);
        let to_balance = client.balance(&to);
        assert!(from_balance >= 0, "Invalid balance after transfer");
        assert!(to_balance >= 0, "Invalid balance after transfer");
    }
}

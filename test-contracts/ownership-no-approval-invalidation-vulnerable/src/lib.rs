#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct OwnershipNoApprovalInvalidationVulnerable;

#[contractimpl]
impl OwnershipNoApprovalInvalidationVulnerable {
    /// ❌ Transfers ownership but leaves existing allowances/approvals intact.
    /// Permissions granted by the old owner remain valid after the transfer.
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &new_owner);
        // ❌ missing: clear allowances / approvals
    }
}

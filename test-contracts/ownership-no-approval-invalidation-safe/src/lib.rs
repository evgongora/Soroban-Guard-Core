#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct OwnershipNoApprovalInvalidationSafe;

#[contractimpl]
impl OwnershipNoApprovalInvalidationSafe {
    /// ✅ Transfers ownership and clears existing allowances so that permissions
    /// granted by the old owner cannot be exploited after the transfer.
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &new_owner);
        // ✅ invalidate all existing approvals
        env.storage()
            .instance()
            .remove(&symbol_short!("allowance"));
    }
}

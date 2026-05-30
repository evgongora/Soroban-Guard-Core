#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct OwnershipPendingNotClearedSafe;

#[contractimpl]
impl OwnershipPendingNotClearedSafe {
    /// Initiates a two-step ownership transfer by storing the candidate.
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        let owner: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("owner"))
            .unwrap();
        owner.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("pending"), &new_owner);
    }

    /// ✅ Writes the new owner AND removes the pending key atomically.
    /// The pending authorization cannot be replayed.
    pub fn accept_ownership(env: Env) {
        let new_owner: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("pending"))
            .unwrap();
        new_owner.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("owner"), &new_owner);
        env.storage()
            .instance()
            .remove(&symbol_short!("pending"));
    }
}

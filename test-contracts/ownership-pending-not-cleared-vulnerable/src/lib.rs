#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct OwnershipPendingNotClearedVulnerable;

#[contractimpl]
impl OwnershipPendingNotClearedVulnerable {
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

    /// ❌ Writes the new owner but never removes the pending key.
    /// The same pending authorization can be replayed to transfer ownership again.
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
        // ❌ missing: env.storage().instance().remove(&symbol_short!("pending"));
    }
}

#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct TierKeyCollisionVulnerable;

#[contractimpl]
impl TierKeyCollisionVulnerable {
    /// Stores a session token in temporary storage.
    pub fn create_session(env: Env, value: u32) {
        // ❌ "session" key written to temporary storage
        env.storage().temporary().set("session", &value);
    }

    /// Tries to read the session from persistent storage — always returns stale/empty.
    pub fn get_session(env: Env) -> u32 {
        // ❌ Same "session" key read from persistent storage; will never see
        //    the value written by create_session above.
        env.storage().persistent().get("session").unwrap_or(0)
    }

    /// Overwrites the session in persistent storage, confusing the data domain.
    pub fn persist_session(env: Env, value: u32) {
        // ❌ Same "session" key now written to persistent storage
        env.storage().persistent().set("session", &value);
    }
}

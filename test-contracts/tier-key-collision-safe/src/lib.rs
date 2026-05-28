#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct TierKeyCollisionSafe;

#[contractimpl]
impl TierKeyCollisionSafe {
    /// Stores a short-lived session token in temporary storage.
    pub fn create_session(env: Env, value: u32) {
        // ✅ "session" key is exclusively used with temporary storage
        env.storage().temporary().set("session", &value);
    }

    /// Reads the session from the same temporary storage tier.
    pub fn get_session(env: Env) -> u32 {
        // ✅ Consistent: reads from the same tier it was written to
        env.storage().temporary().get("session").unwrap_or(0)
    }

    /// Stores long-lived config in persistent storage under a distinct key.
    pub fn set_config(env: Env, value: u32) {
        // ✅ "config" key is exclusively used with persistent storage
        env.storage().persistent().set("config", &value);
    }

    /// Reads config from persistent storage.
    pub fn get_config(env: Env) -> u32 {
        // ✅ Consistent: reads from the same tier it was written to
        env.storage().persistent().get("config").unwrap_or(0)
    }
}

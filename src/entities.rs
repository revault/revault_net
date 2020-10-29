//! Entities is a module that abstracts different entity types in the revault
//! network and provides the necessary data structures and functionality
//! for secure communication.

use crate::error::Error;
use serde::{Deserialize, Serialize};
// use serde_json;
use snow::params::NoiseParams;
use std::{collections::HashMap, fs::File, hash::Hash, path::Path};

// Used by wallet, cosigner, and watchtower software to maintain a map of
// the entities which they can securely communicate with.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityMap {
    stakeholder_map: Option<HashMap<Stakeholder, Vec<u8>>>,
    manager_map: Option<HashMap<Manager, Vec<u8>>>,
    cosigner_map: Option<HashMap<Cosigner, Vec<u8>>>,
    watchtower_map: Option<HashMap<Watchtower, Vec<u8>>>,
}

impl EntityMap {
    // Construct an EntityMap from a hash map (presumably one generated from a config file)
    pub fn new(
        stakeholder_map: Option<HashMap<Stakeholder, Vec<u8>>>,
        manager_map: Option<HashMap<Manager, Vec<u8>>>,
        cosigner_map: Option<HashMap<Cosigner, Vec<u8>>>,
        watchtower_map: Option<HashMap<Watchtower, Vec<u8>>>,
    ) -> Self {
        EntityMap {
            stakeholder_map,
            manager_map,
            cosigner_map,
            watchtower_map,
        }
    }

    // Write the entity map to disk as serialized JSON.
    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut file = File::create(path).map_err(|e| {
            Error::EntityMap(format!("Failed to create file for entity map: {}", e))
        })?;
        // let map_str = serde_json::to_string(self)
        // Write map_str to file...
        Ok(())
    }

    // Open the EntityMap
    pub fn open<P: AsRef<Path>>(path: P) -> Result<(), Error> {
        //pub fn open<P: AsRef<Path>>(path: P) -> Result<EntityMap, Error> {
        let file = File::open(path)
            .map_err(|e| Error::EntityMap(format!("Failed to open entity map: {}", e)))?;
        // read from file...
        // let map: EntityMap = serde_json::from_str(_)
        // Ok( map )
        unimplemented!()
    }
}

pub trait Entity {
    fn get_pubkey(&self) -> Vec<u8>;

    // Other useful functionality?
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Stakeholder {
    // Static public key used for noise handshake
    pub public_key: Vec<u8>,
}

impl Entity for Stakeholder {
    fn get_pubkey(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Manager {
    pub public_key: Vec<u8>,
}

impl Entity for Manager {
    fn get_pubkey(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Watchtower {
    pub public_key: Vec<u8>,
}

impl Entity for Watchtower {
    fn get_pubkey(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Cosigner {
    pub public_key: Vec<u8>,
}

impl Entity for Cosigner {
    fn get_pubkey(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_map() {
        unimplemented!();
    }
}

//! Revault noise wrapper functions
//!
//! The User software should be able to handle being an initiator and a responder in
//! noise handshakes. The Cosigner and Watchtower software should always act as a
//! responder and only for User initiators.

use crate::entities::{Cosigner, Entity, EntityMap, Manager, Stakeholder, Watchtower};
use crate::error::Error;
use snow::{params::NoiseParams, resolvers::SodiumResolver, Builder, HandshakeState, Keypair};
use std::net::TcpStream;

#[derive(Debug)]
pub enum RemoteEntity {
    Cosigner(Cosigner),
    Manager(Manager),
    Stakeholder(Stakeholder),
    Watchtower(Watchtower),
}

/// In Revault a Stakeholder connects only to Stakeholders and Watchtowers, which both implementing
/// the Entity trait, with a distinct noise handshake pattern. This function returns the exact
/// Noise parameters to use.  
pub fn get_noise_params_as_stakeholder(remote_entity: &RemoteEntity) -> Result<NoiseParams, Error> {
    match remote_entity {
        Watchtower => Ok("Noise_XK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
        Stakeholder => Ok("Noise_KK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
        _ => Err(Error::Noise(format!(
            "Stakeholders only connect with Watchtowers and other Stakeholders"
        ))),
    }
}

/// In Revault a Manager connects only to Stakeholders and Watchtowers, which both implementing
/// the Entity trait, with a distinct noise handshake pattern. This function returns the exact
/// Noise parameters to use.  
pub fn get_noise_params_as_manager(remote_entity: &RemoteEntity) -> Result<NoiseParams, Error> {
    match remote_entity {
        Watchtower => Ok("Noise_XK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
        Cosigner => Ok("Noise_XK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
        _ => Err(Error::Noise(format!(
            "Managers only connect with Watchtowers and Cosigners"
        ))),
    }
}

/// A Watchtower only enacts a noise handshake as a responder, and always with
/// a User initiator.
pub fn get_noise_params_as_watchtower() -> Result<NoiseParams, Error> {
    Ok("Noise_XK_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?)
}

/// A Cosigner only enacts a noise handhsake as a responder, and always with
/// a User initiator.
pub fn get_noise_params_as_cosigner() -> Result<NoiseParams, Error> {
    Ok("Noise_XK_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?)
}

/// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
/// when generating a static key pair for secure communication.
pub fn generate_keypair(noise_params: NoiseParams) -> Result<Keypair, Error> {
    Ok(
        Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()))
            .generate_keypair()
            .map_err(|_| Error::Noise(format!("Failed to generate keypair")))?,
    )
}

/// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
/// when generating a handshake state using a builder.
pub fn get_handshake_state(
    noise_params: NoiseParams,
    initiator: bool,
    static_priv_key: &[u8],
    remote_pub_key: &[u8],
) -> Result<HandshakeState, Error> {
    let builder = Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()));
    if initiator {
        Ok(builder
            .local_private_key(&static_priv_key)
            .remote_public_key(&remote_pub_key)
            .build_initiator()
            .map_err(|_| Error::Noise(format!("Failed to build initiator")))?)
    } else {
        Ok(builder
            .local_private_key(&static_priv_key)
            .remote_public_key(&remote_pub_key)
            .build_responder()
            .map_err(|_| Error::Noise(format!("Failed to build responder")))?)
    }
}

// Given an incoming TCP stream, the calling software needs to determine which entity it
// is communicating with and decipher the message that is read.
pub fn decipher_stream(stream: TcpStream, map: EntityMap, buf: &mut [u8]) -> Result<(), Error> {
    // for each entity in entity_map:
    //      get pubkey
    //      get NoiseParams
    //      try to decipher msg:
    //          if ok { write deciphered msg to buf & return }
    //          else { continue }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        generate_keypair, get_handshake_state, get_noise_params_as_cosigner,
        get_noise_params_as_manager, get_noise_params_as_stakeholder,
        get_noise_params_as_watchtower, RemoteEntity,
    };
    use crate::entities::{Cosigner, Stakeholder, Watchtower};

    #[test]
    fn test_get_noise_params() {
        let dummy_pubkey: Vec<u8> = Vec::new();
        let wt = RemoteEntity::Watchtower(Watchtower {
            public_key: dummy_pubkey.clone(),
        });
        let cs = RemoteEntity::Cosigner(Cosigner {
            public_key: dummy_pubkey.clone(),
        });
        let stk = RemoteEntity::Stakeholder(Stakeholder {
            public_key: dummy_pubkey,
        });

        // Check noise parameter selection doesn't error for the hard-coded
        // handshake patterns.
        assert!(get_noise_params_as_stakeholder(&wt).is_ok());
        assert!(get_noise_params_as_stakeholder(&stk).is_ok());
        assert!(get_noise_params_as_manager(&cs).is_ok());
        assert!(get_noise_params_as_manager(&wt).is_ok());
        assert!(get_noise_params_as_cosigner().is_ok());
        assert!(get_noise_params_as_watchtower().is_ok());
    }

    #[test]
    fn test_generate_keypair() {
        let dummy_pubkey: Vec<u8> = Vec::new();
        let stk = RemoteEntity::Stakeholder(Stakeholder {
            public_key: dummy_pubkey,
        });
        let noise_params = get_noise_params_as_stakeholder(&stk).unwrap();
        assert!(generate_keypair(noise_params).is_ok());
    }

    #[test]
    fn test_get_handshake_state() {
        // User as initiator
        let dummy_pubkey: Vec<u8> = Vec::new();
        let stk = RemoteEntity::Stakeholder(Stakeholder {
            public_key: dummy_pubkey,
        });
        let noise_params = get_noise_params_as_stakeholder(&stk).unwrap();
        let initiator = true;
        let local_keypair = generate_keypair(noise_params.clone()).unwrap();
        let remote_keypair = generate_keypair(noise_params.clone()).unwrap();
        assert!(get_handshake_state(
            noise_params.clone(),
            initiator,
            &local_keypair.private,
            &remote_keypair.public
        )
        .is_ok());

        // User as responder
        let initiator = false;
        let local_keypair = generate_keypair(noise_params.clone()).unwrap();
        let remote_keypair = generate_keypair(noise_params.clone()).unwrap();
        assert!(get_handshake_state(
            noise_params,
            initiator,
            &local_keypair.private,
            &remote_keypair.public
        )
        .is_ok());
    }
}

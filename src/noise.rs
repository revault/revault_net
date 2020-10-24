//! Revault noise wrapper functions
//!
//! The User software should be able to handle being an initiator and a responder in
//! noise handshakes. The Cosigner and Watchtower software should always act as a
//! responder and only for User initiators.

use crate::error::Error;
use snow::{params::NoiseParams, resolvers::SodiumResolver, Builder, HandshakeState, Keypair};

/// Type for specifying the remote entity a User is connecting to
#[derive(Debug)]
pub enum RemoteEntity {
    /// Watchtower
    Watchtower,
    /// Cosigner
    Cosigner,
    /// User
    User,
}

/// In Revault a User connects to any of the RemoteEntity variants with a different
/// noise handshake pattern. This function specifies the exact Noise parameters to use.  
pub fn get_noise_params_as_user(remote_entity: &RemoteEntity) -> Result<NoiseParams, Error> {
    match remote_entity {
        RemoteEntity::Watchtower => Ok("Noise_XK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
        RemoteEntity::Cosigner => Ok("Noise_XK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
        RemoteEntity::User => Ok("Noise_KK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?),
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

#[cfg(test)]
mod tests {
    use super::{
        generate_keypair, get_handshake_state, get_noise_params_as_cosigner,
        get_noise_params_as_user, get_noise_params_as_watchtower, RemoteEntity,
    };

    #[test]
    fn test_get_noise_params() {
        let wt = RemoteEntity::Watchtower {};
        let cs = RemoteEntity::Cosigner {};
        let us = RemoteEntity::User {};

        // Check noise parameter selection doesn't error for the hard-coded
        // handshake patterns.
        assert!(get_noise_params_as_user(&wt).is_ok());
        assert!(get_noise_params_as_user(&cs).is_ok());
        assert!(get_noise_params_as_user(&us).is_ok());
        assert!(get_noise_params_as_cosigner().is_ok());
        assert!(get_noise_params_as_watchtower().is_ok());
    }

    #[test]
    fn test_generate_keypair() {
        let us = RemoteEntity::User {};
        let noise_params = get_noise_params_as_user(&us).unwrap();
        assert!(generate_keypair(noise_params).is_ok());
    }

    #[test]
    fn test_get_handshake_state() {
        // User as initiator
        let us = RemoteEntity::User {};
        let noise_params = get_noise_params_as_user(&us).unwrap();
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

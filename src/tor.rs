//! Tor wrapper
//!
//! Contains useful methods for starting the Tor daemon
use libtor::{
    log::{LogDestination, LogLevel},
    Tor, TorFlag,
};
use std::thread::JoinHandle;

// Libtor doesn't like msvc ¯\_(ツ)_/¯
#[cfg(target_env = "msvc")]
compile_error!("Tor feature can't be used with msvc. Use mingw instead.");

/// Result of the `start_tor` method. Contains useful info
/// about the Tor daemon running
#[derive(Debug)]
pub struct TorProxy {
    /// JoinHandle of the Tor daemon
    pub tor_handle: Option<JoinHandle<Result<u8, libtor::Error>>>,
    /// Host of the SOCKS5 proxy
    pub host: String,
    /// Socks port used by the Tor daemon
    pub socks_port: u16,
    /// Data directory used by the Tor daemon
    pub data_directory: String,
}

impl TorProxy {
    /// Starts the Tor daemon using the provided data_directory and socks_port. If
    /// no socks_port is provided, Tor will pick one, which will be available in
    /// the `TorProxy` structure
    // TODO: maybe add the control port as well? It might be useful.
    pub fn start_tor(data_directory: String, socks_port: Option<u16>) -> Self {
        let log_file = format!("{}/log", data_directory);
        let mut tor = Tor::new();
        tor.flag(TorFlag::LogTo(
            LogLevel::Notice,
            LogDestination::File(log_file.clone()),
        ))
        .flag(TorFlag::DataDirectory(data_directory.clone()))
        // Otherwise tor will catch our attempts to shut down processes...
        .flag(TorFlag::Custom("__DisableSignalHandlers 1".into()));

        if let Some(port) = socks_port {
            tor.flag(TorFlag::SocksPort(port));
        } else {
            tor.flag(TorFlag::Custom("SocksPort auto".into()));
        }

        let tor_handle = tor.start_background().into();

        let socks_port = socks_port.unwrap_or_else(|| {
            // Alright, we need to discover which socks port we're using
            // Let's grep the log file :)
            use std::io::Read;
            let needle = "Socks listener listening on port ";
            for _ in 0..15 {
                let mut haystack = String::new();
                let port: Option<u16> = std::fs::File::open(&log_file)
                    .ok()
                    .and_then(|mut f| f.read_to_string(&mut haystack).ok())
                    .and_then(|_| haystack.find(needle))
                    .and_then(|i| haystack[i + needle.len()..].splitn(2, '.').next())
                    .and_then(|s| s.parse().ok());
                if let Some(port) = port {
                    return port;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            panic!("Can't find socks_port in logfile");
        });

        TorProxy {
            tor_handle,
            host: "127.0.0.1".into(),
            socks_port,
            data_directory,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn start_tor() {
        // FIXME: Well, this is not testing much. Ignored for now, but it might
        // be useful for debugging purposes.
        // Note that you can't have multiple tor running in the same process,
        // so if you want to start this you need to make sure that `cargo test`
        // is not running other tests that start tor (only test_transport_kk_tor
        // for now).
        TorProxy::start_tor("/tmp/tor-revault-net".into(), None);
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

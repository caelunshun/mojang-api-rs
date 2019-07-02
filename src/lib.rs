//! This crate implements a simple API for
//! interfacing with the Mojang API.
//!
//! Currently, only server-side authentication
//! has been implemented, but more functions will
//! be added in the near future.

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

use num_bigint::BigInt;
use openssl::sha::Sha1;

use reqwest::Client;

/// The session server's response to
/// an authentication request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServerAuthResponse {
    /// The player's UUID, encoded
    /// as a string without dashes.
    /// The string can be serialized
    /// using `Uuid::from_str()`.
    pub id: String,
    /// The player's username.
    pub name: String,
    /// A list of properties sent by the session
    /// server. Typically, a "textures"
    /// property is sent containing the player's
    /// skin.
    pub properties: Vec<ServerAuthProperty>,
}

/// A property, as returned by the session server
/// during authentication. Typically, a "textures"
/// property is received in the authentication response
/// which contains base64-encoded JSON data. See wiki.vg
/// for more information.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServerAuthProperty {
    /// The name of the property.
    pub name: String,
    /// The value of the property.
    /// In the case of the "textures" property,
    /// this is sent as a base64-encoded
    /// JSON dictionary containing the skin's
    /// URL/
    pub value: String,
    /// The property's signature as signed
    /// by Yggdrasil's private key.
    /// This is used by the client to ensure
    /// validity of the data.
    pub signature: String,
}

/// An error during authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Something went wrong with the request.
    /// For example, the Internet might not be
    /// reacheable.
    RequestFailed,
    /// Authentication failed. If this error
    /// is returned, servers should kick clients.
    AuthFailed,
}

/// Performs a server-side authentication request as documented
/// at wiki.vg/Authentication. `server_hash` can be obtained
/// by calling `server_hash()`.
pub fn server_auth(username: &str, server_hash: &str) -> Result<ServerAuthResponse, AuthError> {
    let url = format!(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}&unsigned=false",
        username, server_hash
    );
    let client = Client::new();

    let mut res = client
        .get(&url)
        .send()
        .map_err(|_| AuthError::RequestFailed)?;

    let text = res.text().map_err(|_| AuthError::AuthFailed)?;
    trace!("Authentication response: {}", text);

    let res: ServerAuthResponse = serde_json::from_str(&text).map_err(|_| AuthError::AuthFailed)?;

    Ok(res)
}

/// Computes the "server hash" required for authentication
/// based on the server ID, the shared secret, and the server's
/// public RSA key. On modern Minecraft versions, the server ID
/// is always an empty string.
pub fn server_hash(server_id: &str, shared_secret: [u8; 16], pub_key: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(server_id.as_bytes());
    hasher.update(&shared_secret);
    hasher.update(pub_key);

    mc_hexdigest(hasher)
}

fn mc_hexdigest(hasher: Sha1) -> String {
    let output = hasher.finish();

    let bigint = BigInt::from_signed_bytes_be(&output);
    format!("{:x}", bigint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdigest() {
        // Examples from wiki.vg
        let mut hasher = Sha1::new();
        hasher.update(b"Notch");
        assert_eq!(
            mc_hexdigest(hasher),
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
        );

        let mut hasher = Sha1::new();
        hasher.update(b"jeb_");
        assert_eq!(
            mc_hexdigest(hasher),
            "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1"
        );

        let mut hasher = Sha1::new();
        hasher.update(b"simon");
        assert_eq!(
            mc_hexdigest(hasher),
            "88e16a1019277b15d58faf0541e11910eb756f6"
        );
    }
}

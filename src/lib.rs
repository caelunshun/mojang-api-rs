//! A simple, easy-to-use library for interfacing with the Mojang API.
//!
//! All functions involving IO in this crate are asynchronous and utilize
//! async/await. As a result, you will have to use nightly Rust until async/await
//! is stabilized.
//!
//! This crate provides a number of functions:
//!
//! * Server-side authentication with the Mojang API, used to verify
//! that clients have logged in correctly. This is available using the
//! [`server_auth`](fn.server_auth.html) function.
//! * Obtaining the "server hash" required for authentication, available using
//! [`server_hash`](fn.server_hash.html). Since Mojang uses abnormal hash digests
//! for obtaining the value, this crate provides a simple way to obtain it.
//!
//! # Examples
//! Authenticating a client on a server:
//! ```no_run
//! #![feature(async_await)]
//! # #[tokio::main]
//! # async fn main() -> Result<(), mojang_api::Error> {
//! # let shared_secret = [0; 16];
//! # let username = "test";
//! # let public_key = &[0];
//!
//! // Obtain the "server hash"
//! let server_hash = mojang_api::server_hash(
//!     "", // Note that the "server ID" is always an empty string
//!     shared_secret,
//!     public_key,
//! );
//!
//! // Make the API request
//! let response = mojang_api::server_auth(&server_hash, username).await?;
//!
//! // Now do something with it...
//! # Ok(())
//! # }
//! ```

#![feature(async_await)]
#![forbid(unsafe_code, missing_docs, missing_debug_implementations, warnings)]
#![doc(html_root_url = "https://docs.rs/mojang-api/0.2.0")]

use bytes::Buf;
use hyper::{Body, Client};
use hyper_tls::HttpsConnector;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::string::FromUtf8Error;
use uuid::Uuid;

type StdResult<T, E> = std::result::Result<T, E>;

/// Result type used by this crate. This is equivalent
/// to `std::result::Result<T, mojang_api::Error>`.
pub type Result<T> = StdResult<T, Error>;

/// Error type for this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Indicates that an IO error occurred.
    Io(io::Error),
    /// Indicates that an HTTP error occurred.
    Http(hyper::Error),
    /// Indicates that the UTF8 bytes failed to parse.
    Utf8(FromUtf8Error),
    /// Indicates that the response included malformed JSON.
    /// This could also indicate that, for example, authentication
    /// failed, because the response would have unexpected fields.
    Json(serde_json::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> StdResult<(), fmt::Error> {
        match self {
            Error::Io(e) => write!(f, "{}", e)?,
            Error::Http(e) => write!(f, "{}", e)?,
            Error::Utf8(e) => write!(f, "{}", e)?,
            Error::Json(e) => write!(f, "{}", e)?,
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

/// Represents the response received when performing
/// server-side authentication with the Mojang API.
///
/// The response includes the player's UUID, username,
/// and optionally some `ProfileProperty`s, which may
/// represent, for example, the player's skin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthResponse {
    /// The UUID of the player.
    pub id: Uuid,
    /// The current username of the player.
    pub name: String,
    /// The player's profile properties.
    #[serde(default)] // If none returned, use empty vector
    pub properties: Vec<ProfileProperty>,
}

/// Represents a profile property returned in the server
/// authentication request.
///
/// The most common profile property is called "textures"
/// and contains the skin of the player.
///
/// Note that both `value` and `signature` are base64-encoded
/// strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileProperty {
    /// The name of this profile property.
    pub name: String,
    /// The base64-encoded value of this profile property.
    pub value: String,
    /// The signature of this profile property, signed with Yggdrasil's private key.
    pub signature: String,
}

/// Performs server-side authentication using the given server hash
/// and username.
///
/// The server hash can be retrieved using [`server_hash`](fn.server_hash.html).
/// Obtaining it requires the server's public RSA key and the secret key
/// being used for encryption with the client.
///
/// Performing this request also requires the client's username.
/// Servers should use the value sent in the Login Start packet.
///
/// The request is performed asynchronously, and this function is `async`.
///
/// See [wiki.vg](https://wiki.vg/Protocol_Encryption#Server) for more
/// information.
///
/// # Examples
/// ```no_run
/// #![feature(async_await)]
/// # #[tokio::main]
/// # async fn main() -> Result<(), mojang_api::Error> {
/// # fn server_hash() -> String { "".to_string() }
/// # fn username() -> String { "".to_string() }
/// // Obtain the server hash and username...
/// let hash = server_hash();
/// let username = username();
///
/// // Make the API request
/// let response = mojang_api::server_auth(&hash, &username).await?;
/// # Ok(())
/// # }
/// ```
pub async fn server_auth(server_hash: &str, username: &str) -> Result<ServerAuthResponse> {
    #[cfg(not(test))]
    let url = format!(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&server_id={}",
        username, server_hash
    );
    #[cfg(test)]
    let url = format!(
        "{}?username={}&serverId={}",
        mockito::server_url(),
        username,
        server_hash
    );

    let connector = HttpsConnector::new(1).unwrap();

    let client = Client::builder().build::<_, Body>(connector);
    let response = client
        .get(url.parse().unwrap())
        .await
        .map_err(Error::Http)?;

    let mut body = response.into_body();

    let response = body_to_string(&mut body).await?;
    let json: ServerAuthResponse = serde_json::from_str(&response).map_err(Error::Json)?;

    Ok(json)
}

/// Computes the "server hash" required for authentication
/// based on the server ID, the shared secret used for
/// communication with the client, and the server's
/// public RSA key.
///
/// On modern Minecraft versions, the server ID
/// is always an empty string.
///
/// # Examples
/// ```
/// # fn shared_secret() -> [u8; 16] { [0; 16] }
/// # fn pub_key() -> &'static [u8] { &[1] }
/// let hash = mojang_api::server_hash("", shared_secret(), pub_key());
/// ```
pub fn server_hash(server_id: &str, shared_secret: [u8; 16], pub_key: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(server_id.as_bytes());
    hasher.update(&shared_secret);
    hasher.update(pub_key);

    mc_hexdigest(hasher)
}

/// Generates a digest for the given hasher using
/// Minecraft's abnormal method.
fn mc_hexdigest(hasher: Sha1) -> String {
    let output = hasher.digest().bytes();

    let bigint = BigInt::from_signed_bytes_be(&output);
    format!("{:x}", bigint)
}

/// Reads a `Body` into a string.
async fn body_to_string(body: &mut Body) -> Result<String> {
    let mut s = String::new();

    while let Some(next) = body.next().await {
        let mut chunk = next.map_err(Error::Http)?;
        let mut vec = vec![0; chunk.len()];
        chunk.copy_to_slice(&mut vec);

        let string = String::from_utf8(vec).map_err(Error::Utf8)?;
        s.push_str(&string);
    }

    Ok(s)
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

    #[tokio::test]
    async fn test_server_auth() -> Result<()> {
        use uuid::Uuid;

        let uuid = Uuid::new_v4();
        let username = "test_";
        let prop_name = "test_prop";
        let prop_val = "test_val";
        let prop_signature = "jioiodqwqiowoiqf";

        let prop = ProfileProperty {
            name: prop_name.to_string(),
            value: prop_val.to_string(),
            signature: prop_signature.to_string(),
        };

        let response = ServerAuthResponse {
            name: username.to_string(),
            id: uuid,
            properties: vec![prop],
        };

        let _m = mockito::mock("GET", "/")
            .with_body(serde_json::to_string(&response).unwrap())
            .create();
        let hash = server_hash("", [0; 16], &[0]);

        let result = server_auth(&hash, username).await?;

        assert_eq!(result.id, uuid);
        assert_eq!(result.name, username);
        assert_eq!(result.properties.len(), 1);

        let prop = result.properties.first().unwrap();

        assert_eq!(prop.name, prop_name);
        assert_eq!(prop.value, prop_val);
        assert_eq!(prop.signature, prop_signature);

        Ok(())
    }
}

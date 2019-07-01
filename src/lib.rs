#[macro_use]
extern crate serde_derive;

use num_bigint::BigInt;
use openssl::sha::Sha1;

use reqwest::Client;

/*#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RequestFailed,
    BadResponse,
}*/

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServerAuthResponse {
    pub id: String,
    pub name: String,
    pub properties: Vec<ServerAuthProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServerAuthProperty {
    pub name: String,
    pub value: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    RequestFailed,
    AuthFailed,
}

pub fn server_auth(username: &str, server_hash: &str) -> Result<ServerAuthResponse, AuthError> {
    let url = format!(
        "https://sessionserver.mojang.com/session/minecraft/hashJoined?username={}&serverId={}",
        username, server_hash
    );
    let client = Client::new();

    let mut res = client
        .get(&url)
        .send()
        .map_err(|_| AuthError::RequestFailed)?;
    let res: ServerAuthResponse = res.json().map_err(|_| AuthError::RequestFailed)?;

    Ok(res)
}

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

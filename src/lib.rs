#[macro_use]
extern crate serde_derive;

#[cfg(test)]
use mockito;
use reqwest::Client;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RequestFailed,
    BadResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProfileSkinCape {
    pub id: String,
    pub name: String,
    pub properties: Vec<ProfileSkinCapeProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProfileSkinCapeProperty {
    name: String,
    value: String,
    signature: String,
}

pub fn get_profile_skin_cape(player_uuid: Uuid) -> Result<ProfileSkinCape, Error> {
    let client = Client::new();
    let url = format!(
        "https://sessionserver.mojang.com/session/minecraft/profile/{}",
        player_uuid.to_simple().to_string()
    );
    let mut res = client.get(&url).send().map_err(|_| Error::RequestFailed)?;

    let res: ProfileSkinCape = res.json().map_err(|_| Error::BadResponse)?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;

}

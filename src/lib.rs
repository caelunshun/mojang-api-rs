#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;

const STATUS_URL: &'static str = "https://status.mojang.com/check";
const API_URL: &'static str = "https://api.mojang.com";

pub enum Error {
    RequestFailed,
    BadResponse,
}

/// The status values returned by the API status
/// check.
#[derive(Clone, Copy, Debug)]
pub enum APIStatusValue {
    /// The service has no issues and is running
    /// fine.
    NoIssues,
    /// The service has some issues.
    SomeIssues,
    /// The service is unavailable
    Unavailable,
}

impl APIStatusValue {
    fn from_string(s: &str) -> Result<Self, Error> {
        match s {
            "red" => Ok(APIStatusValue::Unavailable),
            "yellow" => Ok(APIStatusValue::SomeIssues),
            "green" => Ok(APIStatusValue::NoIssues),
            _ => Err(Error::BadResponse),
        }
    }
}
/// The result when querying the API status URL.
/// This type contains a mapping of service names (as `String`s)
/// to `APIStatusValues` to represent the response.
#[derive(Clone, Debug)]
pub struct APIStatusResponse {
    statuses: HashMap<String, APIStatusValue>,
}

impl APIStatusResponse {
    pub fn get_status(&self, service: &str) -> Option<&APIStatusValue> {
        self.statuses.get(service)
    }
}

pub fn api_status() -> Result<APIStatusResponse, Error> {
    let client = reqwest::Client::new();
    let mut res = client.get(STATUS_URL)
        .send()
        .map_err(|_| Error::RequestFailed)?;

    let map: HashMap<String, String> = res.json().map_err(|_| Error::BadResponse)?;
    let statuses = map.into_iter().map(|(k, v)| {
        let val = APIStatusValue::from_string(&v)?;
        Ok((k, val))
    }).collect::<Result<HashMap<String, APIStatusValue>, Error>>();

    match statuses {
        Ok(m) => Ok(APIStatusResponse { statuses: m }),
        Err(e) => Err(e),
    }
}
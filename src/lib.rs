#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;

#[cfg(test)]
use mockito;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    RequestFailed,
    BadResponse,
}

/// The status values returned by the API status
/// check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum APIStatus {
    /// The service has no issues and is running
    /// fine.
    NoIssues,
    /// The service has some issues.
    SomeIssues,
    /// The service is unavailable
    Unavailable,
}

impl APIStatus {
    fn from_string(s: &str) -> Result<Self, Error> {
        match s {
            "red" => Ok(APIStatus::Unavailable),
            "yellow" => Ok(APIStatus::SomeIssues),
            "green" => Ok(APIStatus::NoIssues),
            _ => Err(Error::BadResponse),
        }
    }
}
/// The result when querying the API status URL.
/// This type contains a mapping of service names (as `String`s)
/// to `APIStatusValues` to represent the response.
#[derive(Clone, Debug)]
pub struct APIStatusResponse {
    statuses: HashMap<String, APIStatus>,
}

impl APIStatusResponse {
    pub fn get_status(&self, service: &str) -> Option<APIStatus> {
        self.statuses.get(service).cloned()
    }
}

pub fn api_status() -> Result<APIStatusResponse, Error> {
    #[cfg(not(test))]
    let url = "https://status.mojang.com/check";
    #[cfg(test)]
    let url = &format!("{}{}", &mockito::server_url(), "/check");

    let client = reqwest::Client::new();
    let mut res = client
        .get(url)
        .send()
        .map_err(|_| Error::RequestFailed)?;

    let map: HashMap<String, String> = {
        let mut m = HashMap::new();
        let val: Value = res.json().map_err(|_| Error::BadResponse)?;
        let arr = val.as_array().ok_or_else(|| Error::BadResponse)?;
        for obj in arr {
            let obj = obj.as_object().ok_or_else(|| Error::BadResponse)?;
            let (key, val) = obj.iter().next().ok_or_else(|| Error::BadResponse)?;
            let val = val.as_str().ok_or_else(|| Error::BadResponse)?;
            m.insert(key.to_string(), val.to_string());
        }
        m
    };

    let statuses = map
        .into_iter()
        .map(|(k, v)| {
            let val = APIStatus::from_string(&v)?;
            Ok((k, val))
        })
        .collect::<Result<HashMap<String, APIStatus>, Error>>();

    match statuses {
        Ok(m) => Ok(APIStatusResponse { statuses: m }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;

    #[test]
    fn test_status_value_from_str() {
        assert_eq!(
            APIStatus::from_string("green"),
            Ok(APIStatus::NoIssues)
        );
        assert_eq!(
            APIStatus::from_string("yellow"),
            Ok(APIStatus::SomeIssues)
        );
        assert_eq!(
            APIStatus::from_string("red"),
            Ok(APIStatus::Unavailable)
        );
    }

    #[test]
    fn test_api_status() {
        let _m = mock("GET", "/check")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body("[{\"minecraft.net\": \"yellow\"}]");

        assert_eq!(api_status().unwrap().get_status("minecraft.net"), Some(APIStatus::SomeIssues));
    }

}

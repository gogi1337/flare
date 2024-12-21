use std::{fs, net::Ipv4Addr};

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub addr: String,
    pub routes: Vec<Route>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    pub route: String,
    pub forward: u16,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)?;

    Ok(config)
}

pub fn find_route<'a>(routes: &'a Vec<Route>, route_name: &str) -> Option<&'a Route> {
    routes.iter().find(|route| route.route == route_name)
}

pub fn split_host(host_raw: String) -> (Ipv4Addr, u16) {
    let hostsep = host_raw.find(":")
        .unwrap();

    let host = host_raw.get(0..hostsep)
        .unwrap()
        .parse::<Ipv4Addr>()
        .unwrap();

    let port = host_raw.get(hostsep+1..host_raw.len())
        .unwrap()
        .parse::<u16>()
        .unwrap();

    (host, port)
}
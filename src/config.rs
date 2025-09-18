use std::{fs, net::Ipv4Addr};

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub addr: String,
    pub disable_domain_not_configured_warns: bool,
    pub disable_failed_to_reach_warns: bool,
    pub routes: Vec<Route>,
}

impl<'a> Config {
    pub fn new(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;

        Ok(config)
    }

    pub fn find_route(&self, route_name: &str) -> Option<&Route> {
        self.routes.iter().find(|route| route.route == route_name)
    }

    pub fn host(&self) -> (Ipv4Addr, u16) {
        let hostsep = self.addr.find(":")
            .unwrap();
    
        let host = self.addr.get(0..hostsep)
            .unwrap()
            .parse::<Ipv4Addr>()
            .unwrap();
    
        let port = self.addr.get(hostsep+1..self.addr.len())
            .unwrap()
            .parse::<u16>()
            .unwrap();
    
        (host, port)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    pub route: String,
    pub forward: String,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)?;

    Ok(config)
}
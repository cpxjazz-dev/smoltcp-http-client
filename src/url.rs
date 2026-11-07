//! 极简 URL 解析：只够 HTTP 客户端用，不做通用 URL 库。
//!
//! 支持 `http://host[:port][/path...]` 和 `https://host[:port][/path...]`。
//! v0.1.0 的限制：
//! - 主机必须是 IPv4 字面量（没有 DNS，域名会报 [`Error::DnsUnsupported`]）；
//! - 不支持 IPv6 字面量、不支持 userinfo（`user:pass@host`）。

use core::net::Ipv4Addr;
use core::str::FromStr;

use crate::Error;

/// `http` 或 `https`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// URL 里的主机部分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
    /// IPv4 字面量，如 `192.168.1.100`。
    Ip(Ipv4Addr),
    /// 域名，如 `example.com`（v0.1.0 不能直接用，等 DNS）。
    Domain(&'a str),
}

/// 解析后的 URL。
#[derive(Debug, Clone, Copy)]
pub struct Url<'a> {
    pub scheme: Scheme,
    pub host: Host<'a>,
    /// 显式端口，没有就按 scheme 取默认（http 80 / https 443）。
    pub port: u16,
    /// 路径 + 查询串，带前导 `/`，没有就默认为 `/`。
    pub path: &'a str,
}

impl<'a> Url<'a> {
    pub fn parse(url: &'a str) -> Result<Self, Error> {
        let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
            (Scheme::Http, r)
        } else if let Some(r) = url.strip_prefix("https://") {
            (Scheme::Https, r)
        } else {
            return Err(Error::InvalidUrl);
        };

        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || path.is_empty() {
            return Err(Error::InvalidUrl);
        }

        // 主机[:端口]。IPv4 里没有冒号，用 rfind 找端口分隔符是安全的。
        let (host_str, port) = match authority.rfind(':') {
            Some(i) => {
                let port = authority[i + 1..]
                    .parse::<u16>()
                    .map_err(|_| Error::InvalidUrl)?;
                (&authority[..i], port)
            }
            None => (
                authority,
                if scheme == Scheme::Http { 80 } else { 443 },
            ),
        };
        if host_str.is_empty() {
            return Err(Error::InvalidUrl);
        }

        let host = match Ipv4Addr::from_str(host_str) {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(host_str),
        };

        Ok(Url {
            scheme,
            host,
            port,
            path,
        })
    }

    /// 主机是 IPv4 字面量时返回它，否则返回 `None`。
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self.host {
            Host::Ip(ip) => Some(ip),
            Host::Domain(_) => None,
        }
    }
}

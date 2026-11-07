//! 阻塞式 `no_std` HTTP/HTTPS 客户端，跑在 raw smoltcp 之上。
//!
//! 从 ESP32-C3 PIR 模板（`esp32-pir-template`）的 TCP 上报代码里抽出来、
//! 通用化之后的样子：模板里那段“连 TCP、发 POST、读响应”被包成了
//! 一个能直接当依赖拉的 crate，PIR 上报只是它的用法之一。
//!
//! # 设计
//!
//! 这个 crate 本身不依赖任何 ESP 的包，也不自己管 Wi-Fi / DHCP /
//! 套接字集合——那些是调用方的活。调用方实现 [`TcpTransport`] 这个
//! 小 trait（一般就是把自家 `Net` 结构体里现成的几行 smoltcp 操作
//! 透传出来，见 `examples/post_json.rs`），然后：
//!
//! ```ignore
//! let mut client = HttpClient::new(&mut net);
//! let resp = client.post_json("http://192.168.1.100:8080/motion", br#"{"event":"motion"}"#)?;
//! assert_eq!(resp.status, 200);
//! ```
//!
//! # HTTPS
//!
//! `tls` feature（默认不开）用 pure-Rust 的 `embedded-tls` 阻塞模式
//! 做 TLS 1.3，证书链 + 主机名都校验（根证书由调用方以 DER 形式
//! 提供）。限制见 [`tls`] 模块文档和 README 的“限制与路线图”。

#![no_std]

extern crate alloc;

pub mod client;
pub mod error;
pub mod transport;
pub mod url;
#[cfg(feature = "tls")]
pub mod tls;

pub use client::{HttpClient, Method, Request, Response};
pub use error::Error;
pub use transport::TcpTransport;
pub use url::{Host, Scheme, Url};
#[cfg(feature = "tls")]
pub use tls::TlsOptions;

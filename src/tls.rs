//! 可选的 TLS 1.3 支持（feature `tls`）。
//!
//! 用 pure-Rust 的 `embedded-tls`（阻塞模式），没有 C 依赖，
//! 能在 riscv32 上编译。只支持 TLS 1.3；证书链 + 主机名都会校验，
//! 根证书由调用方以 DER 形式提供。
//!
//! # 为什么不用 rustls
//!
//! rustls 默认的 `ring` 后端只支持 64 位 RISC-V，
//! ESP32-C3 是 32 位 riscv32imc，编不过；`aws-lc-rs` 后端要给
//! riscv32 编 C 代码，目标机上没有交叉 C 编译器。
//! `embedded-tls` 是纯 Rust 实现，没有这些问题，
//! 而且它有阻塞模式，正好配这个 crate 的阻塞式设计
//! （`embedded-io-async` 的那套只适合 Embassy 路线）。
//!
//! # 证书有效期
//!
//! v0.1.0 不校验证书有效期：芯片上没有可靠时钟（要先跑 SNTP 对时），
//! 这里用 `NoClock`，只校验“证书链能不能追到你给的根证书”和
//! “主机名对不对”。这是明确写出来的限制，不是悄悄跳过的：
//! 过期证书在 v0.1.0 里会被接受。等你有了 SNTP 时间源，
//! 再把 `TlsOptions` 换成带时钟的版本（路线图见 README）。

use embedded_tls::blocking::{TlsConfig, TlsConnection, TlsContext};
use embedded_tls::pki::CertVerifier;
use embedded_tls::{
    Aes128GcmSha256, Certificate, CryptoProvider, CryptoRngCore, NoClock, TlsVerifier,
};

use crate::client::Stream;
use crate::error::Error;
use crate::transport::TcpTransport;

/// TLS 记录缓冲的推荐大小：8 KiB 每个方向。
/// embedded-tls 一次只处理一个 TLS 记录；服务器的记录通常
/// 不超过 4 KiB，8 KiB 留了余量；想要最大兼容性就用 16384。
pub const TLS_RECORD_BUFFER_SIZE: usize = 8192;

/// 证书链的最大字节数（`CertVerifier` 的 `CERT_SIZE` 参数）。
/// 一条常见的公网证书链（根 + 中间 + 叶子）约 3–4 KiB，4 KiB 够用。
pub const TLS_MAX_CERT_SIZE: usize = 4096;

/// HTTPS 需要的选项。调用方在每次请求时现配现用：
/// 根证书和随机数都是调用方的东西，这个 crate 不替你保管。
pub struct TlsOptions<'a> {
    /// 服务器名：发 SNI 用，也用来校验服务端证书的主机名。
    /// 注意：它和 URL 里的 IP 是两回事——URL 写 IP（连哪台机器），
    /// 这里写域名（证书是给谁颁的），比如 URL 是
    /// `https://192.168.1.100/api`，这里就写 `api.example.com`。
    pub server_name: &'a str,
    /// 根证书，DER 编码，如 `include_bytes!("ca.der")`。
    /// 校验时会拿服务端的证书链往这个根上追。
    pub ca_der: &'a [u8],
    /// 硬件随机数源（如 esp-hal 的 `Rng`；如果它没有实现
    /// `CryptoRng`，包一层 newtype 转发 `RngCore` + `CryptoRng` 即可）。
    pub rng: &'a mut dyn CryptoRngCore,
    /// TLS 读记录缓冲，推荐 `TLS_RECORD_BUFFER_SIZE`。
    pub read_buffer: &'a mut [u8],
    /// TLS 写记录缓冲，推荐 `TLS_RECORD_BUFFER_SIZE`。
    pub write_buffer: &'a mut [u8],
}

/// `embedded-io` 适配层：把调用方的 `TcpTransport` 包成
/// `embedded-tls` 要的阻塞 `Read` / `Write`。
///
/// 语义是阻塞式的：`read` 会一直等到有数据、对端关闭或超时，
/// 不会返回 `WouldBlock`——`embedded-tls` 的阻塞模式就是这么用的。
pub struct SmoltcpIo<'t, T: TcpTransport> {
    transport: &'t mut T,
    timeout_ms: u32,
}

impl<'t, T: TcpTransport> SmoltcpIo<'t, T> {
    pub fn new(transport: &'t mut T, timeout_ms: u32) -> Self {
        Self {
            transport,
            timeout_ms,
        }
    }
}

#[derive(Debug)]
pub struct IoError;

// embedded-io 0.7 的 `Error` trait 要求 `core::error::Error`，
// 所以这里要补 Display + Error（之前只 derive 了 Debug）。
impl core::fmt::Display for IoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "I/O error")
    }
}

impl core::error::Error for IoError {}

impl embedded_io::Error for IoError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl<T: TcpTransport> embedded_io::ErrorType for SmoltcpIo<'_, T> {
    type Error = IoError;
}

impl<T: TcpTransport> embedded_io::Read for SmoltcpIo<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let deadline = self.transport.now_ms() + self.timeout_ms as u64;
        loop {
            if self.transport.now_ms() > deadline {
                return Err(IoError);
            }
            self.transport.poll();
            if self.transport.can_recv() {
                return match self.transport.recv(buf) {
                    Ok(n) => Ok(n),
                    Err(_) => Ok(0),
                };
            }
            if !self.transport.may_recv() {
                return Ok(0);
            }
            self.transport.delay_ms(5);
        }
    }
}

impl<T: TcpTransport> embedded_io::Write for SmoltcpIo<'_, T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        let deadline = self.transport.now_ms() + self.timeout_ms as u64;
        loop {
            if self.transport.now_ms() > deadline {
                return Err(IoError);
            }
            self.transport.poll();
            if self.transport.may_send() {
                return self.transport.send(buf).map_err(|_| IoError);
            }
            self.transport.delay_ms(5);
        }
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.transport.poll();
        Ok(())
    }
}

/// 一个 TLS 1.3 会话（阻塞式），可当 [`Stream`] 用。
pub struct TlsStream<'o, 't, T: TcpTransport> {
    conn: TlsConnection<'o, SmoltcpIo<'t, T>, Aes128GcmSha256>,
}

impl<'o, 't, T: TcpTransport> TlsStream<'o, 't, T> {
    /// 在已建立的 TCP 连接上做 TLS 握手。`transport` 必须是已经
    /// 连上、对端可达的状态（`HttpClient` 会先把 TCP 建好）。
    pub fn open(
        transport: &'t mut T,
        opts: TlsOptions<'o>,
        timeout_ms: u32,
    ) -> Result<Self, Error> {
        let io = SmoltcpIo::new(transport, timeout_ms);
        let config = TlsConfig::new()
            .with_server_name(opts.server_name)
            .enable_rsa_signatures();
        let mut conn = TlsConnection::new(io, opts.read_buffer, opts.write_buffer);
        let provider = VerifyingProvider::new(opts.rng, opts.ca_der);
        conn.open(TlsContext::new(&config, provider))?;
        Ok(Self { conn })
    }

    /// 发 close_notify，优雅结束 TLS 会话。错误直接忽略——
    /// 后面 `HttpClient` 还会关 TCP 连接。
    pub fn close(self) {
        let _ = self.conn.close();
    }
}

impl<'o, 't, T: TcpTransport> Stream for TlsStream<'o, 't, T> {
    fn write_all(&mut self, mut data: &[u8], _deadline_ms: u64) -> Result<(), Error> {
        // 超时由底下的 SmoltcpIo 按 open() 时给的 timeout_ms 卡，
        // 这里的 deadline 参数用不上（TLS 握手 / 记录读写是
        // 在 embedded-tls 内部阻塞完成的，没法中途打断）。
        // 注意：这里故意不用 embedded-io 的 write_all，
        // 直接调 TlsConnection 的 write（不管它是 inherent 方法
        // 还是 trait 方法都能编过），手动循环写完。
        while !data.is_empty() {
            let n = self.conn.write(data).map_err(Error::from)?;
            if n == 0 {
                return Err(Error::Send);
            }
            data = &data[n..];
        }
        Ok(())
    }

    fn read_some(&mut self, buf: &mut [u8], _deadline_ms: u64) -> Result<usize, Error> {
        // 同上：超时由 SmoltcpIo 卡。
        let n = self.conn.read(buf).map_err(Error::from)?;
        Ok(n)
    }
}

/// 带证书校验的 crypto provider：把调用方的随机数源和 `CertVerifier`
///（根证书 + `NoClock`）包在一起，交给 `TlsContext`。
///
/// embedded-tls 0.19 的形状（以 0.19.0 源码 `src/config.rs` /
/// `src/pki.rs` / `tests/rustpki_test.rs` 为准，2026-11-07 在
/// InstaBox 机器上核实）：
/// - `TlsContext::new` 要的是一个 `CryptoProvider`，而不是 verifier 本身；
/// - `CertVerifier::new` 只收一个参数——`Certificate::X509(ca_der)`，
///   时钟（`NoClock`）是 `CertVerifier` 的泛型参数，不是构造参数；
/// - 随机数由 `CryptoProvider::rng()` 提供；
/// - `signer` / `client_cert` 用默认实现（本 crate 不做双向认证）。
struct VerifyingProvider<'a> {
    rng: &'a mut dyn CryptoRngCore,
    verifier: CertVerifier<'a, Aes128GcmSha256, NoClock, TLS_MAX_CERT_SIZE>,
}

impl<'a> VerifyingProvider<'a> {
    fn new(rng: &'a mut dyn CryptoRngCore, ca_der: &'a [u8]) -> Self {
        Self {
            rng,
            verifier: CertVerifier::new(Certificate::X509(ca_der)),
        }
    }
}

impl CryptoProvider for VerifyingProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    // 本 crate 不做客户端证书认证，signer 永远不会被调到；
    // 这个类型只用来满足 trait，取一个能 `AsRef<[u8]>` 的定长数组即可。
    type Signature = [u8; 72];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut *self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}

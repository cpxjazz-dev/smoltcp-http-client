//! 错误类型。

use core::fmt;

/// 这个 crate 的错误。`Display` 写的是人能直接看懂的一句话，
/// 串口打印出来就能定位。
#[derive(Debug)]
pub enum Error {
    /// TCP 连接失败（对端不可达、端口没开、路由不通等）。
    Connect,
    /// TCP 连接超时（三次握手一直没完成）。
    ConnectTimeout,
    /// 发数据失败（对端提前关闭等）。
    Send,
    /// 收数据失败。
    Recv,
    /// 响应超时（连接上了，但对方一直不回）。
    ResponseTimeout,
    /// URL 写错了（缺 `http://` / `https://`、缺主机、端口不是数字等）。
    InvalidUrl,
    /// 主机名是域名：v0.1.0 还没有 DNS，只能写 IPv4 字面量。
    DnsUnsupported,
    /// `https://` 的 URL，但没开 `tls` feature 或没走 `*_tls` 方法。
    TlsRequired,
    /// 响应解析失败（状态行 / 响应头不合规、body 没收全就断了等）。
    InvalidResponse,
    /// 服务端用了 `Transfer-Encoding: chunked`，v0.1.0 不支持。
    /// 请求用的是 HTTP/1.0，合规的服务端不会回 chunked。
    ChunkedUnsupported,
    /// 响应 body 超过 `HttpClient::with_max_body_bytes` 的上限。
    BodyTooLarge,
    /// TLS 握手 / 读写失败（证书校验不通过也在这里）。
    #[cfg(feature = "tls")]
    Tls(embedded_tls::TlsError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::Connect => "TCP connect failed",
            Error::ConnectTimeout => "TCP connect timed out",
            Error::Send => "TCP send failed",
            Error::Recv => "TCP recv failed",
            Error::ResponseTimeout => "HTTP response timed out",
            Error::InvalidUrl => "invalid URL",
            Error::DnsUnsupported => "DNS is not supported yet, use an IPv4 literal",
            Error::TlsRequired => "https URL requires the `tls` feature and a *_tls method",
            Error::InvalidResponse => "invalid HTTP response",
            Error::ChunkedUnsupported => "chunked transfer-encoding is not supported yet",
            Error::BodyTooLarge => "response body exceeds the size limit",
            #[cfg(feature = "tls")]
            Error::Tls(e) => return write!(f, "TLS error: {:?}", e),
        };
        write!(f, "{}", msg)
    }
}

impl core::error::Error for Error {}

#[cfg(feature = "tls")]
impl From<embedded_tls::TlsError> for Error {
    fn from(e: embedded_tls::TlsError) -> Self {
        Error::Tls(e)
    }
}

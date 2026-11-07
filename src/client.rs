//! 阻塞式 HTTP 客户端：`HttpClient`、`Request`、`Response`。
//!
//! 请求固定用 HTTP/1.0 + `Connection: close`（一次请求一个连接，
//! 用完就关）：这是从模板里验证过的做法，逻辑最简单，
//! 服务端不会回 chunked，body 按 `Content-Length` 收，
//! 没有 `Content-Length` 就收到对端关闭为止。

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use smoltcp::wire::IpAddress;

use crate::error::Error;
use crate::transport::TcpTransport;
use crate::url::{Scheme, Url};

/// 默认本地端口（固定一个就行，不用随机端口）。
pub const DEFAULT_LOCAL_PORT: u16 = 49152;
/// 默认连接超时：10 秒。
pub const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 10_000;
/// 默认响应超时：5 秒。
pub const DEFAULT_RESPONSE_TIMEOUT_MS: u32 = 5_000;
/// 默认响应 body 上限：64 KiB（C3 只有 400 KiB SRAM，别让一个
/// 失控的响应把堆吃光；不够用就 `with_max_body_bytes` 调大）。
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
/// 响应头上限：8 KiB。
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// HTTP 方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Head => "HEAD",
        }
    }
}

/// 一次 HTTP 请求。
pub struct Request<'a> {
    pub method: Method,
    pub url: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn new(method: Method, url: &'a str) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: &[],
        }
    }

    pub fn get(url: &'a str) -> Self {
        Self::new(Method::Get, url)
    }

    pub fn post(url: &'a str, content_type: &'a str, body: &'a [u8]) -> Self {
        Self::new(Method::Post, url)
            .header("Content-Type", content_type)
            .body(body)
    }

    pub fn post_json(url: &'a str, body: &'a [u8]) -> Self {
        Self::post(url, "application/json", body)
    }

    pub fn header(mut self, name: &'a str, value: &'a str) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn body(mut self, body: &'a [u8]) -> Self {
        self.body = body;
        self
    }
}

/// 一次 HTTP 响应：状态码 + 响应头 + body（已收全）。
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// 按名取响应头（不区分大小写），没有返回 `None`。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// body 当 UTF-8 字符串读（不是合法 UTF-8 就报错）。
    pub fn body_str(&self) -> Result<&str, core::str::Utf8Error> {
        core::str::from_utf8(&self.body)
    }
}

/// 阻塞式字节流：明文 TCP 和 TLS 会话都长这样，
/// HTTP 收发逻辑只认这个接口，不用管下面是不是加密的。
pub(crate) trait Stream {
    /// 全部写出（阻塞到写完、出错或 `deadline_ms` 超时）。
    fn write_all(&mut self, data: &[u8], deadline_ms: u64) -> Result<(), Error>;
    /// 至少读 1 个字节（阻塞到有数据、对端关闭或超时）。
    /// 返回 0 表示对端已关闭（读完了）。
    fn read_some(&mut self, buf: &mut [u8], deadline_ms: u64) -> Result<usize, Error>;
}

/// 明文 TCP 流：直接包着调用方的 `TcpTransport`。
struct TcpStream<'t, T: TcpTransport> {
    transport: &'t mut T,
}

impl<'t, T: TcpTransport> Stream for TcpStream<'t, T> {
    fn write_all(&mut self, mut data: &[u8], deadline_ms: u64) -> Result<(), Error> {
        while !data.is_empty() {
            if self.transport.now_ms() > deadline_ms {
                return Err(Error::ResponseTimeout);
            }
            self.transport.poll();
            if !self.transport.may_send() {
                return Err(Error::Send);
            }
            let n = self.transport.send(data)?;
            if n == 0 {
                // 发送缓冲满了，等一会儿再试。
                self.transport.delay_ms(5);
            } else {
                data = &data[n..];
            }
        }
        Ok(())
    }

    fn read_some(&mut self, buf: &mut [u8], deadline_ms: u64) -> Result<usize, Error> {
        loop {
            if self.transport.now_ms() > deadline_ms {
                return Err(Error::ResponseTimeout);
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

/// 阻塞式 HTTP 客户端。一次请求一个连接，用完就关。
pub struct HttpClient<'t, T: TcpTransport> {
    transport: &'t mut T,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    local_port: u16,
    max_body_bytes: usize,
}

impl<'t, T: TcpTransport> HttpClient<'t, T> {
    pub fn new(transport: &'t mut T) -> Self {
        Self {
            transport,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            response_timeout_ms: DEFAULT_RESPONSE_TIMEOUT_MS,
            local_port: DEFAULT_LOCAL_PORT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    pub fn with_connect_timeout(mut self, ms: u32) -> Self {
        self.connect_timeout_ms = ms;
        self
    }

    pub fn with_response_timeout(mut self, ms: u32) -> Self {
        self.response_timeout_ms = ms;
        self
    }

    pub fn with_local_port(mut self, port: u16) -> Self {
        self.local_port = port;
        self
    }

    pub fn with_max_body_bytes(mut self, n: usize) -> Self {
        self.max_body_bytes = n;
        self
    }

    /// 发一次 HTTP 请求（`http://` 的 URL）。
    pub fn request(&mut self, req: &Request) -> Result<Response, Error> {
        let url = Url::parse(req.url)?;
        if url.scheme == Scheme::Https {
            return Err(Error::TlsRequired);
        }
        let ip = url.ip().ok_or(Error::DnsUnsupported)?;
        self.connect_tcp(ip, url.port)?;
        let host_header = format!("{}", ip);
        let deadline = self.transport.now_ms() + self.response_timeout_ms as u64;
        let result = {
            let mut stream = TcpStream {
                transport: &mut *self.transport,
            };
            exchange(
                &mut stream,
                req,
                &url,
                &host_header,
                deadline,
                self.max_body_bytes,
            )
        };
        self.finish_tcp();
        result
    }

    /// `GET`。
    pub fn get(&mut self, url: &str) -> Result<Response, Error> {
        self.request(&Request::get(url))
    }

    /// `POST`，`Content-Type` 自己定。
    pub fn post(&mut self, url: &str, content_type: &str, body: &[u8]) -> Result<Response, Error> {
        self.request(&Request::post(url, content_type, body))
    }

    /// `POST`，`Content-Type: application/json`。
    pub fn post_json(&mut self, url: &str, body: &[u8]) -> Result<Response, Error> {
        self.request(&Request::post_json(url, body))
    }

    /// 发一次 HTTPS 请求（`https://` 的 URL），需要 `tls` feature。
    /// 证书链 + 主机名都会校验，根证书和随机数由 `tls_opts` 提供。
    ///
    /// 注意这里把 `tls_opts` 的字段重借成函数内的短生命周期再传给
    /// `TlsStream::open`：`TlsConnection` 要求 transport 的借用活得比
    /// TLS 缓冲久，如果直接传 `tls_opts`（它的生命周期是调用方给的
    /// 参数），transport 借用会被迫活满整个参数生命周期，后面就没法
    /// 再借 `self` 调 `finish_tcp`（E0499）。重借之后两个借用都是
    /// 函数内的局部量，`stream.close()` 后即结束。
    #[cfg(feature = "tls")]
    pub fn request_tls(
        &mut self,
        req: &Request,
        tls_opts: crate::tls::TlsOptions,
    ) -> Result<Response, Error> {
        let url = Url::parse(req.url)?;
        if url.scheme != Scheme::Https {
            return Err(Error::InvalidUrl);
        }
        let ip = url.ip().ok_or(Error::DnsUnsupported)?;
        self.connect_tcp(ip, url.port)?;
        let host_header = tls_opts.server_name.to_string();
        let deadline = self.transport.now_ms() + self.response_timeout_ms as u64;
        let result = {
            let tls_opts = tls_opts;
            let opts = crate::tls::TlsOptions {
                server_name: tls_opts.server_name,
                ca_der: tls_opts.ca_der,
                rng: &mut *tls_opts.rng,
                read_buffer: &mut *tls_opts.read_buffer,
                write_buffer: &mut *tls_opts.write_buffer,
            };
            let mut stream = crate::tls::TlsStream::open(
                &mut *self.transport,
                opts,
                self.response_timeout_ms,
            )?;
            let r = exchange(
                &mut stream,
                req,
                &url,
                &host_header,
                deadline,
                self.max_body_bytes,
            );
            // 发 close_notify 再关 TCP（exchange 出错也照做）。
            stream.close();
            r
        };
        self.finish_tcp();
        result
    }

    /// `POST` JSON 到 `https://`，需要 `tls` feature。
    #[cfg(feature = "tls")]
    pub fn post_json_tls(
        &mut self,
        url: &str,
        body: &[u8],
        tls_opts: crate::tls::TlsOptions,
    ) -> Result<Response, Error> {
        self.request_tls(&Request::post_json(url, body), tls_opts)
    }

    /// 建 TCP 连接并等握手完成。
    fn connect_tcp(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), Error> {
        let remote = (
            IpAddress::v4(ip.octets()[0], ip.octets()[1], ip.octets()[2], ip.octets()[3]),
            port,
        );
        self.transport.connect(remote, self.local_port)?;
        let deadline = self.transport.now_ms() + self.connect_timeout_ms as u64;
        loop {
            self.transport.poll();
            if self.transport.may_send() {
                return Ok(());
            }
            if self.transport.now_ms() > deadline {
                self.transport.abort();
                return Err(Error::ConnectTimeout);
            }
            self.transport.delay_ms(10);
        }
    }

    /// 关 TCP 连接，给 FIN 一点时间发出去。
    fn finish_tcp(&mut self) {
        self.transport.close();
        let deadline = self.transport.now_ms() + 500;
        while self.transport.now_ms() < deadline {
            self.transport.poll();
            self.transport.delay_ms(10);
        }
    }
}

/// 一次 HTTP 收发：写请求、读响应头、按 Content-Length（或收到
/// 对端关闭）收 body。`stream` 可能是明文 TCP，也可能是 TLS 会话。
fn exchange<S: Stream>(
    stream: &mut S,
    req: &Request,
    url: &Url,
    host_header: &str,
    deadline_ms: u64,
    max_body_bytes: usize,
) -> Result<Response, Error> {
    // 1. 发请求。Content-Type 等头由 Request 自带；
    // Host / Content-Length / Connection 由客户端统一写。
    let mut request = format!(
        "{} {} HTTP/1.0\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        req.method.as_str(),
        url.path,
        host_header,
        req.body.len(),
    );
    for (name, value) in &req.headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes(), deadline_ms)?;
    if !req.body.is_empty() {
        stream.write_all(req.body, deadline_ms)?;
    }

    // 2. 读响应头，读到 "\r\n\r\n" 为止。
    let mut head: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    let header_end = loop {
        if head.len() > MAX_HEADER_BYTES {
            return Err(Error::InvalidResponse);
        }
        let n = stream.read_some(&mut chunk, deadline_ms)?;
        if n == 0 {
            // 响应头没收全对端就关了。
            return Err(Error::InvalidResponse);
        }
        head.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&head, b"\r\n\r\n") {
            break pos;
        }
    };
    let header_bytes = &head[..header_end];
    // 读响应头那几包里可能已经带了一部分 body，先留着。
    let mut body: Vec<u8> = head[header_end + 4..].to_vec();

    let header_text = core::str::from_utf8(header_bytes).map_err(|_| Error::InvalidResponse)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(Error::InvalidResponse)?;
    let status = parse_status(status_line)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(Error::InvalidResponse)?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.parse().map_err(|_| Error::InvalidResponse)?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
        headers.push((name.to_string(), value.to_string()));
    }
    if chunked {
        return Err(Error::ChunkedUnsupported);
    }

    // 3. 收 body。
    match content_length {
        Some(len) => {
            if len > max_body_bytes {
                return Err(Error::BodyTooLarge);
            }
            while body.len() < len {
                let n = stream.read_some(&mut chunk, deadline_ms)?;
                if n == 0 {
                    // 没收全对端就关了。
                    return Err(Error::InvalidResponse);
                }
                if body.len() + n > max_body_bytes {
                    return Err(Error::BodyTooLarge);
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(len);
        }
        None => {
            // 没有 Content-Length：收到对端关闭为止。
            loop {
                if body.len() > max_body_bytes {
                    return Err(Error::BodyTooLarge);
                }
                let n = stream.read_some(&mut chunk, deadline_ms)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
        }
    }

    Ok(Response {
        status,
        headers,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// 解析状态行，如 `HTTP/1.0 200 OK` / `HTTP/1.1 404 Not Found`。
fn parse_status(line: &str) -> Result<u16, Error> {
    let mut parts = line.split_whitespace();
    let _version = parts.next().ok_or(Error::InvalidResponse)?;
    let code = parts.next().ok_or(Error::InvalidResponse)?;
    code.parse::<u16>().map_err(|_| Error::InvalidResponse)
}

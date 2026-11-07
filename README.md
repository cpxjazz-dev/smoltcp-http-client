# smoltcp-http-client

阻塞式 `no_std` HTTP/HTTPS 客户端，跑在 raw smoltcp 之上。

从 ESP32-C3 PIR 模板（`esp32-pir-template`）的 TCP 上报代码里抽出来、
通用化之后的样子：模板里那段“连 TCP、发 POST、读响应”被包成了
一个能直接当依赖拉的 crate，PIR 上报只是它的用法之一。

```toml
smoltcp-http-client = "0.1"
```

## 特点

- **阻塞式**：没有 Embassy、没有 async，主循环里直接调。
  模板选阻塞路线的原因一样：只有一个任务，没必要上异步。
- **不依赖任何 ESP 的包**：只依赖 smoltcp。Wi-Fi、DHCP、
  套接字集合都在调用方那边，这个 crate 只通过 `TcpTransport`
  trait 收发字节——所以它在任何能跑 smoltcp 的 `no_std` 芯片上
  都能用（ESP32-C3、STM32 + 网卡、RP2040 + W5500……）。
- **HTTPS（`tls` feature）**：pure-Rust 的 `embedded-tls`
  阻塞模式做 TLS 1.3，证书链 + 主机名都校验。

## 用法

调用方实现 `TcpTransport`（一般就是把自家 `Net` 里现成的几行
smoltcp 操作透传出来，完整例子见 `examples/post_json.rs`），然后：

```rust
let mut client = HttpClient::new(&mut net);

let resp = client.post_json(
    "http://192.168.1.100:8080/motion",
    br#"{"event":"motion","count":1}"#,
)?;
assert_eq!(resp.status, 200);
println!("body: {}", resp.body_str()?);
```

`GET` / `POST` / `PUT` / `DELETE` / `PATCH` / `HEAD` 都有，
也可以用 `Request` 自己组装请求头和 body：

```rust
let resp = client.request(
    &Request::get("http://192.168.1.100:8080/status")
        .header("X-Device", "c3-01"),
)?;
```

## HTTPS

```toml
smoltcp-http-client = { version = "0.1", features = ["tls"] }
```

```rust
use smoltcp_http_client::TlsOptions;
use smoltcp_http_client::tls::TLS_RECORD_BUFFER_SIZE;

let mut read_buf = [0u8; TLS_RECORD_BUFFER_SIZE];
let mut write_buf = [0u8; TLS_RECORD_BUFFER_SIZE];

let resp = client.post_json_tls(
    "https://192.168.1.100:443/api",
    br#"{"event":"motion"}"#,
    TlsOptions {
        server_name: "api.example.com", // SNI + 证书主机名校验
        ca_der: include_bytes!("ca.der"), // 根证书（DER）
        rng: &mut rng,                  // 硬件随机数源
        read_buffer: &mut read_buf,
        write_buffer: &mut write_buf,
    },
)?;
```

注意：URL 里写 IP（连哪台机器），`server_name` 里写域名
（证书是给谁颁的）——v0.1.0 还没有 DNS，域名解析在路线图里。
根证书从哪来：`openssl x509 -in ca.pem -outform DER -out ca.der`，
或者用 `webpki-roots` 的 Mozilla 根证书集（它本身也是 `no_std` 的）。

**单核假定**：`tls` feature 假定单核目标。`embedded-tls` 的 RSA 路线
经 `rsa → num-bigint-dig → lazy_static → spin` 用到原子 CAS，
riscv32imc 没有原生 CAS，所以这个 crate 给 `portable-atomic` 开了
`unsafe-assume-single-core`（关中断实现 CAS，和 esp-hal 在 ESP32-C3
上的做法一致；注意不能同时开 `critical-section`）。ESP32-C3 是单核，
符合；多核芯片上不要开 `tls`。

## 为什么是 embedded-tls，而不是 rustls

- rustls 默认的 `ring` 后端只支持 **64 位 RISC-V**，
  ESP32-C3 是 32 位 riscv32imc，编不过；
  `aws-lc-rs` 后端要给 riscv32 编 C 代码，目标机上没有交叉 C 编译器。
- `embedded-tls` 是纯 Rust 实现，没有这些问题，而且它有**阻塞模式**，
  正好配这个 crate 的阻塞式设计（`embedded-io-async` 的那套只适合
  Embassy 路线）。
- `embedded-tls` 只支持 TLS 1.3。现代服务端（Cloudflare、AWS、
  Nginx 默认配置）都支持 TLS 1.3；只支持 TLS 1.2 的老服务端连不上，
  这是明确写出来的限制。

## 安全说明（先看这段再用 HTTPS）

- **证书链 + 主机名都校验**，不会悄悄跳过。根证书由你提供，
  服务端证书必须能追到这个根上。
- **v0.1.0 不校验证书有效期**：芯片上没有可靠时钟（要先跑 SNTP 对时），
  这里用 `NoClock`，过期证书会被接受。这是明确写出来的限制，
  不是悄悄跳过的；等你有了 SNTP 时间源，再换成带时钟的版本。
- 不要用 `UnsecureProvider`（不校验）当正式用法，它只该出现在测试里。
  这个 crate 不提供不校验的选项。

## 限制与路线图

v0.1.0 明确不支持的：

- **DNS**：URL 主机只能写 IPv4 字面量，域名会报 `Error::DnsUnsupported`。
  下一步：用 smoltcp 的 DNS socket 做解析，域名 URL 就能直接用了。
- **IPv6**：只支持 IPv4。
- **chunked 响应**：请求用 HTTP/1.0 + `Connection: close`，
  合规的服务端不会回 chunked；回了就报 `Error::ChunkedUnsupported`。
- **HTTP/2、Keep-Alive**：一次请求一个连接，用完就关。
  传感器上报这个量级不需要复用连接。
- **证书有效期校验**：见上面的安全说明，需要 SNTP 时间源。
- **TLS 1.2**：`embedded-tls` 只支持 TLS 1.3。
- **TLS 只支持单核目标**：见上面 HTTPS 一节，`tls` feature 用
  `portable-atomic` 的 `unsafe-assume-single-core` 实现原子 CAS。

## 和 reqwless 的关系

`reqwless` 是现成的 embedded HTTP 客户端，但它是**异步**的
（`embedded-io-async`，配 Embassy / embassy-net）。
这个 crate 是它的**阻塞版对照**：同样的 HTTP 客户端，
跑在 raw smoltcp + 阻塞主循环上，给不用 Embassy 的项目用。
如果你已经在用 Embassy，直接用 `reqwless` 更合适。

## 版本基线

- smoltcp 0.13、embedded-tls 0.19、embedded-io 0.7
- Rust 1.91+、edition 2024
- example 的 ESP 部分：esp-hal ~1.1 / esp-radio 0.18 / esp-rtos 0.3
  （和 `esp32-pir-template` 同一套基线，成套升级）

## License

MIT OR Apache-2.0

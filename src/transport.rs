//! 传输层 trait：调用方把自家 smoltcp 的操作透传出来，
//! 这个 crate 只通过它收发字节，不直接碰 `Interface` / `SocketSet`。
//!
//! 这样设计的原因：smoltcp 的 `Interface`、`SocketSet`、网卡设备
//! 都是调用方在管（Wi-Fi、DHCP 都在那边），crate 如果自己去借它们，
//! 借用检查会把调用方卡死；用 trait 隔开，各自的借用互不干扰。

use smoltcp::wire::IpAddress;

use crate::Error;

/// 调用方的 TCP 传输层：一个已经建好的 smoltcp TCP 套接字 +
/// 驱动它的办法。实现一般就是十几行透传，见 `examples/post_json.rs`
/// 里的 `Net`。
///
/// 约定：
/// - `send` 返回实际写出的字节数；写 0 表示发送缓冲满了，调用方
///   会 poll 一下再重试，不要当成错误。
/// - `recv` 返回实际读到的字节数；读 0 表示当前没数据（不要当成
///   错误，也不要当成连接关闭；关闭用 `may_recv` 判断）。
/// - `connect` 只负责发起连接；连没连上由 `may_send` 判断。
pub trait TcpTransport {
    /// 单调时钟，毫秒（上电以来的毫秒数就行）。
    /// 客户端用它算连接 / 响应超时。
    fn now_ms(&mut self) -> u64;

    /// 驱动一次 smoltcp（`iface.poll(...)`）。
    fn poll(&mut self);

    /// 阻塞当前线程 `ms` 毫秒。
    fn delay_ms(&mut self, ms: u32);

    /// 发起 TCP 连接：连 `remote`，本地端口用 `local_port`。
    /// 只发起，不等握手完成；握手完成用 `may_send` 判断。
    fn connect(&mut self, remote: (IpAddress, u16), local_port: u16) -> Result<(), Error>;

    /// 往 TCP 发送缓冲写数据，返回写出的字节数（可能比 `data` 短）。
    fn send(&mut self, data: &[u8]) -> Result<usize, Error>;

    /// 从 TCP 接收缓冲读数据，返回读到的字节数（0 = 当前没数据）。
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error>;

    /// 套接字是否处于可发送状态（握手完成且未关闭）。
    fn may_send(&mut self) -> bool;

    /// 接收缓冲里是否有数据可读。
    fn can_recv(&mut self) -> bool;

    /// 对端是否还可能发数据（false = 对端已关闭，读完缓冲就没了）。
    fn may_recv(&mut self) -> bool;

    /// 优雅关闭：发 FIN。
    fn close(&mut self);

    /// 强制关闭：发 RST。
    fn abort(&mut self);
}

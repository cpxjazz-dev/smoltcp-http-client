//! ESP32-C3 上用 `smoltcp-http-client` 发 POST JSON 到 **HTTPS** 的完整例子。
//!
//! 跑法（和 `post_json.rs` 一样）：
//! ```text
//! SSID=你家WiFi PASSWORD=密码 SERVER_IP=192.168.1.100 SERVER_NAME=api.example.com \
//!   cargo run --release --example post_json_tls --features tls
//! ```
//!
//! 和 `post_json.rs` 的区别只有三处：
//! 1. 用 `post_json_tls`（`tls` feature），会真的走 TLS 1.3 握手，
//!    所以这个例程能把 TLS 栈（embedded-tls + rustpki + RSA/P-384）
//!    链接进固件——量 TLS 版固件体积就靠它（只编 `post_json.rs`
//!    的话链接器会把没调到的 TLS 代码全裁掉，测出来的不是实数）。
//! 2. 随机数：`esp-hal` 的 `Rng` 只实现了 `rand_core` 的 `RngCore`，
//!    没实现 `CryptoRng`，不能直接给 `TlsOptions` 用；这里用
//!    `HwRng` 这个 newtype 包一层，转发出 `RngCore + CryptoRng`
//!    （`embedded-tls 0.19` 用的是 `rand_core 0.6`，见 `Cargo.toml`
//!    里 dev-dependencies 的 `rand_core = "0.6"`）。
//! 3. 根证书：`assets/isrg-root-x1.der` 是 Let's Encrypt 的 ISRG Root X1
//!    根证书（DER，官网下载，2035 年到期），`server_name` 必须是
//!    服务端证书上的域名，URL 里写 IP、这里写域名，两者是两回事。
//!
//! 注意：v0.1.0 不校验证书有效期（见 `src/tls.rs`），也没有 DNS，
//! URL 主机只能写 IPv4 字面量。

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

#[cfg(not(feature = "tls"))]
compile_error!("post_json_tls 需要 --features tls：cargo run --release --example post_json_tls --features tls");

use alloc::format;
use alloc::string::ToString;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::rng::Rng as EspRng;
use esp_hal::time::Instant;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::wifi::{sta::StationConfig, Config, Interface as WifiInterface, PowerSaveMode, WifiController};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{
    Device as SmolDevice, DeviceCapabilities, Medium, RxToken as SmolRxToken, TxToken as SmolTxToken,
};
use smoltcp::socket::dhcpv4;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use smoltcp_http_client::tls::TLS_RECORD_BUFFER_SIZE;
use smoltcp_http_client::{Error, HttpClient, TcpTransport, TlsOptions};

extern crate alloc;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");
const SERVER_IP: [u8; 4] = [192, 168, 1, 100];
const SERVER_PORT: u16 = 443;
const SERVER_PATH: &str = "/api";
/// SNI + 证书主机名校验用的域名（证书是给谁颁的），和 URL 里的 IP 是两回事。
const SERVER_NAME: &str = env!("SERVER_NAME");
/// ISRG Root X1（Let's Encrypt 根证书，DER）。
const CA_DER: &[u8] = include_bytes!("../assets/isrg-root-x1.der");

// ================= 硬件随机数：esp-hal Rng -> rand_core 0.6 =================

/// `esp-hal` 的 `Rng` 只实现了 `rand_core::RngCore`，没实现 `CryptoRng`
/// 标记 trait，所以不能直接当 `TlsOptions.rng` 用（`embedded-tls`
/// 要的是 `rand_core 0.6` 的 `CryptoRngCore = RngCore + CryptoRng`）。
/// 包一层 newtype 转发即可：底层熵源还是片上硬件 RNG。
pub struct HwRng(EspRng);

impl RngCore for HwRng {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }

    fn next_u64(&mut self) -> u64 {
        ((self.0.random() as u64) << 32) | (self.0.random() as u64)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let word = self.0.random().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HwRng {}

// ================= smoltcp 设备适配（抄自 post_json.rs） =================

pub struct WifiDevice<'d> {
    inner: WifiInterface<'d>,
}

impl<'d> WifiDevice<'d> {
    pub fn new(interface: WifiInterface<'d>) -> Self {
        Self { inner: interface }
    }
}

pub struct WifiRxToken(esp_radio::wifi::WifiRxToken);

impl SmolRxToken for WifiRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.0.consume_token(|buf| f(&*buf))
    }
}

pub struct WifiTxToken(esp_radio::wifi::WifiTxToken);

impl SmolTxToken for WifiTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.0.consume_token(len, f)
    }
}

impl SmolDevice for WifiDevice<'_> {
    type RxToken<'a> = WifiRxToken where Self: 'a;
    type TxToken<'a> = WifiTxToken where Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inner
            .receive()
            .map(|(rx, tx)| (WifiRxToken(rx), WifiTxToken(tx)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        self.inner.transmit().map(WifiTxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps
    }
}

// ================= Net：Wi-Fi + DHCP + TCP 套接字 =================

pub struct Net<'a> {
    iface: Interface,
    device: WifiDevice<'static>,
    sockets: SocketSet<'a>,
    dhcp_handle: SocketHandle,
    tcp_handle: SocketHandle,
    delay: Delay,
}

impl<'a> Net<'a> {
    pub fn new(
        device: WifiInterface<'static>,
        socket_entries: &'a mut [SocketStorage<'a>; 2],
        tcp_rx_storage: &'a mut [u8],
        tcp_tx_storage: &'a mut [u8],
        delay: Delay,
    ) -> Self {
        let mut sockets = SocketSet::new(socket_entries as &mut [SocketStorage<'a>]);
        let dhcp_handle = sockets.add(dhcpv4::Socket::new());
        let tcp_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(tcp_rx_storage),
            tcp::SocketBuffer::new(tcp_tx_storage),
        ));

        let mac = device.mac_address();
        let mut device = WifiDevice::new(device);
        let iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&mac))),
            &mut device,
            smol_timestamp(),
        );

        Self {
            iface,
            device,
            sockets,
            dhcp_handle,
            tcp_handle,
            delay,
        }
    }

    pub fn configure_wifi(controller: &mut WifiController<'_>) {
        let station_config = StationConfig::default()
            .with_ssid(SSID)
            .with_password(PASSWORD.to_string());
        controller.set_config(&Config::Station(station_config)).unwrap();
        controller
            .set_power_saving(PowerSaveMode::Minimum)
            .unwrap();
        println!("Wi-Fi started");
    }

    pub fn connect_wifi(controller: &mut WifiController<'_>, delay: &Delay) {
        loop {
            println!("Connecting to SSID={} ...", SSID);
            match embassy_futures::block_on(controller.connect_async()) {
                Ok(_info) => {
                    println!("Wi-Fi connected");
                    return;
                }
                Err(e) => {
                    println!("connect_async() error: {:?}, retrying in 5 s", e);
                    delay.delay_millis(5000);
                }
            }
        }
    }

    pub fn obtain_ip(&mut self) {
        println!("Waiting for DHCP lease ...");
        loop {
            self.iface
                .poll(smol_timestamp(), &mut self.device, &mut self.sockets);
            if let Some(event) = self
                .sockets
                .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
                .poll()
            {
                if let dhcpv4::Event::Configured(config) = event {
                    println!("DHCP: address={}, router={:?}", config.address, config.router);
                    self.iface.update_ip_addrs(|addrs| {
                        addrs.push(IpCidr::Ipv4(config.address)).unwrap();
                    });
                    if let Some(router) = config.router {
                        self.iface
                            .routes_mut()
                            .add_default_ipv4_route(router)
                            .unwrap();
                    }
                    return;
                }
            }
            self.delay.delay_millis(50);
        }
    }
}

// ================= 给 Net 实现 TcpTransport，HttpClient 就能用了 =================

impl TcpTransport for Net<'_> {
    fn now_ms(&mut self) -> u64 {
        Instant::now().duration_since_epoch().as_millis() as u64
    }

    fn poll(&mut self) {
        self.iface
            .poll(smol_timestamp(), &mut self.device, &mut self.sockets);
    }

    fn delay_ms(&mut self, ms: u32) {
        self.delay.delay_millis(ms);
    }

    fn connect(&mut self, remote: (IpAddress, u16), local_port: u16) -> Result<(), Error> {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        socket
            .connect(self.iface.context(), remote, local_port)
            .map_err(|_| Error::Connect)
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        socket.send_slice(data).map_err(|_| Error::Send)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        socket.recv_slice(buf).map_err(|_| Error::Recv)
    }

    fn may_send(&mut self) -> bool {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).may_send()
    }

    fn can_recv(&mut self) -> bool {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).can_recv()
    }

    fn may_recv(&mut self) -> bool {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).may_recv()
    }

    fn close(&mut self) {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        let _ = socket.close();
    }

    fn abort(&mut self) {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).abort();
    }
}

fn smol_timestamp() -> SmolInstant {
    SmolInstant::from_millis(Instant::now().duration_since_epoch().as_millis() as i64)
}

// ================= 主程序：连 Wi-Fi，POST 一条 JSON 到 HTTPS =================

#[esp_hal::main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(size: 128 * 1024);

    let delay = Delay::new();
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    let (mut wifi_controller, interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, Default::default())
            .expect("Failed to initialize Wi-Fi controller");
    let device = interfaces.station;

    let mut socket_entries: [SocketStorage<'_>; 2] = Default::default();
    let mut tcp_rx_storage = [0u8; 2048];
    let mut tcp_tx_storage = [0u8; 2048];
    let mut net = Net::new(
        device,
        &mut socket_entries,
        &mut tcp_rx_storage,
        &mut tcp_tx_storage,
        delay,
    );

    Net::configure_wifi(&mut wifi_controller);
    Net::connect_wifi(&mut wifi_controller, &net.delay);
    net.obtain_ip();

    // TLS 要的随机数源 + 记录缓冲。
    // esp-hal 1.1 的 Rng::new() 不取外设参数（RNG 是单例，直接 new）。
    let mut hw_rng = HwRng(EspRng::new());
    let mut read_buf = [0u8; TLS_RECORD_BUFFER_SIZE];
    let mut write_buf = [0u8; TLS_RECORD_BUFFER_SIZE];

    let url = format!(
        "https://{}.{}.{}.{}:{}{}",
        SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3], SERVER_PORT, SERVER_PATH
    );
    let body = format!(
        r#"{{"event":"motion","count":{}}}"#,
        1
    );

    let mut client = HttpClient::new(&mut net);
    let tls_opts = TlsOptions {
        server_name: SERVER_NAME,
        ca_der: CA_DER,
        rng: &mut hw_rng,
        read_buffer: &mut read_buf,
        write_buffer: &mut write_buf,
    };
    match client.post_json_tls(&url, body.as_bytes(), tls_opts) {
        Ok(resp) => {
            println!(
                "POST ok: status={} body={}",
                resp.status,
                resp.body_str().unwrap_or("<non-utf8>")
            );
        }
        Err(e) => {
            println!("POST failed: {}", e);
        }
    }

    // 发完就停在这里（例子只发一次）。
    loop {
        net.delay.delay_millis(1000);
    }
}

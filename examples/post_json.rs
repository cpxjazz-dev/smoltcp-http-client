//! ESP32-C3 上用 `smoltcp-http-client` 发 POST JSON 的完整例子。
//!
//! 跑法（和 PIR 模板一样）：
//! ```text
//! SSID=你家WiFi PASSWORD=密码 cargo run --release --example post_json
//! ```
//!
//! 这个文件里 `Net` 的作用：
//! 1. 把 Wi-Fi、DHCP、smoltcp 套接字集合管起来（从 PIR 模板的
//!    `net.rs` 抄过来、只留了 TCP + DHCP 的精简版）；
//! 2. 给 `Net` 实现 `TcpTransport`，`HttpClient` 就能用它收发。
//!
//! 注意：`HttpClient` 本身不依赖任何 ESP 的包，
//! 这里的 `Net` 只是“调用方怎么接线”的示范。

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

use alloc::format;
use alloc::string::ToString;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::time::Instant;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::wifi::{sta::StationConfig, Config, Interface as WifiInterface, PowerSaveMode, WifiController};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{
    Device as SmolDevice, DeviceCapabilities, Medium, RxToken as SmolRxToken, TxToken as SmolTxToken,
};
use smoltcp::socket::dhcpv4;
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use smoltcp_http_client::{Error, HttpClient, TcpTransport};

extern crate alloc;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");
const SERVER_IP: [u8; 4] = [192, 168, 1, 100];
const SERVER_PORT: u16 = 8080;
const SERVER_PATH: &str = "/motion";

// ================= smoltcp 设备适配（抄自 PIR 模板 net.rs） =================

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

// ================= 主程序：连 Wi-Fi，POST 一条 JSON =================

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

    let url = format!(
        "http://{}.{}.{}.{}:{}{}",
        SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3], SERVER_PORT, SERVER_PATH
    );
    let body = format!(
        r#"{{"event":"motion","count":{}}}"#,
        1
    );

    let mut client = HttpClient::new(&mut net);
    match client.post_json(&url, body.as_bytes()) {
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

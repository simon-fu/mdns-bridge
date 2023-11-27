
use anyhow::Result;
use time::{UtcOffset, macros::format_description};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt::{time::OffsetTime, MakeWriter}};


// pub mod mdns;
pub mod bridge_mdns;

fn main() -> Result<()>{
    init_log();
    bridge_mdns::run_main()?;
    Ok(())
}

// #[tokio::main]
// async fn main() -> Result<()> {
//     init_log();
//     // recv_and_dump().await?;
//     // send_rubbish().await?;

    
//     let multi_addr0 = "224.0.0.251:5353";
//     let multi_addr1 = multi_addr0;
//     let multi_addr2 = multi_addr0;
//     let if_addr1  = "172.16.3.210";
//     let if_addr2  = "192.168.1.7";
    
//     let std_socket1 = bind_multicast(multi_addr1, Some(if_addr1))?;
//     std_socket1.set_nonblocking(true)?;
//     let socket1 = UdpSocket::from_std(std_socket1)?;

//     let std_socket2 = bind_multicast(multi_addr2, Some(if_addr2))?;
//     let socket2 = socket2::Socket::from(std_socket2);

//     // {
//     //     let addr: SocketAddr = multi_addr2.parse()?;
//     //     socket2.send_to("abc111".as_bytes(), &socket2::SockAddr::from(addr)).with_context(||"socket2 send failed")?;
//     //     debug!("sent ok");
//     // }

//     let std_socket2: std::net::UdpSocket = socket2.into();
//     std_socket2.set_nonblocking(true)?;
//     let socket2 = UdpSocket::from_std(std_socket2)?;


//     // let multi_addr1: SocketAddr = multi_addr1.parse()?;
//     let multi_addr2: SocketAddr = multi_addr2.parse()?;

//     debug!("listening at [{multi_addr1}-{if_addr1}]");
//     debug!("listening at [{multi_addr2}-{if_addr2}]");


//     let mut buf1 = vec![0; 1700];
//     let mut buf2 = vec![0; 1700];
    
//     // socket2.send_to(&buf[..10], multi_addr2).await.with_context(||"send failed")?;

//     loop {
//         tokio::select! {
//             r = socket1.recv_from(&mut buf1) => {
//                 let (len, from_addr) = r?;
//                 debug!("recv1 bytes {from_addr}, {len}");
//                 if len == 0 {
//                     break;
//                 }

//                 socket2.send_to(&buf1[..len], multi_addr2).await.with_context(||"send failed")?;
//                 debug!("send2 bytes {multi_addr2}, {len}");                
//             }
//             r = socket2.recv_from(&mut buf2) => {
//                 let (len, from_addr) = r?;
//                 debug!("recv2 bytes {from_addr}, {len}");
//                 if len == 0 {
//                     break;
//                 }

//                 socket1.send_to(&buf2[..len], multi_addr1).await.with_context(||"send failed")?;
//                 debug!("send1 bytes {multi_addr1}, {len}");                
//             }
//         }
//         // let (len, from_addr) = socket1.recv_from(&mut buf1).await?;
//         // debug!("recv bytes {from_addr}, {len}");
//         // if len == 0 {
//         //     break;
//         // }

//         // socket2.send_to(&buf1[..len], multi_addr2).await.with_context(||"send failed")?;
//         // // socket2.send(&buf[..len]).await.with_context(||"send failed")?;
//         // debug!("send bytes {multi_addr2}, {len}");
//     }

//     Ok(())
// }


// async fn recv_and_dump() -> Result<()> {
//     let multi_addr = "224.0.0.251:5353";
//     // let if_addr  = "0.0.0.0";
//     let if_addr  = "172.16.3.210";
    
    
//     let std_socket = bind_multicast(multi_addr, Some(if_addr))?;
//     std_socket.set_nonblocking(true)?;
//     let socket = UdpSocket::from_std(std_socket)?;


//     let multi_addr: SocketAddr = multi_addr.parse()?;
//     debug!("listening at [{multi_addr}-{if_addr}]");
//     let mut buf = vec![0; 1700];

//     loop {
//         let (len, from_addr) = socket.recv_from(&mut buf).await?;
//         // debug!("-- recv bytes {from_addr}, {len}");
//         if len == 0 {
//             break;
//         }

//         let r = find_subsequence(&buf[..len], ":6112".as_bytes());
//         if r.is_none() {
//             continue;
//         }

//         let mut dup_buf = buf.clone();
//         dup_buf.resize(len, 0);

//         let r = DnsIncoming::new(dup_buf);
//         match r {
//             Ok(incoming) => debug!("{incoming:?}"),
//             Err(e) => debug!("parsing failed: [{e:?}]"),
//         }
//     }

//     Ok(())
// }

// fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
//     haystack.windows(needle.len()).position(|window| window == needle)
// }

// async fn send_rubbish() -> Result<()> {
//     let multi_addr = "224.0.0.251:5353";
//     let if_addr  = "0.0.0.0";
    
//     let std_socket = bind_multicast(multi_addr, Some(if_addr))?;
//     std_socket.set_nonblocking(true)?;
//     let socket = UdpSocket::from_std(std_socket)?;


//     let multi_addr: SocketAddr = multi_addr.parse()?;

//     debug!("listening at [{multi_addr}-{if_addr}]");

//     loop {
//         let data = "abc123".as_bytes();
//         let sent_bytes = socket.send_to(data, multi_addr).await.with_context(||"send failed")?;
//         debug!("sent bytes {multi_addr}, {sent_bytes}", );
//         if sent_bytes == 0 {
//             break;
//         }
//         tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
//     }

//     Ok(())
// }

pub(crate) fn init_log() {
    init_log2(||std::io::stdout())
}

pub(crate) fn init_log2<W2>(w: W2) 
where
    W2: for<'writer> MakeWriter<'writer> + 'static + Send + Sync,
{

    // https://time-rs.github.io/book/api/format-description.html
    let fmts = format_description!("[hour]:[minute]:[second].[subsecond digits:3]");

    let offset = UtcOffset::current_local_offset().expect("should get local offset!");
    let timer = OffsetTime::new(offset, fmts);
    
    let filter = if cfg!(debug_assertions) {
        if let Ok(v) = std::env::var(EnvFilter::DEFAULT_ENV) {
            v.into()
        } else {
            "mdns_bridge=debug".into()
            // "debug".into()
        }
    } else {
        EnvFilter::builder()
        .with_default_directive(LevelFilter::DEBUG.into())
        .from_env_lossy()
    };
        
    tracing_subscriber::fmt()
    .with_max_level(tracing::metadata::LevelFilter::DEBUG)
    .with_env_filter(filter)
    // .with_env_filter("rtun=debug,rserver=debug")
    .with_writer(w)
    .with_timer(timer)
    .with_target(false)
    .init();
}

// fn bind_multicast(
//     multi_addr: &str,
//     if_addr: Option<&str>,
// ) -> Result<std::net::UdpSocket> {
//     let multi_addr: SocketAddr = multi_addr.parse()?;

//     let if_addr = match if_addr {
//         Some(v) => Some(v.parse()?),
//         None => None,
//     };

//     bind_multicast_ip(&multi_addr, if_addr)
// }

// fn bind_multicast_ip(
//     multi_addr: &SocketAddr,
//     if_addr: Option<IpAddr>,
// ) -> Result<std::net::UdpSocket> {
//     use socket2::{Domain, Type, Protocol, Socket};

//     // assert!(multi_addr.ip().is_multicast(), "Must be multcast address");

//     match *multi_addr {
//         SocketAddr::V4(multi_addr) => { 
            
//             let domain = Domain::IPV4;

//             let interface = match if_addr {
//                 Some(v) => match v {
//                     IpAddr::V4(v) => v,
//                     IpAddr::V6(_) => bail!("multi addr v4 but if addr v6"),
//                 },
//                 None => Ipv4Addr::new(0, 0, 0, 0),
//             };

//             // parse_interface_or(xfer, ||Ok(Ipv4Addr::new(0, 0, 0, 0)))
//             // .with_context(||format!("invalid ipv4 [{:?}]", xfer))?;
            
//             debug!("udp addr: multicast [{}], ipv4 iface [{}]", multi_addr, interface);

//             // let if_addr = SocketAddr::new(interface.into(), multi_addr.port());

//             let socket = Socket::new(
//                 domain,
//                 Type::DGRAM,
//                 Some(Protocol::UDP),
//             )?;
//             socket.set_reuse_address(true)?;
//             socket.set_reuse_port(true)?;
//             // // socket.bind(&socket2::SockAddr::from(if_addr))?;
//             // // socket.bind(&socket2::SockAddr::from(multi_addr))?;
//             // try_bind_multicast(&socket, &multi_addr.into())?;

//             let bind_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), multi_addr.port());
//             // let bind_addr = SocketAddrV4::new(interface, multi_addr.port());
//             socket.bind(&socket2::SockAddr::from(bind_addr))?;
            

//             // 接收端好像没什么用
//             // 发送端设置为true时，可以用同一个 socket 收到自己发送的数据
//             socket.set_multicast_loop_v4(false)?;  

//             // join to the multicast address, with all interfaces
//             socket.join_multicast_v4(
//                 multi_addr.ip(),
//                 &interface,
//             )?;

//             Ok(socket.into())
//         },
//         SocketAddr::V6(multi_addr) => {
            
//             let domain = Domain::IPV6;

//             let interface = match if_addr {
//                 Some(v) => match v {
//                     IpAddr::V4(_v) => bail!("multi addr v6 but if addr v4"),
//                     IpAddr::V6(v) => v,
//                 },
//                 None => Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
//             };

//             // let interface = parse_interface_or(xfer, ||Ok(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))
//             // .with_context(||format!("invalid ipv6 [{:?}]", xfer))?;
//             debug!("udp addr: multicast [{}], ipv6 iface [{}]", multi_addr, interface);

//             // let if_addr = SocketAddr::new(interface.into(), multi_addr.port());

//             let socket = Socket::new(
//                 domain,
//                 Type::DGRAM,
//                 Some(Protocol::UDP),
//             )?;
//             // reuse address 是允许多个进程监听同一个地址:端口，但是同一个进程绑定两次会有问题？
//             // reuse port 是多个socket负载均衡
//             // 参考： https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
//             socket.set_reuse_address(true)?;
//             // socket.bind(&socket2::SockAddr::from(if_addr))?;
//             // socket.bind(&socket2::SockAddr::from(multi_addr))?;
//             try_bind_multicast(&socket, &multi_addr.into())?;

//             socket.set_multicast_loop_v6(false)?;

//             // join to the multicast address, with all interfaces (ipv6 uses indexes not addresses)
//             socket.join_multicast_v6(
//                 multi_addr.ip(),
//                 0,
//             )?;

//             Ok(socket.into())
//         },
//     }

    
// }

// /// On Windows, unlike all Unix variants, it is improper to bind to the multicast address
// ///
// /// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms737550(v=vs.85).aspx
// #[cfg(windows)]
// fn try_bind_multicast(socket: &socket2::Socket, addr: &SocketAddr) -> std::io::Result<()> {
//     let addr = match *addr {
//         SocketAddr::V4(addr) => SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), addr.port()),
//         SocketAddr::V6(addr) => {
//             SocketAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), addr.port())
//         }
//     };
//     socket.bind(&socket2::SockAddr::from(addr))
// }

// /// On unixes we bind to the multicast address, which causes multicast packets to be filtered
// #[cfg(unix)]
// fn try_bind_multicast(socket: &socket2::Socket, addr: &SocketAddr) -> std::io::Result<()> {
//     socket.bind(&socket2::SockAddr::from(*addr))
// }

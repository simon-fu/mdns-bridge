
extern crate pnet;

use pnet::datalink::{self, NetworkInterface, DataLinkReceiver, DataLinkSender};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use anyhow::{Result, Context, bail};


pub fn run_dump_eth(iface: &str) -> Result<()> {

    let config = Arc::new(Config {
        mcast_addr: "224.0.0.251:5353".parse()?,
    });

    let (eth, _eth_tx, mut eth_rx) = make_interface_and_channel(iface)
    .with_context(||format!("failed to make interface [{iface}]"))?;

    let eth_ip = find_ipv4(&eth)?;

    dump_eth(&config, &mut eth_rx, eth_ip)?;

    Ok(())
}

struct Config {
    mcast_addr: SocketAddr,
}

fn dump_eth(
    config: &Arc<Config>,
    en0_rx: &mut Box<dyn DataLinkReceiver>, 
    // ppp0_tx: &mut Box<dyn DataLinkSender>,
    recv_src_ip: Ipv4Addr,
    // send_src_ip: Ipv4Addr,
    // ctx: &Arc<RunContext>,
) -> Result<()> {
    // let mut ether_buf = vec![0u8; 1700];

    // let mut ipv4_buf = vec![0u8; 1700];
    // let mut ipv4_packet_mut = MutableIpv4Packet::new(&mut ipv4_buf)
    // .with_context(||"create mutable ipv4 packet failed")?;

    loop {
        let frame = en0_rx.next().with_context(||"read frame failed")?;
        // if ctx.vpn_down.load(Ordering::Relaxed) {
        //     bail!("vpn has down")
        // }

        let ether_frame = EthernetPacket::new(&frame[..])
        .with_context(||"parse ether packet failed")?;
        if ether_frame.get_ethertype() == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(ether_frame.payload())
            .with_context(||"parse ipv4 packet failed")?;
            // tracing::debug!("  ipv4 packet: protocol {}", packet.get_next_level_protocol());
            
            if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp && packet.get_source() == recv_src_ip {
                // tracing::debug!("  it is protocol udp");
                if let Some(udp) = UdpPacket::new(packet.payload()) {
                    // tracing::debug!("  udp packet: {}, {}", packet.get_destination(), udp.get_destination());

                    let ip = packet.get_destination();
                    let port = udp.get_destination();
                    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
                    if addr == config.mcast_addr {
                        // tracing::debug!("  it is mdns packet");

                        dump_mdns_packet(
                            packet.get_source(), udp.get_source(),
                            ip, port,
                            udp.payload(),
                        );

                    }
                }
            }
        }
    }
}

fn dump_mdns_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) {
    // use pretty_hex::PrettyHex;
    // tracing::debug!("  mdns hex [{src_ip}:{src_port}] -> [{dst_ip}:{dst_port}]: {:?}", payload.hex_dump());
    tracing::debug!("  mdns hex [{src_ip}:{src_port}] -> [{dst_ip}:{dst_port}]: {:?}", payload.len());
    let r = simple_dns::Packet::parse(payload);
    tracing::debug!("  parsed dns [{r:?}]");
}


fn make_interface_and_channel(name: &str) -> Result<(NetworkInterface, Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let en0: NetworkInterface = datalink::interfaces()
    .into_iter()
    .find(|iface| iface.name == name)
    .with_context(|| "NOT found interface")?;
    
    let ch = datalink::channel(&en0, Default::default())
    .with_context(||"create datalink channel failed")?;

    match ch {
        datalink::Channel::Ethernet(tx, rx) => Ok((en0, tx, rx)),
        _e => bail!("unknown channel"),
    }
}

fn find_ipv4(intf: &NetworkInterface) -> Result<Ipv4Addr> {
    for ip in intf.ips.iter() {
        match ip {
            IpNetwork::V4(ip) => return Ok(ip.ip()),
            IpNetwork::V6(_ip) => {},
        }
    }
    bail!("Not found ipv4 address [{}]", intf.name)
}

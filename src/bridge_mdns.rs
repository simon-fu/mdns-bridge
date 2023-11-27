extern crate pnet;

use pnet::datalink::{self, NetworkInterface, DataLinkReceiver, DataLinkSender};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, PacketSize, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::util::MacAddr;
use tracing::{debug, error};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use anyhow::{Result, Context, bail, anyhow};


pub fn run_main() -> Result<()> {
    tracing::debug!("run main");

    let config = Arc::new(Config {
        en: IntfArgs {
            name: "en0".into(),
            mtu: 1500,
        },
        ppp: IntfArgs {
            name: "ppp0".into(),
            mtu: 1280,
        },
        mcast_addr: "224.0.0.251:5353".parse()?,
    });

    let mut last_err: Option<String> = None;

    loop {
        let r = run_loop(&config);
        if let Err(e) = r {
            let err_msg = format!("{e:?}");
            if last_err.as_ref() != Some(&err_msg) {
                error!("{err_msg}");
                last_err = Some(err_msg);
            }
        }
        thread::sleep(Duration::from_millis(1000));
    }
    
}

fn run_loop(config: &Arc<Config>) -> Result<()> {
    let (en0, mut en0_tx, mut en0_rx) = make_interface_and_channel(&config.en.name)
    .with_context(||format!("failed to make interface [{}]", config.en.name))?;

    let (ppp0, mut ppp0_tx, mut ppp0_rx) = make_interface_and_channel(&config.ppp.name)
    .with_context(||format!("failed to make interface [{}]", config.ppp.name))?;

    debug!("-- en0: {:?}", en0);
    debug!("-- ppp0: {:?}", ppp0);


    let en0_mac = en0.mac.with_context(||"no mac address of en0")?;
    let en0_ip = find_ipv4(&en0)?;
    let ppp0_ip = find_ipv4(&ppp0)?;
    debug!("found en0 ip: {en0_ip:?}");
    debug!("found ppp0 ip: {ppp0_ip:?}");
    debug!("ipv4_mcast_addr {:?}", config.mcast_addr);


    let recv_src_ip = en0_ip;
    let send_src_ip = ppp0_ip;
    let config0 = config.clone();
    let en0_to_ppp0 = thread::spawn(move || {
        let r = en0_to_pp0(&config0, &mut en0_rx, &mut ppp0_tx, recv_src_ip, send_src_ip);
        debug!("en0_to_ppp0 finished with [{r:?}]");
    });

    let config0 = config.clone();
    let ppp0_to_en0 = thread::spawn(move || {
        let r = ppp0_to_en0(&config0, &mut ppp0_rx, &mut en0_tx, en0_mac, en0_mac);
        debug!("ppp0_to_en0 finished with [{r:?}]");
    });
    
    ppp0_to_en0.join().map_err(|e|anyhow!("wait for ppp0_to_en0 faile, {e:?}"))?;
    en0_to_ppp0.join().map_err(|e|anyhow!("wait for en0_to_ppp0 faile, {e:?}"))?;
    
    Ok(())
}

pub struct IntfArgs {
    pub name: String,
    pub mtu: usize,
}

struct Config {
    en: IntfArgs,
    ppp: IntfArgs,
    mcast_addr: SocketAddr,
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


fn ppp0_to_en0(
    config: &Arc<Config>,
    ppp0_rx: &mut Box<dyn DataLinkReceiver>, 
    en0_tx: &mut Box<dyn DataLinkSender>,
    send_src_mac: MacAddr,
    send_dst_mac: MacAddr,
) -> Result<()> {
    let mut ether_buf = vec![0u8; 1700];
    let mut ethernet_frame = MutableEthernetPacket::new(&mut ether_buf[..])
    .with_context(||"create mutable ether frame failed")?;
    ethernet_frame.set_source(send_src_mac);
    ethernet_frame.set_destination(send_dst_mac);
    ethernet_frame.set_ethertype(EtherTypes::Ipv4);


    loop {
        let frame = ppp0_rx.next().with_context(||"read frame failed")?;
        let packet = Ipv4Packet::new(&frame[4..])
        .with_context(||"parse ipv4 packet failed")?;
        // tracing::debug!("  ipv4 packet: protocol {}", packet.get_next_level_protocol());
        
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            // tracing::debug!("  it is protocol udp");
            if let Some(udp) = UdpPacket::new(packet.payload()) {
                // tracing::debug!("  udp packet: {}, {}", packet.get_destination(), udp.get_destination());

                let ip = packet.get_destination();
                let port = udp.get_destination();
                let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
                if addr == config.mcast_addr {
                    // tracing::debug!("  it is mdns packet");


                    // ipv4_packet_mut.clone_from(&packet);
                    // ipv4_packet_mut.set_destination(send_dst_ip);
                    // let ipv4_data_len = packet.packet().len();
                    // let ipv4_data = &ipv4_packet_mut.packet()[..ipv4_data_len];

                    let ipv4_data = packet.packet();

                    ethernet_frame.set_payload(ipv4_data);
                    let eframe = ethernet_frame.to_immutable();
                    let ether_packet = &eframe.packet()[..eframe.packet_size() + ipv4_data.len()];
                    

                    tracing::debug!("en0: sent ether packet bytes {}", ether_packet.len());
                    en0_tx.send_to(ether_packet, None)
                    .with_context(||"send but no buffer")?
                    .with_context(||"send but failed")?;
                }
            }
        }
    }

}

fn en0_to_pp0(
    config: &Arc<Config>,
    en0_rx: &mut Box<dyn DataLinkReceiver>, 
    ppp0_tx: &mut Box<dyn DataLinkSender>,
    recv_src_ip: Ipv4Addr,
    send_src_ip: Ipv4Addr,
) -> Result<()> {
    let mut ether_buf = vec![0u8; 1700];

    let mut ipv4_buf = vec![0u8; 1700];
    let mut ipv4_packet_mut = MutableIpv4Packet::new(&mut ipv4_buf)
    .with_context(||"create mutable ipv4 packet failed")?;

    loop {
        let frame = en0_rx.next().with_context(||"read frame failed")?;

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

                        ipv4_packet_mut.clone_from(&packet);
                        ipv4_packet_mut.set_source(send_src_ip);
                        let ipv4_data_len = packet.packet().len();
                        let ipv4_data = &ipv4_packet_mut.packet()[..ipv4_data_len];

                        // let ipv4_data = packet.packet();
                        ether_buf[0] = 0xFF; // address
                        ether_buf[1] = 0x03; // control

                        // protocol (IP)
                        ether_buf[2] = 0x00; 
                        ether_buf[3] = 0x21; 

                        ether_buf[4..4+ipv4_data.len()].clone_from_slice(ipv4_data);
                        let ether_packet = &ether_buf[..4+ipv4_data.len()];
                        
                        // ethernet_frame.set_payload(ipv4_data);
                        // let eframe = ethernet_frame.to_immutable();
                        // let ether_packet = &eframe.packet()[..eframe.packet_size() + ipv4_data.len()];

                        if ether_packet.len() <= config.ppp.mtu {
                            tracing::debug!("ppp0: sent ether packet bytes {} (ipv4_data_len {})", ether_packet.len(), ipv4_data_len);
                            ppp0_tx.send_to(ether_packet, None)
                            .with_context(||"send but no buffer")?
                            .with_context(||"send but failed")?;
                        } else {
                            tracing::debug!("ppp0: drop ether packet bytes {} (ipv4_data_len {})", ether_packet.len(), ipv4_data_len);
                        }
                    }
                }
            }
        }
    }
}

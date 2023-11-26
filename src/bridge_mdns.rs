extern crate pnet;

use pnet::datalink::{self, NetworkInterface, DataLinkReceiver, DataLinkSender};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, PacketSize, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::util::MacAddr;
use tracing::debug;
use std::net::Ipv4Addr;
use std::thread;

pub fn run_main() {
    tracing::debug!("run main");

    // let en0: NetworkInterface = datalink::interfaces()
    //     .into_iter()
    //     .find(|iface| iface.name == "en0")
    //     .unwrap();

    // let ppp0: NetworkInterface = datalink::interfaces()
    //     .into_iter()
    //     .find(|iface| iface.name == "ppp0")
    //     .unwrap();

    // // 创建一个新的线程来处理从 en0 到 ppp0 的数据包转发
    // let en0_to_ppp0 = thread::spawn(move || {
    //     let (_tx, mut rx) = match datalink::channel(&en0, Default::default()) {
    //         Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
    //         _ => panic!("Failed to create datalink channel."),
    //     };

    //     loop {
    //         match rx.next() {
    //             Ok(frame) => {
    //                 let packet = Ipv4Packet::new(&frame[14..]).unwrap();
    //                 if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
    //                     if let Some(udp) = UdpPacket::new(packet.payload()) {
    //                         // 检查是否为组播地址
    //                         if packet.get_destination() == Ipv4Addr::new(224, 0, 0, 251) && udp.get_destination() == 5353 {
    //                             // 创建新的 IP 包
    //                             let mut new_packet = MutableIpv4Packet::owned(packet.packet().to_owned()).unwrap();
    //                             new_packet.set_source(Ipv4Addr::new(172, 16, 3, 210));

    //                             // 发送到 ppp0
    //                             let (mut ppp0_tx, _) = match datalink::channel(&ppp0, Default::default()) {
    //                                 Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
    //                                 _ => panic!("Failed to create datalink channel."),
    //                             };
    //                             ppp0_tx.send_to(new_packet.packet(), None);
    //                         }
    //                     }
    //                 }
    //             }
    //             Err(e) => {
    //                 panic!("An error occurred while reading: {}", e);
    //             }
    //         }
    //     }
    // });

    // 创建一个新的线程来处理从 ppp0 到 en0 的数据包转发

    let en0: NetworkInterface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == "en0")
        .unwrap();

    let ppp0: NetworkInterface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == "ppp0")
        .unwrap();

    let (mut en0_tx, mut _en0_rx) = match datalink::channel(&en0, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to create datalink channel."),
    };

    let (mut _ppp0_tx, mut ppp0_rx) = match datalink::channel(&ppp0, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to create datalink channel."),
    };

    let en0_mac = en0.mac.unwrap();
    debug!("en0 mac address {:?}", en0.mac);

    let ipv4_mcast_addr = MacAddr(0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb);
    let en0_ip = Ipv4Addr::new(192, 168, 1, 7);
    let ppp0_ip = Ipv4Addr::new(172, 16, 3, 210);



    let recv_src_ip = en0_ip;
    let send_src_ip = ppp0_ip;
    let en0_to_ppp0 = thread::spawn(move || {
        en0_to_pp0(&mut _en0_rx, &mut _ppp0_tx, recv_src_ip, send_src_ip);
    });

    let dst_ip = Ipv4Addr::new(192, 168, 1, 7);
    let ppp0_to_en0 = thread::spawn(move || {
        ppp0_to_en0(&mut ppp0_rx, &mut en0_tx, en0_mac, en0_mac, dst_ip);
    });
    

    // let ppp0_to_en0 = thread::spawn(move || {

    //     let mut ether_buf = vec![0u8; 1700];
    //     let mut ethernet_frame = MutableEthernetPacket::new(&mut ether_buf[..]).unwrap();
    //     ethernet_frame.set_source(en0_mac);
    //     ethernet_frame.set_destination(ipv4_mcast_addr);
    //     ethernet_frame.set_ethertype(EtherTypes::Ipv4);

    //     loop {
    //         match ppp0_rx.next() {
    //             Ok(frame) => {
    //                 // tracing::debug!("== recv from ppp0 bytes {}", frame.len());
    //                 // let eth_packet = EthernetPacket::new(frame).unwrap();
    //                 // tracing::debug!("  ether packet: payload {}", eth_packet.payload().len());

    //                 // let packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
    //                 // let packet = Ipv4Packet::new(&frame[14..]).unwrap();
    //                 let packet = Ipv4Packet::new(&frame[4..]).unwrap();
    //                 // tracing::debug!("  ipv4 packet: protocol {}", packet.get_next_level_protocol());
                    
    //                 if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
    //                     // tracing::debug!("  it is protocol udp");
    //                     if let Some(udp) = UdpPacket::new(packet.payload()) {
    //                         // tracing::debug!("  udp packet: {}, {}", packet.get_destination(), udp.get_destination());
    //                         // 检查是否为组播地址
    //                         if packet.get_destination() == Ipv4Addr::new(224, 0, 0, 251) && udp.get_destination() == 5353 {
    //                             // tracing::debug!("  it is mdns packet");
    //                             // 发送到 en0
    //                             // let (mut en0_tx, _) = match datalink::channel(&en0, Default::default()) {
    //                             //     Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
    //                             //     _ => panic!("Failed to create datalink channel."),
    //                             // };
    //                             // en0_tx.send_to(packet.packet(), None);

    //                             let payload = packet.packet();
    //                             ethernet_frame.set_payload(packet.packet());
    //                             let eframe = ethernet_frame.to_immutable();
    //                             let ether_packet = &eframe.packet()[..eframe.packet_size() + payload.len()];
    //                             tracing::debug!("en0: sent ether packet bytes {}", ether_packet.len());
    //                             en0_tx.send_to(ether_packet, None).unwrap().unwrap();
    //                         }
    //                     }
    //                 }
    //             }
    //             Err(e) => {
    //                 panic!("An error occurred while reading: {}", e);
    //             }
    //         }
    //     }
    // });

    // 等待两个线程结束
    en0_to_ppp0.join().unwrap();
    ppp0_to_en0.join().unwrap();
}

fn ppp0_to_en0(
    ppp0_rx: &mut Box<dyn DataLinkReceiver>, 
    en0_tx: &mut Box<dyn DataLinkSender>,
    send_src_mac: MacAddr,
    send_dst_mac: MacAddr,
    send_dst_ip: Ipv4Addr,
    // dst_port: u16,
) {
    let mut ether_buf = vec![0u8; 1700];
    let mut ethernet_frame = MutableEthernetPacket::new(&mut ether_buf[..]).unwrap();
    ethernet_frame.set_source(send_src_mac);
    ethernet_frame.set_destination(send_dst_mac);
    ethernet_frame.set_ethertype(EtherTypes::Ipv4);

    // let mut ipv4_buf = vec![0u8; 1700];
    // let mut ipv4_packet_mut = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();

    loop {
        match ppp0_rx.next() {
            Ok(frame) => {
                let packet = Ipv4Packet::new(&frame[4..]).unwrap();
                // tracing::debug!("  ipv4 packet: protocol {}", packet.get_next_level_protocol());
                
                if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    // tracing::debug!("  it is protocol udp");
                    if let Some(udp) = UdpPacket::new(packet.payload()) {
                        // tracing::debug!("  udp packet: {}, {}", packet.get_destination(), udp.get_destination());
                        // 检查是否为组播地址
                        if packet.get_destination() == Ipv4Addr::new(224, 0, 0, 251) && udp.get_destination() == 5353 {
                            // tracing::debug!("  it is mdns packet");
                            // 发送到 en0


                            // ipv4_packet_mut.clone_from(&packet);
                            // ipv4_packet_mut.set_destination(send_dst_ip);
                            // let ipv4_data_len = packet.packet().len();
                            // let ipv4_data = &ipv4_packet_mut.packet()[..ipv4_data_len];

                            let ipv4_data = packet.packet();

                            ethernet_frame.set_payload(ipv4_data);
                            let eframe = ethernet_frame.to_immutable();
                            let ether_packet = &eframe.packet()[..eframe.packet_size() + ipv4_data.len()];
                            

                            tracing::debug!("en0: sent ether packet bytes {}", ether_packet.len());
                            en0_tx.send_to(ether_packet, None).unwrap().unwrap();
                        }
                    }
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn en0_to_pp0(
    en0_rx: &mut Box<dyn DataLinkReceiver>, 
    ppp0_tx: &mut Box<dyn DataLinkSender>,
    // send_src_mac: MacAddr,
    // send_dst_mac: MacAddr,
    recv_src_ip: Ipv4Addr,
    send_src_ip: Ipv4Addr,
    // dst_port: u16,
) {
    let mut ether_buf = vec![0u8; 1700];
    // let mut ethernet_frame = MutableEthernetPacket::new(&mut ether_buf[..]).unwrap();
    // ethernet_frame.set_source(send_src_mac);
    // ethernet_frame.set_destination(send_dst_mac);
    // ethernet_frame.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_buf = vec![0u8; 1700];
    let mut ipv4_packet_mut = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();

    loop {
        match en0_rx.next() {
            Ok(frame) => {
                let ether_frame = EthernetPacket::new(&frame[..]).unwrap();
                if ether_frame.get_ethertype() == EtherTypes::Ipv4 {
                    let packet = Ipv4Packet::new(ether_frame.payload()).unwrap();
                    // tracing::debug!("  ipv4 packet: protocol {}", packet.get_next_level_protocol());
                    
                    if packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp && packet.get_source() == recv_src_ip {
                        // tracing::debug!("  it is protocol udp");
                        if let Some(udp) = UdpPacket::new(packet.payload()) {
                            // tracing::debug!("  udp packet: {}, {}", packet.get_destination(), udp.get_destination());
                            // 检查是否为组播地址
                            if packet.get_destination() == Ipv4Addr::new(224, 0, 0, 251) && udp.get_destination() == 5353 {
                                // tracing::debug!("  it is mdns packet");
                                // 发送到 en0
    
                                // let mut new_packet = MutableIpv4Packet::owned(packet.packet().to_owned()).unwrap();
    
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

                                if ether_packet.len() <= 1280 {
                                    tracing::debug!("ppp0: sent ether packet bytes {} (ipv4_data_len {})", ether_packet.len(), ipv4_data_len);
                                    ppp0_tx.send_to(ether_packet, None).unwrap().unwrap();
                                } else {
                                    tracing::debug!("ppp0: drop ether packet bytes {} (ipv4_data_len {})", ether_packet.len(), ipv4_data_len);
                                }
                            }
                        }
                    }
                }
                
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

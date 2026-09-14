//
// Copyright (c) 2024-2026 PADL Software Pty Ltd
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#if os(Linux)

@preconcurrency
import AsyncExtensions
import CLinuxSockAddr
import Glibc
import IEEE802
import IORing
import IORingUtils
import SocketAddress
import struct SystemPackage.Errno

// Ethernet header (destination, source, EtherType) plus room for one 802.1Q tag.
private let _ethernetHeaderLength = 14
private let _vlanTagLength = 4

/// Classic-BPF (SO_ATTACH_FILTER) accepting only ingress frames whose EtherType is in
/// `etherTypes` and dropping our own TX (PACKET_OUTGOING); lets an ETH_P_ALL socket narrow
/// in-kernel.
public func makeEtherTypeFilter(etherTypes: [UInt16]) -> [SocketFilter] {
  // opcodes: BPF_LD|B|ABS=0x30, BPF_LD|H|ABS=0x28, BPF_JMP|JEQ|K=0x15, BPF_RET|K=0x06
  let n = etherTypes.count
  var program: [SocketFilter] = [
    SocketFilter(
      code: 0x30,
      jt: 0,
      jf: 0,
      k: 0xFFFF_F000 &+ 4
    ), // A = skb->pkt_type (SKF_AD_PKTTYPE)
    SocketFilter(code: 0x15, jt: UInt8(n + 1), jf: 0, k: UInt32(PACKET_OUTGOING)), // drop our TX
    SocketFilter(code: 0x28, jt: 0, jf: 0, k: 12), // A = EtherType (offset 12)
  ]
  for (i, etherType) in etherTypes.enumerated() {
    // match -> jump past the remaining tests to the accept; else fall through
    program.append(SocketFilter(code: 0x15, jt: UInt8(n - i), jf: 0, k: UInt32(etherType)))
  }
  program.append(SocketFilter(code: 0x06, jt: 0, jf: 0, k: 0)) // drop
  program.append(SocketFilter(code: 0x06, jt: 0, jf: 0, k: 0x0004_0000)) // accept
  return program
}

public func makeLinkLayerAddress(
  macAddress: EUI48? = nil,
  etherType: UInt16 = UInt16(ETH_P_ALL),
  packetType: UInt8 = 0,
  index: Int? = nil
) -> sockaddr_ll {
  var sll = sockaddr_ll()
  sll.sll_family = UInt16(AF_PACKET)
  sll.sll_protocol = etherType.bigEndian
  sll.sll_ifindex = CInt(index ?? 0)
  sll.sll_pkttype = packetType
  if let macAddress {
    sll.sll_halen = UInt8(ETH_ALEN)
    sll.sll_addr.0 = macAddress[0]
    sll.sll_addr.1 = macAddress[1]
    sll.sll_addr.2 = macAddress[2]
    sll.sll_addr.3 = macAddress[3]
    sll.sll_addr.4 = macAddress[4]
    sll.sll_addr.5 = macAddress[5]
  }
  return sll
}

/// A snapshot of an Ethernet interface's identity, read with the SIOCGIF* ioctls.
public struct EthernetInterface: Sendable, CustomStringConvertible {
  public let name: String
  public let index: Int
  public let macAddress: EUI48
  public let mtu: Int

  public init(name: String) throws {
    guard name.utf8.count < Int(IFNAMSIZ) else { throw Errno.invalidArgument }

    let index = if_nametoindex(name)
    guard index != 0 else { throw Errno(rawValue: ENODEV) }

    let fd = socket(CInt(AF_PACKET), Int32(SOCK_DGRAM.rawValue), 0)
    guard fd >= 0 else { throw Errno(rawValue: errno) }
    defer { close(fd) }

    var ifr = ifreq()
    withUnsafeMutableBytes(of: &ifr.ifr_ifrn.ifrn_name) { buffer in
      for (i, byte) in name.utf8.enumerated() {
        buffer[i] = byte
      }
    }

    guard ioctl(fd, UInt(SIOCGIFHWADDR), &ifr) == 0 else { throw Errno(rawValue: errno) }
    let hwaddr = withUnsafeBytes(of: &ifr.ifr_ifru.ifru_hwaddr.sa_data) { Array($0.prefix(6)) }

    guard ioctl(fd, UInt(SIOCGIFMTU), &ifr) == 0 else { throw Errno(rawValue: errno) }

    self.name = name
    self.index = Int(index)
    macAddress = [hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]]
    mtu = Int(ifr.ifr_ifru.ifru_mtu)
  }

  public var description: String {
    "EthernetInterface(name: \(name), index: \(index), macAddress: \(_macAddressToString(macAddress)), mtu: \(mtu))"
  }
}

/// Sends and receives raw Ethernet frames on one interface using AF_PACKET sockets and io_uring.
public final class RawEthernetPort: Sendable, CustomStringConvertible {
  public let interface: EthernetInterface

  private let _ring: IORing
  private let _txSocket: Socket

  public init(interface: EthernetInterface, ring: IORing = .shared) throws {
    self.interface = interface
    _ring = ring
    _txSocket = try Socket(
      ring: ring,
      domain: sa_family_t(AF_PACKET),
      type: SOCK_RAW,
      protocol: 0
    )
  }

  public convenience init(name: String, ring: IORing = .shared) throws {
    try self.init(interface: EthernetInterface(name: name), ring: ring)
  }

  public var description: String {
    "RawEthernetPort(\(interface))"
  }

  /// Opens a receive socket that only sees frames with one of `etherTypes`, and joins each of
  /// `groupAddresses` so that the device's multicast filter (and any hardware-offloaded bridge
  /// MDB) forwards them, without resorting to promiscuous mode.
  public func receivePackets(
    etherTypes: [UInt16],
    groupAddresses: [EUI48]
  ) async throws -> AnyAsyncSequence<IEEE802Packet> {
    // open with protocol 0 and attach the BPF before bind() enables capture, so no unfiltered
    // frames leak in the socket()->attachFilter() window
    let rxSocket = try Socket(
      ring: _ring,
      domain: sa_family_t(AF_PACKET),
      type: SOCK_RAW,
      protocol: 0
    )
    try rxSocket.attachFilter(makeEtherTypeFilter(etherTypes: etherTypes))
    try rxSocket.bind(to: makeLinkLayerAddress(
      macAddress: interface.macAddress,
      etherType: UInt16(ETH_P_ALL),
      packetType: UInt8(PACKET_MULTICAST),
      index: interface.index
    ))
    for groupAddress in groupAddresses {
      try rxSocket.addMulticastMembership(for: makeLinkLayerAddress(
        macAddress: groupAddress,
        index: interface.index
      ))
    }

    // io_uring requires the buffer size to be aligned to its recvmsg header
    let alignment = MemoryLayout<UInt64>.alignment
    let frameSize = interface.mtu + _ethernetHeaderLength + _vlanTagLength
    let count = (frameSize + alignment - 1) / alignment * alignment

    return try await rxSocket.receiveMessages(count: count, capacity: 32)
      .compactMap { message in
        // keep the socket, and hence its group memberships, alive for the sequence's lifetime
        _ = rxSocket
        return try? message.buffer.withParserSpan { input in
          try IEEE802Packet(parsing: &input)
        }
      }.eraseToAnyAsyncSequence()
  }

  public func send(_ packet: IEEE802Packet) async throws {
    var address = makeLinkLayerAddress(
      macAddress: packet.destMacAddress,
      etherType: packet.etherType,
      index: interface.index
    )
    let name = withUnsafeBytes(of: &address) { Array($0) }
    try await _txSocket.sendMessage(Message(name: name, buffer: packet.serialized()))
  }
}

#endif

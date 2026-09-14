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
private let _ethernetHeaderLength = Int(ETH_HLEN)
private let _vlanTagLength = 4

// the EtherType follows the destination and source addresses; the first payload octet (for AVTP, the
// subtype) follows the EtherType
private let _etherTypeOffset = UInt32(2 * ETH_ALEN)
private let _subtypeOffset = UInt32(ETH_HLEN)

// classic-BPF instructions (linux/bpf_common.h) and ancillary loads (linux/filter.h)
private let _bpfLoadByte = UInt16(BPF_LD | BPF_B | BPF_ABS)
private let _bpfLoadHalfWord = UInt16(BPF_LD | BPF_H | BPF_ABS)
private let _bpfJumpIfEqual = UInt16(BPF_JMP | BPF_JEQ | BPF_K)
private let _bpfJumpIfGreater = UInt16(BPF_JMP | BPF_JGT | BPF_K)
private let _bpfJumpIfGreaterOrEqual = UInt16(BPF_JMP | BPF_JGE | BPF_K)
private let _bpfReturn = UInt16(BPF_RET | BPF_K)
private let _bpfPacketTypeOffset = UInt32(bitPattern: Int32(SKF_AD_OFF + SKF_AD_PKTTYPE))
private let _bpfVLANTagPresentOffset = UInt32(bitPattern: Int32(SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT))
private let _bpfVLANTagAbsent: UInt32 = 0

// a filter returns how many bytes of the frame to keep: none drops it, and anything at least as long
// as the longest frame keeps it whole
private let _bpfDropFrame: UInt32 = 0
private let _bpfAcceptFrame: UInt32 = 0x0004_0000

/// Assembles a classic-BPF program whose jumps name labels. Classic BPF only jumps forward, by at
/// most `UInt8.max` instructions, so each label must be placed after, and near, the jumps to it.
private struct _SocketFilterAssembler {
  typealias Label = Int

  private var _instructions = [(code: UInt16, k: UInt32, jt: Label?, jf: Label?)]()
  private var _labelPositions = [Label: Int]()
  private var _labelCount = 0

  mutating func makeLabel() -> Label {
    defer { _labelCount += 1 }
    return _labelCount
  }

  mutating func place(_ label: Label) {
    _labelPositions[label] = _instructions.count
  }

  mutating func load(_ code: UInt16, offset: UInt32) {
    _instructions.append((code: code, k: offset, jt: nil, jf: nil))
  }

  /// Jumps to `ifTrue` or `ifFalse` on the comparison; a nil label falls through.
  mutating func jump(_ code: UInt16, _ k: UInt32, ifTrue: Label? = nil, ifFalse: Label? = nil) {
    _instructions.append((code: code, k: k, jt: ifTrue, jf: ifFalse))
  }

  mutating func `return`(_ length: UInt32) {
    _instructions.append((code: _bpfReturn, k: length, jt: nil, jf: nil))
  }

  func assembled() -> [SocketFilter] {
    _instructions.enumerated().map { index, instruction in
      func offset(to label: Label?) -> UInt8 {
        guard let label else { return 0 }
        guard let position = _labelPositions[label] else {
          preconditionFailure("socket filter jumps to an unplaced label")
        }
        let offset = position - (index + 1)
        precondition(offset >= 0 && offset <= Int(UInt8.max), "socket filter jump out of range")
        return UInt8(offset)
      }
      return SocketFilter(
        code: instruction.code,
        jt: offset(to: instruction.jt),
        jf: offset(to: instruction.jf),
        k: instruction.k
      )
    }
  }
}

/// A classic-BPF program (SO_ATTACH_FILTER) accepting only frames whose EtherType is one of
/// `etherTypes`, letting an ETH_P_ALL packet socket narrow what the kernel queues to it.
///
/// - Parameters:
///   - etherTypes: the EtherTypes to accept.
///   - subtypes: for any EtherType listed here, the values of the first octet after the EtherType
///     to accept (for AVTP, the subtype: ATDECC control and AVTP stream data share an EtherType);
///     frames with any other value, or with no payload, are dropped. An EtherType absent here
///     accepts any payload.
///   - dropsVLANTagged: drop frames that arrived with an 802.1Q tag. The kernel removes the tag
///     before a packet socket sees a received frame, so the EtherType can't reveal it.
///   - dropsOutgoing: drop the frames this host transmits (PACKET_OUTGOING). A filter can't tell
///     which socket sent a frame, so this hides those of every other socket and process too. The
///     kernel never loops a frame back to the packet socket that sent it, so a socket that both
///     sends and receives can pass false to see other senders on this host without seeing itself.
public func makeEtherTypeFilter(
  etherTypes: [UInt16],
  subtypes: [UInt16: [ClosedRange<UInt8>]] = [:],
  dropsVLANTagged: Bool = false,
  dropsOutgoing: Bool = true
) -> [SocketFilter] {
  var assembler = _SocketFilterAssembler()
  let accept = assembler.makeLabel()
  let drop = assembler.makeLabel()

  if dropsOutgoing {
    assembler.load(_bpfLoadByte, offset: _bpfPacketTypeOffset)
    assembler.jump(_bpfJumpIfEqual, UInt32(PACKET_OUTGOING), ifTrue: drop)
  }
  if dropsVLANTagged {
    assembler.load(_bpfLoadByte, offset: _bpfVLANTagPresentOffset)
    assembler.jump(_bpfJumpIfEqual, _bpfVLANTagAbsent, ifFalse: drop)
  }

  // an EtherType without subtypes accepts at once; one with them checks its subtype further on
  assembler.load(_bpfLoadHalfWord, offset: _etherTypeOffset)
  let subtypeChecks = etherTypes.map { etherType in
    (etherType, subtypes[etherType].map { ($0, assembler.makeLabel()) })
  }
  for (etherType, subtypeCheck) in subtypeChecks {
    assembler.jump(_bpfJumpIfEqual, UInt32(etherType), ifTrue: subtypeCheck?.1 ?? accept)
  }
  assembler.place(drop)
  assembler.return(_bpfDropFrame)

  for case let (_, (ranges, label)?) in subtypeChecks {
    assembler.place(label)
    // a frame too short to have a subtype ends the program, dropping it
    assembler.load(_bpfLoadByte, offset: _subtypeOffset)
    for range in ranges {
      let nextRange = assembler.makeLabel()
      assembler.jump(_bpfJumpIfGreaterOrEqual, UInt32(range.lowerBound), ifFalse: nextRange)
      assembler.jump(_bpfJumpIfGreater, UInt32(range.upperBound), ifTrue: nextRange, ifFalse: accept)
      assembler.place(nextRange)
    }
    assembler.return(_bpfDropFrame)
  }

  assembler.place(accept)
  assembler.return(_bpfAcceptFrame)
  return assembler.assembled()
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
  /// MDB) forwards them, without resorting to promiscuous mode. `subtypes` further restricts an
  /// EtherType to frames whose first payload octet is in one of its ranges; see
  /// `makeEtherTypeFilter(etherTypes:subtypes:dropsVLANTagged:dropsOutgoing:)`.
  public func receivePackets(
    etherTypes: [UInt16],
    groupAddresses: [EUI48],
    subtypes: [UInt16: [ClosedRange<UInt8>]] = [:]
  ) async throws -> AnyAsyncSequence<IEEE802Packet> {
    // open with protocol 0 and attach the BPF before bind() enables capture, so no unfiltered
    // frames leak in the socket()->attachFilter() window
    let rxSocket = try Socket(
      ring: _ring,
      domain: sa_family_t(AF_PACKET),
      type: SOCK_RAW,
      protocol: 0
    )
    try rxSocket.attachFilter(makeEtherTypeFilter(etherTypes: etherTypes, subtypes: subtypes))
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

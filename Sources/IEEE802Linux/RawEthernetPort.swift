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
import Synchronization
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

// io_uring buffers provided to receive frames into
private let _receiveBufferCount = 32
// frames queued for a receiver that isn't keeping up, beyond which newer frames are dropped
private let _receiveQueueLength = 256

/// Sends and receives raw Ethernet frames on one interface using AF_PACKET sockets and io_uring.
///
/// A port sends and receives on one packet socket. The kernel never loops a frame back to the
/// packet socket that sent it (dev_queue_xmit_nit() skips it), so a port receives the frames other
/// sockets and processes on this host send on the interface, which the kernel marks
/// PACKET_OUTGOING, but not its own. A socket filter can't tell senders apart, so this relies on
/// the socket being shared: its receivers are demultiplexed in userspace.
public final class RawEthernetPort: Sendable, CustomStringConvertible {
  public let interface: EthernetInterface

  private let _socket: _PacketSocket

  public init(interface: EthernetInterface, ring: IORing = .shared) throws {
    self.interface = interface
    _socket = try _PacketSocket(interface: interface, ring: ring)
  }

  public convenience init(name: String, ring: IORing = .shared) throws {
    try self.init(interface: EthernetInterface(name: name), ring: ring)
  }

  deinit {
    _socket.portReleased()
  }

  public var description: String {
    "RawEthernetPort(\(interface))"
  }

  /// Receives the frames with one of `etherTypes`, joining each of `groupAddresses` so that the
  /// device's multicast filter (and any hardware-offloaded bridge MDB) forwards them, without
  /// resorting to promiscuous mode. `subtypes` further restricts an EtherType to frames whose first
  /// payload octet is in one of its ranges; see
  /// `makeEtherTypeFilter(etherTypes:subtypes:dropsVLANTagged:dropsOutgoing:)`.
  ///
  /// Frames sent by other sockets on this host are received, but not those this port sends. The
  /// groups are left when the sequence ends or its consumer stops iterating it. An error on the
  /// socket, such as the interface going down, ends every sequence of this port with that error.
  public func receivePackets(
    etherTypes: [UInt16],
    groupAddresses: [EUI48],
    subtypes: [UInt16: [ClosedRange<UInt8>]] = [:]
  ) async throws -> AnyAsyncSequence<IEEE802Packet> {
    try _socket.receive(etherTypes: etherTypes, groupAddresses: groupAddresses, subtypes: subtypes)
      .eraseToAnyAsyncSequence()
  }

  public func send(_ packet: IEEE802Packet) async throws {
    var address = makeLinkLayerAddress(
      macAddress: packet.destMacAddress,
      etherType: packet.etherType,
      index: interface.index
    )
    let name = withUnsafeBytes(of: &address) { Array($0) }
    let buffer = try packet.serialized()
    do {
      try await _socket.socket.sendMessage(Message(name: name, buffer: buffer))
    } catch let error as Errno where error == .networkDown {
      // a packet socket bound to an interface keeps ENETDOWN pending from when the interface last
      // went down, and the next send reports it even if the interface has come back up; reporting
      // clears it, so retry once, which fails again only if the interface is still down
      try await _socket.socket.sendMessage(Message(name: name, buffer: buffer))
    }
  }
}

/// One `receivePackets()` sequence: the frames it wants, and where they go.
private struct _Receiver: Sendable {
  let etherTypes: [UInt16]
  let subtypes: [UInt16: [ClosedRange<UInt8>]]
  let groupAddresses: [EUI48]
  let continuation: AsyncThrowingStream<IEEE802Packet, Error>.Continuation

  func matches(_ packet: IEEE802Packet) -> Bool {
    guard etherTypes.contains(packet.etherType) else { return false }
    guard let ranges = subtypes[packet.etherType] else { return true }
    guard let subtype = packet.payload.first else { return false }
    return ranges.contains { $0.contains(subtype) }
  }
}

private struct _ReceiveState: Sendable {
  var receivers = [UInt64: _Receiver]()
  var nextReceiverID: UInt64 = 0
  var isBound = false
  var isPortReleased = false
  var receiveTask: Task<(), Never>?
}

/// A port's packet socket, and the receivers sharing its frames. It outlives the port while any
/// receiver remains.
private final class _PacketSocket: Sendable {
  let socket: Socket

  private let _interface: EthernetInterface
  private let _state = Mutex(_ReceiveState())

  init(interface: EthernetInterface, ring: IORing) throws {
    _interface = interface
    // with protocol 0 the socket receives nothing until bind(), by when a filter is attached, so
    // no unfiltered frame leaks in; a port that only sends never binds it
    socket = try Socket(
      ring: ring,
      domain: sa_family_t(AF_PACKET),
      type: SOCK_RAW,
      protocol: 0
    )
  }

  func receive(
    etherTypes: [UInt16],
    groupAddresses: [EUI48],
    subtypes: [UInt16: [ClosedRange<UInt8>]]
  ) throws -> AsyncThrowingStream<IEEE802Packet, Error> {
    let (stream, continuation) = AsyncThrowingStream.makeStream(
      of: IEEE802Packet.self,
      throwing: Error.self,
      bufferingPolicy: .bufferingOldest(_receiveQueueLength)
    )
    let id = _state.withLock { state in
      defer { state.nextReceiverID += 1 }
      return state.nextReceiverID
    }
    // set before the receiver is added, so that however its sequence ends, it's removed
    continuation.onTermination = { [weak self] _ in
      self?._removeReceiver(id: id)
    }

    try _state.withLock { state in
      state.receivers[id] = _Receiver(
        etherTypes: etherTypes,
        subtypes: subtypes,
        groupAddresses: groupAddresses,
        continuation: continuation
      )
      var joinedGroupAddresses = [EUI48]()
      do {
        try _attachFilter(for: state.receivers)
        if !state.isBound {
          try socket.bind(to: makeLinkLayerAddress(
            macAddress: _interface.macAddress,
            etherType: UInt16(ETH_P_ALL),
            packetType: UInt8(PACKET_MULTICAST),
            index: _interface.index
          ))
          state.isBound = true
        }
        for groupAddress in groupAddresses {
          try socket.addMulticastMembership(for: makeLinkLayerAddress(
            macAddress: groupAddress,
            index: _interface.index
          ))
          joinedGroupAddresses.append(groupAddress)
        }
      } catch {
        state.receivers[id] = nil
        _leave(joinedGroupAddresses)
        try? _attachFilter(for: state.receivers)
        throw error
      }

      if state.receiveTask == nil {
        // an error left pending by an earlier receive task reports a past event, such as the
        // interface having gone down, and would end this receiver at once
        _ = try? socket.getIntegerOption(option: SO_ERROR)
        state.receiveTask = Task { await self._receive() }
      }
    }
    return stream
  }

  func portReleased() {
    _state.withLock { state in
      state.isPortReleased = true
      if state.receivers.isEmpty { _stopReceiving(&state) }
    }
  }

  private func _removeReceiver(id: UInt64) {
    _state.withLock { state in
      guard let receiver = state.receivers.removeValue(forKey: id) else { return }
      // the kernel counts a socket's joins of a group, so a group another receiver joined stays
      // joined. Failing to leave or narrow (because the interface has gone, say) leaves the socket
      // admitting more than it need, which matching each frame to its receivers still corrects.
      _leave(receiver.groupAddresses)
      try? _attachFilter(for: state.receivers)
      if state.isPortReleased, state.receivers.isEmpty { _stopReceiving(&state) }
    }
  }

  private func _stopReceiving(_ state: inout _ReceiveState) {
    state.receiveTask?.cancel()
    state.receiveTask = nil
  }

  private func _leave(_ groupAddresses: [EUI48]) {
    for groupAddress in groupAddresses {
      try? socket.dropMulticastMembership(for: makeLinkLayerAddress(
        macAddress: groupAddress,
        index: _interface.index
      ))
    }
  }

  /// Attaches a filter admitting the frames any of `receivers` wants (with none, nothing). The
  /// socket sends as well as receives, so the kernel already keeps its own frames from it, and
  /// outgoing frames are those of other senders.
  private func _attachFilter(for receivers: [UInt64: _Receiver]) throws {
    var etherTypes = [UInt16]()
    var subtypes = [UInt16: [ClosedRange<UInt8>]]()
    var etherTypesWithAnySubtype = Set<UInt16>()
    for receiver in receivers.values {
      for etherType in receiver.etherTypes {
        if !etherTypes.contains(etherType) { etherTypes.append(etherType) }
        if let ranges = receiver.subtypes[etherType] {
          if !etherTypesWithAnySubtype.contains(etherType) {
            subtypes[etherType, default: []] += ranges
          }
        } else {
          etherTypesWithAnySubtype.insert(etherType)
          subtypes[etherType] = nil
        }
      }
    }
    try socket.attachFilter(makeEtherTypeFilter(
      etherTypes: etherTypes,
      subtypes: subtypes,
      dropsOutgoing: false
    ))
  }

  private func _receive() async {
    // io_uring requires the buffer size to be aligned to its recvmsg header
    let alignment = MemoryLayout<UInt64>.alignment
    let frameSize = _interface.mtu + _ethernetHeaderLength + _vlanTagLength
    let count = (frameSize + alignment - 1) / alignment * alignment

    var receiveError: (any Error)?
    do {
      let messages = try await socket.receiveMessages(count: count, capacity: _receiveBufferCount)
      for try await message in messages {
        guard let packet = try? message.buffer.withParserSpan({ input in
          try IEEE802Packet(parsing: &input)
        }) else { continue }
        let continuations = _state.withLock { state in
          state.receivers.values.filter { $0.matches(packet) }.map(\.continuation)
        }
        for continuation in continuations {
          continuation.yield(packet)
        }
      }
    } catch {
      receiveError = error
    }

    // end the receivers as each would have ended on a socket of its own; a later receiver starts a
    // new receive task
    let receivers = _state.withLock { state in
      state.receiveTask = nil
      return Array(state.receivers.values)
    }
    for receiver in receivers {
      receiver.continuation.finish(throwing: receiveError)
    }
  }
}

#endif

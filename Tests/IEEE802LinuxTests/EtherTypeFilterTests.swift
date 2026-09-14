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

import CLinuxSockAddr
import Glibc
import IEEE802
import IEEE802Linux
import IORingUtils
import struct SystemPackage.Errno
import XCTest

private let _avtpEtherType: UInt16 = 0x22F0
private let _mvrpEtherType: UInt16 = 0x88F5
private let _ipv4EtherType = UInt16(ETH_P_IP)

// AVTP subtypes (IEEE Std 1722-2016)
private let _iec61883Subtype: UInt8 = 0x00
private let _aafSubtype: UInt8 = 0x02
private let _crfSubtype: UInt8 = 0x04
private let _adpSubtype: UInt8 = 0xFA
private let _aecpSubtype: UInt8 = 0xFB
private let _acmpSubtype: UInt8 = 0xFC
private let _reservedSubtype: UInt8 = 0xFD
private let _maapSubtype: UInt8 = 0xFE
private let _efControlSubtype: UInt8 = 0xFF
private let _atdeccSubtypes = _adpSubtype..._acmpSubtype

private let _atdeccGroupAddress: EUI48 = [0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00]
private let _sourceAddress: EUI48 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
private let _maximumFrameLength = 1522

// classic-BPF decoding (linux/bpf_common.h), for the interpreter below
private let _bpfLoadByte = UInt16(BPF_LD | BPF_B | BPF_ABS)
private let _bpfLoadHalfWord = UInt16(BPF_LD | BPF_H | BPF_ABS)
private let _bpfJumpIfEqual = UInt16(BPF_JMP | BPF_JEQ | BPF_K)
private let _bpfJumpIfGreater = UInt16(BPF_JMP | BPF_JGT | BPF_K)
private let _bpfJumpIfGreaterOrEqual = UInt16(BPF_JMP | BPF_JGE | BPF_K)
private let _bpfReturn = UInt16(BPF_RET | BPF_K)
private let _bpfPacketTypeOffset = Int32(SKF_AD_OFF + SKF_AD_PKTTYPE)
private let _bpfVLANTagPresentOffset = Int32(SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT)
private let _bitsPerByte = 8

private struct _Frame {
  let name: String
  let bytes: [UInt8]

  init(_ name: String, etherType: UInt16, payload: [UInt8]) throws {
    self.name = name
    bytes = try IEEE802Packet(
      destMacAddress: _atdeccGroupAddress,
      tci: nil,
      sourceMacAddress: _sourceAddress,
      etherType: etherType,
      payload: payload
    ).serialized()
  }

  init(_ name: String, bytes: [UInt8]) {
    self.name = name
    self.bytes = bytes
  }
}

private func _frames() throws -> [_Frame] {
  let header = try _Frame("header", etherType: _avtpEtherType, payload: []).bytes
  return try [
    _Frame("ADP", etherType: _avtpEtherType, payload: [_adpSubtype, 0x00, 0x00, 0x38]),
    _Frame("AECP", etherType: _avtpEtherType, payload: [_aecpSubtype, 0x00, 0x00, 0x14]),
    _Frame("ACMP", etherType: _avtpEtherType, payload: [_acmpSubtype, 0x00, 0x00, 0x2C]),
    _Frame("reserved", etherType: _avtpEtherType, payload: [_reservedSubtype, 0x00]),
    _Frame("MAAP", etherType: _avtpEtherType, payload: [_maapSubtype, 0x01, 0x00, 0x10]),
    _Frame("EF_CONTROL", etherType: _avtpEtherType, payload: [_efControlSubtype, 0x00]),
    _Frame("AAF", etherType: _avtpEtherType, payload: [_aafSubtype, 0x81, 0x00, 0x00]),
    _Frame("CRF", etherType: _avtpEtherType, payload: [_crfSubtype, 0x80, 0x00, 0x00]),
    _Frame("IEC 61883", etherType: _avtpEtherType, payload: [_iec61883Subtype, 0x81, 0x00]),
    _Frame("MVRP", etherType: _mvrpEtherType, payload: [0x00, 0x01, 0x02]),
    _Frame("IPv4", etherType: _ipv4EtherType, payload: [0x45, 0x00, 0x00, 0x14]),
    // an AVTP EtherType but no payload, so no subtype
    _Frame("header only", bytes: header),
    // too short to have an EtherType at all
    _Frame("truncated", bytes: Array(header.prefix(Int(2 * ETH_ALEN) + 1))),
  ]
}

/// Runs frames through `program` in the kernel, attached to one end of an AF_UNIX datagram
/// socketpair (which needs no privilege), and returns the names of those it delivers. The
/// kernel's checker also rejects a malformed program here. A unix socket's frames are never
/// outgoing or VLAN-tagged, so the ancillary loads always read PACKET_HOST and no tag.
private func _namesDeliveredByKernel(
  _ program: [SocketFilter],
  frames: [_Frame]
) throws -> [String] {
  var sockets: [CInt] = [-1, -1]
  guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &sockets) == 0 else {
    throw Errno(rawValue: errno)
  }
  defer {
    close(sockets[0])
    close(sockets[1])
  }

  var instructions = program.map { sock_filter(code: $0.code, jt: $0.jt, jf: $0.jf, k: $0.k) }
  try instructions.withUnsafeMutableBufferPointer { buffer in
    var fprog = sock_fprog(len: UInt16(buffer.count), filter: buffer.baseAddress)
    guard setsockopt(
      sockets[1],
      SOL_SOCKET,
      SO_ATTACH_FILTER,
      &fprog,
      socklen_t(MemoryLayout<sock_fprog>.size)
    ) == 0 else {
      throw Errno(rawValue: errno)
    }
  }

  // a datagram socket keeps the frames in order, and their distinct bytes identify each one
  XCTAssertEqual(Set(frames.map(\.bytes)).count, frames.count)
  for frame in frames {
    // the sender never learns of a filtered frame: a unix socket drops it silently
    guard send(sockets[0], frame.bytes, frame.bytes.count, 0) == frame.bytes.count else {
      throw Errno(rawValue: errno)
    }
  }

  var delivered = [String]()
  var buffer = [UInt8](repeating: 0, count: _maximumFrameLength)
  while true {
    let count = recv(sockets[1], &buffer, buffer.count, CInt(MSG_DONTWAIT))
    guard count >= 0 else {
      guard errno == EAGAIN else { throw Errno(rawValue: errno) }
      break
    }
    let bytes = Array(buffer[0..<count])
    guard let frame = frames.first(where: { $0.bytes == bytes }) else {
      XCTFail("received a frame that was not sent")
      continue
    }
    delivered.append(frame.name)
  }
  return delivered
}

/// Interprets the classic-BPF instructions `makeEtherTypeFilter()` emits, modelling the ancillary
/// loads it uses, so a frame can be run as outgoing or VLAN-tagged, which the kernel only does for
/// frames on an AF_PACKET socket (and so with CAP_NET_RAW).
private struct _SocketFilterInterpreter {
  var packetType = UInt8(PACKET_HOST)
  var isVLANTagPresent = false

  func accepts(_ frame: _Frame, program: [SocketFilter]) -> Bool {
    let bytes = frame.bytes
    var accumulator: UInt32 = 0
    var programCounter = 0

    while programCounter < program.count {
      let instruction = program[programCounter]
      programCounter += 1

      switch instruction.code {
      case _bpfLoadByte:
        switch Int32(bitPattern: instruction.k) {
        case _bpfPacketTypeOffset:
          accumulator = UInt32(packetType)
        case _bpfVLANTagPresentOffset:
          accumulator = isVLANTagPresent ? 1 : 0
        default:
          // a load beyond the frame ends the program, dropping the frame
          guard Int(instruction.k) < bytes.count else { return false }
          accumulator = UInt32(bytes[Int(instruction.k)])
        }
      case _bpfLoadHalfWord:
        guard Int(instruction.k) + MemoryLayout<UInt16>.size <= bytes.count else { return false }
        accumulator = UInt32(bytes[Int(instruction.k)]) << _bitsPerByte |
          UInt32(bytes[Int(instruction.k) + 1])
      case _bpfJumpIfEqual:
        programCounter += Int(accumulator == instruction.k ? instruction.jt : instruction.jf)
      case _bpfJumpIfGreater:
        programCounter += Int(accumulator > instruction.k ? instruction.jt : instruction.jf)
      case _bpfJumpIfGreaterOrEqual:
        programCounter += Int(accumulator >= instruction.k ? instruction.jt : instruction.jf)
      case _bpfReturn:
        return instruction.k != 0
      default:
        XCTFail("unexpected instruction \(instruction)")
        return false
      }
    }
    XCTFail("program ran off its end")
    return false
  }

  func acceptedNames(_ frames: [_Frame], program: [SocketFilter]) -> [String] {
    frames.filter { accepts($0, program: program) }.map(\.name)
  }
}

final class EtherTypeFilterTests: XCTestCase {
  /// Asserts that both the kernel and the interpreter accept exactly `expected` of `_frames()`.
  private func _assertAccepts(
    _ program: [SocketFilter],
    _ expected: [String],
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let frames = try _frames()
    XCTAssertEqual(
      try _namesDeliveredByKernel(program, frames: frames),
      expected,
      "kernel",
      file: file,
      line: line
    )
    XCTAssertEqual(
      _SocketFilterInterpreter().acceptedNames(frames, program: program),
      expected,
      "interpreter",
      file: file,
      line: line
    )
  }

  func testEtherTypeFilterMatchesOnlyEtherType() throws {
    try _assertAccepts(
      makeEtherTypeFilter(etherTypes: [_avtpEtherType]),
      [
        "ADP", "AECP", "ACMP", "reserved", "MAAP", "EF_CONTROL", "AAF", "CRF", "IEC 61883",
        "header only",
      ]
    )
    try _assertAccepts(
      makeEtherTypeFilter(etherTypes: [_ipv4EtherType, _mvrpEtherType]),
      ["MVRP", "IPv4"]
    )
    try _assertAccepts(makeEtherTypeFilter(etherTypes: []), [])
  }

  // AAF, CRF and IEC 61883 stream data share ATDECC's EtherType, and flood the socket on a bridge
  func testEtherTypeFilterDropsAVTPStreamData() throws {
    try _assertAccepts(
      makeEtherTypeFilter(etherTypes: [_avtpEtherType], subtypes: [_avtpEtherType: [_atdeccSubtypes]]),
      ["ADP", "AECP", "ACMP"]
    )
  }

  func testEtherTypeFilterMatchesSeveralSubtypeRanges() throws {
    try _assertAccepts(
      makeEtherTypeFilter(
        etherTypes: [_avtpEtherType],
        subtypes: [_avtpEtherType: [_atdeccSubtypes, _maapSubtype..._maapSubtype]]
      ),
      ["ADP", "AECP", "ACMP", "MAAP"]
    )
    try _assertAccepts(
      makeEtherTypeFilter(etherTypes: [_avtpEtherType], subtypes: [_avtpEtherType: []]),
      []
    )
  }

  func testEtherTypeFilterRestrictsSubtypesOfOnlyTheirEtherType() throws {
    let expected = ["ADP", "AECP", "ACMP", "MVRP"]
    try _assertAccepts(
      makeEtherTypeFilter(
        etherTypes: [_avtpEtherType, _mvrpEtherType],
        subtypes: [_avtpEtherType: [_atdeccSubtypes]]
      ),
      expected
    )
    try _assertAccepts(
      makeEtherTypeFilter(
        etherTypes: [_mvrpEtherType, _ipv4EtherType, _avtpEtherType],
        subtypes: [_avtpEtherType: [_atdeccSubtypes], _ipv4EtherType: []]
      ),
      expected
    )
  }

  func testEtherTypeFilterDropsOutgoingFramesByDefault() throws {
    let frames = try _frames()
    let program = makeEtherTypeFilter(etherTypes: [_avtpEtherType], subtypes: [_avtpEtherType: [_atdeccSubtypes]])
    // the ancillary loads leave the program acceptable to the kernel
    XCTAssertEqual(try _namesDeliveredByKernel(program, frames: frames), ["ADP", "AECP", "ACMP"])

    var interpreter = _SocketFilterInterpreter()
    for packetType in [PACKET_HOST, PACKET_MULTICAST, PACKET_OTHERHOST] {
      interpreter.packetType = UInt8(packetType)
      XCTAssertEqual(interpreter.acceptedNames(frames, program: program), ["ADP", "AECP", "ACMP"])
    }
    interpreter.packetType = UInt8(PACKET_OUTGOING)
    XCTAssertEqual(interpreter.acceptedNames(frames, program: program), [])
  }

  // the frames other sockets and processes on this host send are outgoing too
  func testEtherTypeFilterCanAcceptOutgoingFrames() throws {
    let frames = try _frames()
    let program = makeEtherTypeFilter(
      etherTypes: [_avtpEtherType],
      subtypes: [_avtpEtherType: [_atdeccSubtypes]],
      dropsOutgoing: false
    )
    XCTAssertEqual(try _namesDeliveredByKernel(program, frames: frames), ["ADP", "AECP", "ACMP"])

    var interpreter = _SocketFilterInterpreter()
    interpreter.packetType = UInt8(PACKET_OUTGOING)
    XCTAssertEqual(interpreter.acceptedNames(frames, program: program), ["ADP", "AECP", "ACMP"])
  }

  func testEtherTypeFilterCanDropVLANTaggedFrames() throws {
    let frames = try _frames()
    let tagged = makeEtherTypeFilter(etherTypes: [_mvrpEtherType], dropsVLANTagged: true)
    let untagged = makeEtherTypeFilter(etherTypes: [_mvrpEtherType])
    XCTAssertEqual(try _namesDeliveredByKernel(tagged, frames: frames), ["MVRP"])

    var interpreter = _SocketFilterInterpreter()
    XCTAssertEqual(interpreter.acceptedNames(frames, program: tagged), ["MVRP"])
    interpreter.isVLANTagPresent = true
    XCTAssertEqual(interpreter.acceptedNames(frames, program: tagged), [])
    XCTAssertEqual(interpreter.acceptedNames(frames, program: untagged), ["MVRP"])
  }
}

#endif

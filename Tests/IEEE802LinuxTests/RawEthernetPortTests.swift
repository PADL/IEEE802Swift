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
import Foundation
import Glibc
import IEEE802
import IEEE802Linux
import XCTest

// names the test a child process runs inside its own user and network namespaces
private let _namespaceTestEnvironmentVariable = "IEEE802SWIFT_NETWORK_NAMESPACE_TEST"
private let _testClassIdentifier = "IEEE802LinuxTests.RawEthernetPortTests"
private let _executableSearchPath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
private let _interfaceName = "veth0"
private let _peerInterfaceName = "veth1"

private let _avtpEtherType: UInt16 = 0x22F0
private let _aafSubtype: UInt8 = 0x02
private let _adpSubtype: UInt8 = 0xFA
private let _atdeccGroupAddress: EUI48 = [0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00]
private let _otherGroupAddress: EUI48 = [0x91, 0xE0, 0xF0, 0x00, 0xFE, 0x00]
private let _minimumPayloadLength = Int(ETH_ZLEN - ETH_HLEN)
// each test frame carries a marker, after its subtype, to tell it apart
private let _markerOffset = 1

private let _receiveTimeout = Duration.seconds(5)
private let _pollInterval = Duration.milliseconds(10)
private let _linkSettleInterval = Duration.milliseconds(200)

private func _executable(named name: String) -> String? {
  let path = ProcessInfo.processInfo.environment["PATH"]?.split(separator: ":").map(String.init) ?? []
  return (path + _executableSearchPath)
    .map { "\($0)/\(name)" }
    .first { FileManager.default.isExecutableFile(atPath: $0) }
}

/// Runs `executable`, returning its exit status and combined output.
private func _run(
  _ executable: String,
  _ arguments: [String],
  environment: [String: String]? = nil
) throws -> (status: Int32, output: String) {
  let process = Process()
  let pipe = Pipe()
  process.executableURL = URL(fileURLWithPath: executable)
  process.arguments = arguments
  if let environment { process.environment = environment }
  process.standardOutput = pipe
  process.standardError = pipe
  try process.run()
  let output = pipe.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()
  return (process.terminationStatus, String(decoding: output, as: UTF8.self))
}

// run in the child, which has already found ip(8) and used it to make its veth pair
private func _ip(_ arguments: String...) throws {
  let result = try _run(_executable(named: "ip") ?? "ip", arguments)
  XCTAssertEqual(result.status, 0, "ip \(arguments.joined(separator: " ")): \(result.output)")
}

private func _packet(
  from port: RawEthernetPort,
  subtype: UInt8 = _adpSubtype,
  marker: UInt8
) -> IEEE802Packet {
  var payload = [UInt8](repeating: 0, count: _minimumPayloadLength)
  payload[0] = subtype
  payload[_markerOffset] = marker
  return IEEE802Packet(
    destMacAddress: _atdeccGroupAddress,
    tci: nil,
    sourceMacAddress: port.interface.macAddress,
    etherType: _avtpEtherType,
    payload: payload
  )
}

/// Receives until the frame marked `last` arrives, returning the marker of each frame received.
private func _receiveMarkers<Packets: AsyncSequence>(
  from packets: sending Packets,
  through last: UInt8
) async throws -> [UInt8] where Packets.Element == IEEE802Packet {
  let receiving = Task {
    var markers = [UInt8]()
    for try await packet in packets where packet.payload.count > _markerOffset {
      markers.append(packet.payload[_markerOffset])
      if markers.last == last { break }
    }
    return markers
  }
  let timeout = Task {
    try await Task.sleep(for: _receiveTimeout)
    receiving.cancel()
  }
  defer { timeout.cancel() }
  let markers = try await receiving.value
  XCTAssertEqual(markers.last, last, "timed out waiting for frame \(last)")
  return markers
}

/// Whether `interface` has joined `groupAddress`, according to /proc/net/dev_mcast.
private func _hasJoined(_ groupAddress: EUI48, on interface: String) throws -> Bool {
  let address = _macAddressToString(groupAddress).replacingOccurrences(of: ":", with: "")
  return try String(contentsOfFile: "/proc/net/dev_mcast", encoding: .utf8)
    .split(separator: "\n")
    .map { $0.split(separator: " ") }
    .contains { $0.contains(Substring(interface)) && $0.last.map(String.init) == address }
}

private func _waitUntil(_ condition: () throws -> Bool) async throws -> Bool {
  let deadline = ContinuousClock.now + _receiveTimeout
  while ContinuousClock.now < deadline {
    if try condition() { return true }
    try await Task.sleep(for: _pollInterval)
  }
  return try condition()
}

/// Packet sockets need CAP_NET_RAW, so each test re-runs itself in a child test process with its
/// own user and network namespaces, in which it holds that capability, on a veth pair made for it.
final class RawEthernetPortTests: XCTestCase {
  private func _inNetworkNamespace(
    _ function: String = #function,
    _ body: () async throws -> ()
  ) async throws {
    let name = function.hasSuffix("()") ? String(function.dropLast(2)) : function
    let environment = ProcessInfo.processInfo.environment
    if environment[_namespaceTestEnvironmentVariable] == name {
      try await body()
      return
    }

    guard let unshare = _executable(named: "unshare"), let ip = _executable(named: "ip") else {
      throw XCTSkip("unshare(1) or ip(8) not found")
    }
    let namespaceArguments = ["--user", "--map-root-user", "--net"]
    let makeVethPair = "\(ip) link add \(_interfaceName) type veth peer name \(_peerInterfaceName)"
    let probe = try _run(unshare, namespaceArguments + ["/bin/sh", "-c", makeVethPair])
    guard probe.status == 0 else {
      throw XCTSkip("can't create a veth pair in an unprivileged network namespace: \(probe.output)")
    }

    // Foundation's Process, which the tests use to run ip(8), needs the loopback interface
    let script = """
    \(ip) link set lo up && \
    \(makeVethPair) && \
    \(ip) link set \(_interfaceName) up && \
    \(ip) link set \(_peerInterfaceName) up && \
    exec "$0" "$1"
    """
    let executable = try FileManager.default.destinationOfSymbolicLink(atPath: "/proc/self/exe")
    var childEnvironment = environment
    childEnvironment[_namespaceTestEnvironmentVariable] = name
    let result = try _run(
      unshare,
      namespaceArguments + ["/bin/sh", "-c", script, executable, "\(_testClassIdentifier)/\(name)"],
      environment: childEnvironment
    )
    XCTAssertEqual(result.status, 0, "\(name) failed in its network namespace:\n\(result.output)")
  }

  // other senders on this host (another process's port, say) transmit frames the kernel shows as
  // outgoing; they must be received, but a port's own frames must not come back to it
  func testReceivesOtherSendersOnHostButNotItself() async throws {
    try await _inNetworkNamespace {
      let port = try RawEthernetPort(name: _interfaceName)
      let otherPort = try RawEthernetPort(name: _interfaceName)
      let peerPort = try RawEthernetPort(name: _peerInterfaceName)

      let packets = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_atdeccGroupAddress],
        subtypes: [_avtpEtherType: [_adpSubtype..._adpSubtype]]
      )
      try await port.send(_packet(from: port, marker: 1))
      try await otherPort.send(_packet(from: otherPort, marker: 2))
      try await peerPort.send(_packet(from: peerPort, subtype: _aafSubtype, marker: 3))
      try await peerPort.send(_packet(from: peerPort, marker: 4))

      let markers = try await _receiveMarkers(from: packets, through: 4)
      XCTAssertEqual(markers.sorted(), [2, 4])
    }
  }

  func testConcurrentReceiversOnOnePort() async throws {
    try await _inNetworkNamespace {
      let port = try RawEthernetPort(name: _interfaceName)
      let peerPort = try RawEthernetPort(name: _peerInterfaceName)

      let control = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_atdeccGroupAddress],
        subtypes: [_avtpEtherType: [_adpSubtype..._adpSubtype]]
      )
      let streams = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_otherGroupAddress],
        subtypes: [_avtpEtherType: [_aafSubtype..._aafSubtype]]
      )
      // a port's own frames reach none of its receivers
      try await port.send(_packet(from: port, marker: 1))
      try await port.send(_packet(from: port, subtype: _aafSubtype, marker: 2))
      try await peerPort.send(_packet(from: peerPort, marker: 3))
      try await peerPort.send(_packet(from: peerPort, subtype: _aafSubtype, marker: 4))
      try await peerPort.send(_packet(from: peerPort, marker: 5))
      try await peerPort.send(_packet(from: peerPort, subtype: _aafSubtype, marker: 6))

      async let controlMarkers = _receiveMarkers(from: control, through: 5)
      async let streamMarkers = _receiveMarkers(from: streams, through: 6)
      let received = try await (controlMarkers, streamMarkers)
      XCTAssertEqual(received.0, [3, 5])
      XCTAssertEqual(received.1, [4, 6])
    }
  }

  func testFinishedReceiverLeavesItsGroupsAndOthersCarryOn() async throws {
    try await _inNetworkNamespace {
      let port = try RawEthernetPort(name: _interfaceName)
      let peerPort = try RawEthernetPort(name: _peerInterfaceName)

      let control = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_atdeccGroupAddress, _otherGroupAddress],
        subtypes: [_avtpEtherType: [_adpSubtype..._adpSubtype]]
      )
      let streams = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_otherGroupAddress],
        subtypes: [_avtpEtherType: [_aafSubtype..._aafSubtype]]
      )
      XCTAssertTrue(try _hasJoined(_atdeccGroupAddress, on: _interfaceName))
      XCTAssertTrue(try _hasJoined(_otherGroupAddress, on: _interfaceName))

      // consuming a sequence releases it once received from, which finishes its receiver
      try await peerPort.send(_packet(from: peerPort, marker: 1))
      let controlMarkers = try await _receiveMarkers(from: consume control, through: 1)
      XCTAssertEqual(controlMarkers, [1])

      // the control receiver is finished; the stream receiver still wants the other group
      let left = try await _waitUntil { try !_hasJoined(_atdeccGroupAddress, on: _interfaceName) }
      XCTAssertTrue(left)
      XCTAssertTrue(try _hasJoined(_otherGroupAddress, on: _interfaceName))

      try await peerPort.send(_packet(from: peerPort, subtype: _aafSubtype, marker: 2))
      let streamMarkers = try await _receiveMarkers(from: consume streams, through: 2)
      XCTAssertEqual(streamMarkers, [2])
      let leftOther = try await _waitUntil { try !_hasJoined(_otherGroupAddress, on: _interfaceName) }
      XCTAssertTrue(leftOther)
    }
  }

  // an interface going administratively down leaves ENETDOWN pending on a packet socket bound to
  // it, which ends a receive in progress but must not fail a later receive or send
  func testReceiveAndSendAfterInterfaceGoesDownAndUp() async throws {
    try await _inNetworkNamespace {
      let port = try RawEthernetPort(name: _interfaceName)
      let peerPort = try RawEthernetPort(name: _peerInterfaceName)

      func bounce() async throws {
        try _ip("link", "set", _interfaceName, "down")
        try await Task.sleep(for: _linkSettleInterval)
        try _ip("link", "set", _interfaceName, "up")
        try await Task.sleep(for: _linkSettleInterval)
      }

      let packets = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_atdeccGroupAddress]
      )
      try await peerPort.send(_packet(from: peerPort, marker: 1))
      let markers = try await _receiveMarkers(from: packets, through: 1)
      XCTAssertEqual(markers, [1])

      // the first bounce ends the receive in progress; the second leaves its error pending
      try await bounce()
      try await bounce()
      let packetsAfterBounce = try await port.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_atdeccGroupAddress]
      )
      try await peerPort.send(_packet(from: peerPort, marker: 2))
      let markersAfterBounce = try await _receiveMarkers(from: packetsAfterBounce, through: 2)
      XCTAssertEqual(markersAfterBounce, [2])

      try await bounce()
      try await bounce()
      let peerPackets = try await peerPort.receivePackets(
        etherTypes: [_avtpEtherType],
        groupAddresses: [_atdeccGroupAddress]
      )
      try await port.send(_packet(from: port, marker: 3))
      let peerMarkers = try await _receiveMarkers(from: peerPackets, through: 3)
      XCTAssertEqual(peerMarkers, [3])
    }
  }
}

#endif

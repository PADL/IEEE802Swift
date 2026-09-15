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

import BinaryParsing
import IEEE802
import XCTest

final class IEEE802Tests: XCTestCase {
  func testUntaggedPacketRoundTrip() throws {
    let packet = IEEE802Packet(
      destMacAddress: [0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00],
      tci: nil,
      sourceMacAddress: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
      etherType: 0x22F0,
      payload: [0xFA, 0x00, 0x00, 0x38]
    )
    let bytes = try packet.serialized()
    XCTAssertEqual(bytes.count, 18)
    XCTAssertEqual(Array(bytes[12..<14]), [0x22, 0xF0])

    let parsed = try bytes.withParserSpan { try IEEE802Packet(parsing: &$0) }
    XCTAssertTrue(_isEqualMacAddress(parsed.destMacAddress, packet.destMacAddress))
    XCTAssertTrue(_isEqualMacAddress(parsed.sourceMacAddress, packet.sourceMacAddress))
    XCTAssertNil(parsed.tci)
    XCTAssertEqual(parsed.etherType, 0x22F0)
    XCTAssertEqual(parsed.payload, packet.payload)
  }

  func testTaggedPacketRoundTrip() throws {
    let packet = IEEE802Packet(
      destMacAddress: [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E],
      tci: IEEE802Packet.TCI(0x6002),
      sourceMacAddress: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
      etherType: 0x22EA,
      payload: [0x00]
    )
    let parsed = try packet.serialized().withParserSpan { try IEEE802Packet(parsing: &$0) }
    XCTAssertEqual(parsed.vid, 2)
    XCTAssertEqual(parsed.tci?.pcp, .CA)
    XCTAssertEqual(parsed.etherType, 0x22EA)
  }

  func testMacAddressString() {
    let mac: EUI48 = [0x91, 0xE0, 0xF0, 0x01, 0x00, 0x01]
    XCTAssertEqual(_macAddressToString(mac), "91:e0:f0:01:00:01")
    XCTAssertTrue(_isEqualMacAddress(_stringToMacAddress("91:e0:f0:01:00:01")!, mac))
    XCTAssertTrue(_isMulticast(macAddress: mac))
  }
}

final class SerializationContextTests: XCTestCase {
  func testIntegersAreSerializedBigEndian() {
    var context = SerializationContext()
    context.serialize(uint8: 0x01)
    context.serialize(uint16: 0x0203)
    context.serialize(uint32: 0x0405_0607)
    context.serialize(uint64: 0x0809_0A0B_0C0D_0E0F)
    context.serialize(int8: -2)
    context.serialize(int16: -3)
    context.serialize(int32: -4)
    context.serialize(int64: .min)
    XCTAssertEqual(context.bytes, [
      0x01,
      0x02, 0x03,
      0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0xFE,
      0xFF, 0xFD,
      0xFF, 0xFF, 0xFF, 0xFC,
      0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    XCTAssertEqual(context.position, 30)
  }

  func testBytesAndMacAddressesAreAppended() {
    var context = SerializationContext()
    context.serialize([0xAA, 0xBB])
    context.serialize(eui48: [0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00])
    context.serialize(contentsOf: "ab".utf8)
    context.serialize(repeating: 0x00, count: 3)
    context.serialize(repeating: 0xFF, count: 0)
    XCTAssertEqual(
      context.bytes,
      [0xAA, 0xBB, 0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00, 0x61, 0x62, 0x00, 0x00, 0x00]
    )
  }

  func testSerializingAtAnIndexOverwritesInPlace() {
    var context = SerializationContext()
    context.serialize(repeating: 0x00, count: 24)
    context.serialize(uint8: 0x01, at: 0)
    context.serialize(uint16: 0x0203, at: 1)
    context.serialize(uint32: 0x0405_0607, at: 3)
    context.serialize(uint64: 0x0809_0A0B_0C0D_0E0F, at: 7)
    context.serialize(eui48: [0x10, 0x11, 0x12, 0x13, 0x14, 0x15], at: 15)
    context.serialize([0x16, 0x17], at: 21)
    context.serialize(int8: -1, at: 23)
    XCTAssertEqual(context.bytes, (0x01...0x17).map { UInt8($0) } + [0xFF])
    XCTAssertEqual(context.position, 24)

    // a length written back over its placeholder once the value it measures is known
    var message = SerializationContext()
    message.serialize(uint16: 0)
    message.serialize(contentsOf: [0xAB, 0xCD, 0xEF])
    message.serialize(uint16: UInt16(message.position - 2), at: 0)
    XCTAssertEqual(message.bytes, [0x00, 0x03, 0xAB, 0xCD, 0xEF])
  }
}

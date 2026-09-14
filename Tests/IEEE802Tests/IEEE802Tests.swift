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

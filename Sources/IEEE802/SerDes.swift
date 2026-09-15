//
// Copyright (c) 2024 PADL Software Pty Ltd
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
import SystemPackage

public protocol Serializable: Sendable {
  func serialize(into: inout SerializationContext) throws
}

public extension Serializable {
  func serialized() throws -> [UInt8] {
    var serializationContext = SerializationContext()
    try serialize(into: &serializationContext)
    return serializationContext.bytes
  }
}

public protocol Deserializble: Sendable, ExpressibleByParsing {
  init(parsing input: inout ParserSpan) throws
}

public protocol SerDes: Serializable, Deserializble {}

/// Serializes values in network byte order into a growing array.
///
/// Integers and MAC addresses are written directly into the array, without an intermediate
/// array per value, and every method is inlinable so that callers in other modules can
/// specialize them.
public struct SerializationContext {
  @usableFromInline
  var _bytes = [UInt8]()

  public init() {}

  @inlinable
  public var bytes: [UInt8] { _bytes }

  @inlinable
  public var position: Int { _bytes.count }

  @inlinable
  public mutating func reserveCapacity(_ capacity: Int) {
    _bytes.reserveCapacity(capacity)
  }

  /// Appends `bytes`, or overwrites the bytes already serialized from `index`.
  @inlinable
  public mutating func serialize(_ bytes: [UInt8], at index: Int? = nil) {
    if let index {
      precondition(_bytes.count >= index + bytes.count)
      _bytes.replaceSubrange(index..<(index + bytes.count), with: bytes)
    } else {
      _bytes += bytes
    }
  }

  @inlinable
  public mutating func serialize(contentsOf bytes: some Sequence<UInt8>) {
    _bytes.append(contentsOf: bytes)
  }

  /// Appends `count` copies of `byte`, such as padding or a reserved field.
  @inlinable
  public mutating func serialize(repeating byte: UInt8, count: Int) {
    precondition(count >= 0)
    _bytes.append(addingCapacity: count) { output in
      for _ in 0..<count {
        output.append(byte)
      }
    }
  }

  @inlinable
  public mutating func serialize(uint8: UInt8, at index: Int? = nil) {
    _serialize(bigEndian: uint8, at: index)
  }

  @inlinable
  public mutating func serialize(uint16: UInt16, at index: Int? = nil) {
    _serialize(bigEndian: uint16, at: index)
  }

  @inlinable
  public mutating func serialize(uint32: UInt32, at index: Int? = nil) {
    _serialize(bigEndian: uint32, at: index)
  }

  @inlinable
  public mutating func serialize(uint64: UInt64, at index: Int? = nil) {
    _serialize(bigEndian: uint64, at: index)
  }

  @inlinable
  public mutating func serialize(int8: Int8, at index: Int? = nil) {
    _serialize(bigEndian: int8, at: index)
  }

  @inlinable
  public mutating func serialize(int16: Int16, at index: Int? = nil) {
    _serialize(bigEndian: int16, at: index)
  }

  @inlinable
  public mutating func serialize(int32: Int32, at index: Int? = nil) {
    _serialize(bigEndian: int32, at: index)
  }

  @inlinable
  public mutating func serialize(int64: Int64, at index: Int? = nil) {
    _serialize(bigEndian: int64, at: index)
  }

  @inlinable
  public mutating func serialize(eui48: EUI48, at index: Int? = nil) {
    if let index {
      precondition(_bytes.count >= index + eui48.count)
      for offset in eui48.indices {
        _bytes[index + offset] = eui48[offset]
      }
    } else {
      _bytes.append(addingCapacity: eui48.count) { output in
        for offset in eui48.indices {
          output.append(eui48[offset])
        }
      }
    }
  }

  @inlinable
  mutating func _serialize(bigEndian value: some FixedWidthInteger, at index: Int?) {
    let count = value.bitWidth / 8
    if let index {
      precondition(_bytes.count >= index + count)
      for offset in 0..<count {
        _bytes[index + offset] = UInt8(truncatingIfNeeded: value >> ((count - 1 - offset) * 8))
      }
    } else {
      _bytes.append(addingCapacity: count) { output in
        for offset in 0..<count {
          output.append(UInt8(truncatingIfNeeded: value >> ((count - 1 - offset) * 8)))
        }
      }
    }
  }
}

// https://forums.swift.org/t/string-format-behaves-differently-on-windows/65197/6
public func _formatHex(
  _ value: some BinaryInteger,
  padToWidth: Int = 16,
  uppercase: Bool = false
) -> String {
  let base = String(value, radix: 16, uppercase: uppercase)
  let pad = String(repeating: "0", count: max(0, padToWidth - base.count))
  return "\(pad)\(base)"
}

// don't want to use Foundation, hence no String(format:)
public func _byteToHex(_ byte: UInt8, uppercase: Bool = false) -> String {
  _formatHex(byte, padToWidth: 2, uppercase: uppercase)
}

public func _bytesToHex(_ bytes: [UInt8], uppercase: Bool = false) -> String {
  bytes.map { _byteToHex($0) }.joined()
}

// MARK: - Helper function for EUI48

public func _eui48(parsing input: inout ParserSpan) throws -> EUI48 {
  try [
    UInt8(parsing: &input),
    UInt8(parsing: &input),
    UInt8(parsing: &input),
    UInt8(parsing: &input),
    UInt8(parsing: &input),
    UInt8(parsing: &input),
  ]
}

extension FixedWidthInteger {
  init<I>(bigEndianBytes iterator: inout I)
    where I: IteratorProtocol, I.Element == UInt8
  {
    self = stride(from: 8, to: Self.bitWidth + 8, by: 8).reduce(into: 0) {
      $0 |= Self(truncatingIfNeeded: iterator.next()!) &<< (Self.bitWidth - $1)
    }
  }

  init(bigEndianBytes bytes: some Collection<UInt8>) {
    precondition(bytes.count == (Self.bitWidth + 7) / 8)
    var iter = bytes.makeIterator()
    self.init(bigEndianBytes: &iter)
  }

  var bigEndianBytes: [UInt8] {
    let count = Self.bitWidth / 8
    var bigEndian = bigEndian
    return [UInt8](withUnsafePointer(to: &bigEndian) {
      $0.withMemoryRebound(to: UInt8.self, capacity: count) {
        UnsafeBufferPointer(start: $0, count: count)
      }
    })
  }

  func serialize(into bytes: inout [UInt8]) throws {
    bytes += bigEndianBytes
  }
}

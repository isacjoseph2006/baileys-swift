import CZlib
import Foundation

enum ZlibError: Error {
    case initFailed(Int32)
    case inflateFailed(Int32)
}

/// One-shot zlib inflate (matching Node's `zlib.inflate`, i.e. zlib-wrapped
/// DEFLATE, not raw deflate) used to decompress WABinary frames that have
/// the compression flag bit set. Grows the output buffer as needed since the
/// decompressed size isn't known up front.
func zlibInflate(_ input: Data) throws -> Data {
    var stream = z_stream()
    let initResult = inflateInit_(&stream, zlibVersion(), Int32(MemoryLayout<z_stream>.size))
    guard initResult == Z_OK else {
        throw ZlibError.initFailed(initResult)
    }
    defer { inflateEnd(&stream) }

    var output = Data()
    var chunk = [UInt8](repeating: 0, count: max(4096, input.count * 4))

    var inputBytes = [UInt8](input)
    var result: Int32 = Z_OK

    try inputBytes.withUnsafeMutableBufferPointer { inPtr in
        stream.next_in = inPtr.baseAddress
        stream.avail_in = UInt32(inPtr.count)

        repeat {
            var produced = 0
            try chunk.withUnsafeMutableBufferPointer { outPtr in
                stream.next_out = outPtr.baseAddress
                stream.avail_out = UInt32(outPtr.count)

                result = inflate(&stream, Z_NO_FLUSH)
                guard result == Z_OK || result == Z_STREAM_END else {
                    throw ZlibError.inflateFailed(result)
                }

                produced = outPtr.count - Int(stream.avail_out)
                output.append(contentsOf: outPtr.prefix(produced))
            }
            // Guard against a malformed/truncated stream spinning forever:
            // if a pass yields no output and isn't the terminal state, there's
            // nothing more this call can do with the input it was given.
            if produced == 0 && result != Z_STREAM_END {
                throw ZlibError.inflateFailed(result)
            }
        } while result != Z_STREAM_END
    }

    return output
}

/// One-shot zlib deflate, used only by tests to produce known-good
/// compressed fixtures for exercising `zlibInflate` (Baileys itself never
/// deflates outgoing frames, so production code has no encode-side path).
func zlibDeflateForTesting(_ input: Data) throws -> Data {
    var destLen = compressBound(uLong(input.count))
    var dest = [UInt8](repeating: 0, count: Int(destLen))
    var source = [UInt8](input)

    let result = source.withUnsafeMutableBufferPointer { srcPtr -> Int32 in
        dest.withUnsafeMutableBufferPointer { dstPtr -> Int32 in
            compress2(dstPtr.baseAddress, &destLen, srcPtr.baseAddress, uLong(srcPtr.count), Z_DEFAULT_COMPRESSION)
        }
    }
    guard result == Z_OK else {
        throw ZlibError.inflateFailed(result)
    }
    return Data(dest.prefix(Int(destLen)))
}

// SPDX-License-Identifier: MPL-2.0
// Independent platform decoding for the mobile-media sanitizer's regression tests.
import AVFoundation
import CoreGraphics
import CoreVideo
import CryptoKit
import Foundation
import ImageIO

func imageSummary(_ path: String) throws -> [String: Any] {
    guard let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil),
          CGImageSourceGetCount(source) == 1,
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
        throw NSError(domain: "FileVeilImageDecode", code: 1)
    }
    let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [String: Any] ?? [:]
    let orientation = (properties[kCGImagePropertyOrientation as String] as? NSNumber)?.intValue ?? 1
    guard image.width * image.height <= 1_000_000 else {
        throw NSError(domain: "FileVeilImageDecodeBudget", code: 1)
    }
    var pixels = [UInt8](repeating: 0, count: image.width * image.height * 4)
    let rendered = pixels.withUnsafeMutableBytes { bytes -> Bool in
        guard let context = CGContext(
            data: bytes.baseAddress, width: image.width, height: image.height,
            bitsPerComponent: 8, bytesPerRow: image.width * 4,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else { return false }
        context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        return true
    }
    guard rendered else { throw NSError(domain: "FileVeilImageRender", code: 1) }
    return ["width": image.width, "height": image.height, "orientation": orientation,
            "rgba_sha256": SHA256.hash(data: Data(pixels)).map { String(format: "%02x", $0) }.joined()]
}

func timeSummary(_ time: CMTime) -> String {
    "\(time.value)/\(time.timescale)"
}

func movieSummary(_ path: String) throws -> [String: Any] {
    let asset = AVURLAsset(url: URL(fileURLWithPath: path))
    var summaries = [[String: Any]]()
    for track in asset.tracks where track.mediaType == .video || track.mediaType == .audio {
        let reader = try AVAssetReader(asset: asset)
        let settings: [String: Any] = track.mediaType == .video
            ? [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
            : [AVFormatIDKey: kAudioFormatLinearPCM,
               AVLinearPCMBitDepthKey: 16, AVLinearPCMIsFloatKey: false,
               AVLinearPCMIsBigEndianKey: false, AVLinearPCMIsNonInterleaved: false]
        let output = AVAssetReaderTrackOutput(track: track, outputSettings: settings)
        reader.add(output)
        guard reader.startReading() else { throw reader.error ?? NSError(domain: "FileVeilAVReader", code: 1) }
        var hash = SHA256()
        var timings = [String]()
        while let sample = output.copyNextSampleBuffer() {
            guard timings.count < 1_000 else { throw NSError(domain: "FileVeilAVBudget", code: 1) }
            timings.append(timeSummary(CMSampleBufferGetPresentationTimeStamp(sample))
                           + ":" + timeSummary(CMSampleBufferGetDuration(sample)))
            if let pixels = CMSampleBufferGetImageBuffer(sample) {
                CVPixelBufferLockBaseAddress(pixels, .readOnly)
                defer { CVPixelBufferUnlockBaseAddress(pixels, .readOnly) }
                guard let base = CVPixelBufferGetBaseAddress(pixels),
                      CVPixelBufferGetWidth(pixels) * CVPixelBufferGetHeight(pixels) <= 1_000_000 else {
                    throw NSError(domain: "FileVeilVideoFrame", code: 1)
                }
                for row in 0..<CVPixelBufferGetHeight(pixels) {
                    hash.update(data: Data(bytes: base.advanced(by: row * CVPixelBufferGetBytesPerRow(pixels)),
                                           count: CVPixelBufferGetWidth(pixels) * 4))
                }
            } else if let block = CMSampleBufferGetDataBuffer(sample) {
                let count = CMBlockBufferGetDataLength(block)
                guard count <= 8 * 1024 * 1024 else { throw NSError(domain: "FileVeilAudioBudget", code: 1) }
                var bytes = [UInt8](repeating: 0, count: count)
                let status = bytes.withUnsafeMutableBytes {
                    CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: count,
                                               destination: $0.baseAddress!)
                }
                guard status == noErr else { throw NSError(domain: "FileVeilAudioDecode", code: Int(status)) }
                hash.update(data: Data(bytes))
            } else { throw NSError(domain: "FileVeilEmptySample", code: 1) }
        }
        guard reader.status == .completed, !timings.isEmpty else {
            throw reader.error ?? NSError(domain: "FileVeilAVIncomplete", code: 1)
        }
        let transform = track.preferredTransform
        summaries.append(["kind": track.mediaType.rawValue, "samples": timings,
                          "transform": [transform.a, transform.b, transform.c, transform.d,
                                        transform.tx, transform.ty],
                          "decoded_sha256": hash.finalize().map { String(format: "%02x", $0) }.joined()])
    }
    guard !summaries.isEmpty else { throw NSError(domain: "FileVeilNoAVTracks", code: 1) }
    return ["tracks": summaries, "duration": timeSummary(asset.duration)]
}

for path in CommandLine.arguments.dropFirst() {
    let extensionName = URL(fileURLWithPath: path).pathExtension.lowercased()
    let summary = try ["heic", "heif", "avif"].contains(extensionName)
        ? imageSummary(path) : movieSummary(path)
    let data = try JSONSerialization.data(withJSONObject: summary, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}

// FVPROV1 5806 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3Mzg1OGJlZGNiZDIxYjA3ZjJiNDZlZjZjYmQ0N2QzMTNjNzM4YjUyYTI3YmExM2M5OWM0NmY4MDM5ODQyNTQxIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvc3VwcG9ydC9tZWRpYV9maWRlbGl0eS5zd2lmdCJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImUwOTljNDhkMzE0MmVhZWRiMWUyNjBmMzYwNTgxYTA1YzEyMDhiODNlMGUwNjcyNTY5Yjk3NGY1ZTVhOTA5YWJmZjgwYTZkNjRjYjkxNjdmMmFkZWExNGQ3OTlkZTA2OTA0Y2JkYTI5ODM2MzA3MmU3MDY3Njg2MDFkYmI3NDA1In1dfV0= FVPROV1-END

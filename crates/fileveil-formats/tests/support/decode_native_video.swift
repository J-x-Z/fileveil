// SPDX-License-Identifier: MPL-2.0
// CI interoperability check against the platform decoder for synthetic fixtures.
import AVFoundation
import CoreVideo
import Foundation

for filename in CommandLine.arguments.dropFirst() {
    let asset = AVURLAsset(url: URL(fileURLWithPath: filename))
    guard let track = asset.tracks(withMediaType: .video).first else { fatalError("Video track missing") }
    let reader = try AVAssetReader(asset: asset)
    let output = AVAssetReaderTrackOutput(track: track, outputSettings: [
        kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
    ])
    reader.add(output)
    guard reader.startReading() else { fatalError("Native decoder did not start") }
    var frames = 0
    while let sample = output.copyNextSampleBuffer() {
        guard let pixels = CMSampleBufferGetImageBuffer(sample),
              CVPixelBufferGetWidth(pixels) == 64, CVPixelBufferGetHeight(pixels) == 64 else {
            fatalError("Decoded fixture dimensions disagree")
        }
        frames += 1
    }
    guard reader.status == .completed, frames == 2 else { fatalError("Native fixture decode failed") }
    print("Native AVAssetReader decoded \(URL(fileURLWithPath: filename).lastPathComponent), 2 frames, 64x64 BGRA")
}

// FVPROV1 1266 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4M2EzZjZlMmI4YThlNDQ3N2E4MTJiN2EwMzQ2YzM4ODdlYmEwMDRkZDI5ZjU3ODU4MTViMDVlNjI1NmQ3NjVmIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3Rlc3RzL3N1cHBvcnQvZGVjb2RlX25hdGl2ZV92aWRlby5zd2lmdCJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjdmMTIxYTUyZGMzOTY3OWIxMGY3MzU1MzM1NDgxNTA4ZGFiMzI0YzAyZTQ4YThkYTAxODY3ZjU5ZmJiZTMzNGE1MDM0MDZkNjM1NGUxNmEzY2MwNWU4MWM5MTA1YmNhODMwMjk4ZDUwYmY0OWIxMzY5NDA5NzhhNTgwY2Q1ODA0In1dfV0= FVPROV1-END

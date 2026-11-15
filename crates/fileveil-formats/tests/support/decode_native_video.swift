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

// FVPROV1 1266 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4M2EzZjZlMmI4YThlNDQ3N2E4MTJiN2EwMzQ2YzM4ODdlYmEwMDRkZDI5ZjU3ODU4MTViMDVlNjI1NmQ3NjVmIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3Rlc3RzL3N1cHBvcnQvZGVjb2RlX25hdGl2ZV92aWRlby5zd2lmdCJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImExOTQ0NjMwYWVlYzU4ZDhiNGQwZGQ5ZDRlNzJlODAyZDlhZGRmZGM3YzljZDNmMGIzY2Y0NzU1YmI0MWQ0MzUyZDIxN2Q0ZDY4NDkyMGI5ZGVhNWM2ODVmZDNjYWM2NDc1NDBmYzkwOGMyZTRiYzhjNzgxMmU3NjY5NWVlYzA0In1dfV0= FVPROV1-END

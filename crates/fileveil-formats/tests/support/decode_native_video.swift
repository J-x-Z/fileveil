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

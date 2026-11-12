// SPDX-License-Identifier: MPL-2.0
// Creates a small, fictional H.264/AAC interoperability sample using platform encoders.
import AVFoundation
import Foundation

guard CommandLine.arguments.count == 3 else {
    fatalError("usage: generate_av_fixture.swift video-source output.mp4")
}
let videoURL = URL(fileURLWithPath: CommandLine.arguments[1])
let outputURL = URL(fileURLWithPath: CommandLine.arguments[2])
guard !FileManager.default.fileExists(atPath: outputURL.path) else { fatalError("Output exists") }
let workspace = outputURL.deletingLastPathComponent().appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: false)
defer { try? FileManager.default.removeItem(at: workspace) }
let waveURL = workspace.appendingPathComponent("tone.wav")
let format = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: 44_100,
                           channels: 1, interleaved: true)!
let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: 5_512)!
buffer.frameLength = 5_512
for index in 0..<Int(buffer.frameLength) {
    buffer.int16ChannelData![0][index] = Int16(sin(Double(index) * 2 * .pi * 220 / 44_100) * 8_000)
}
do {
let wave = try AVAudioFile(forWriting: waveURL, settings: format.settings,
                          commonFormat: .pcmFormatInt16, interleaved: true)
try wave.write(from: buffer)
}
let video = AVURLAsset(url: videoURL)
let audio = AVURLAsset(url: waveURL)
let composition = AVMutableComposition()
let range = CMTimeRange(start: .zero, duration: CMTime(value: 1, timescale: 8))
let videoTrack = composition.addMutableTrack(withMediaType: .video,
                                            preferredTrackID: kCMPersistentTrackID_Invalid)!
let audioTrack = composition.addMutableTrack(withMediaType: .audio,
                                            preferredTrackID: kCMPersistentTrackID_Invalid)!
try videoTrack.insertTimeRange(range, of: video.tracks(withMediaType: .video)[0], at: .zero)
try audioTrack.insertTimeRange(range, of: audio.tracks(withMediaType: .audio)[0], at: .zero)
let exporter = AVAssetExportSession(asset: composition, presetName: AVAssetExportPresetHighestQuality)!
exporter.outputURL = outputURL
exporter.outputFileType = .mp4
let model = AVMutableMetadataItem()
model.keySpace = .quickTimeMetadata
model.key = "com.apple.quicktime.model" as NSString
model.value = "Synthetic FileVeil Device" as NSString
exporter.metadata = [model]
let completed = DispatchSemaphore(value: 0)
exporter.exportAsynchronously { completed.signal() }
guard completed.wait(timeout: .now() + 60) == .success,
      exporter.status == .completed else {
    fatalError("Native fixture export failed \(String(describing: exporter.error))")
}
print(outputURL.path)

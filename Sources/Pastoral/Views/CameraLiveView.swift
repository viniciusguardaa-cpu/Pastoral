import SwiftUI
import AppKit

// MARK: - Camera live view
//
// Displays a live RTSP stream in a SwiftUI view. Wraps an NSImageView
// that gets updated whenever a new frame arrives from the RTSPStreamClient.
// The stream lifecycle is managed by AppState (startLiveStream/stopLiveStream).

/// A SwiftUI view that shows a live camera feed. The current frame is
/// published by AppState as an NSImage keyed by camera id.
struct CameraLiveView: View {
    let cameraID: String
    @Bindable var state: AppState

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.black)

            if let frame = state.liveFrames[cameraID] {
                Image(nsImage: frame)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
            } else if state.liveStreamActive.contains(cameraID) {
                VStack(spacing: 8) {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("conectando…")
                        .font(.caption2)
                        .foregroundStyle(.white.opacity(0.5))
                }
            } else {
                VStack(spacing: 6) {
                    Image(systemName: "camera.fill")
                        .font(.title2)
                        .foregroundStyle(.white.opacity(0.3))
                    Text("stream parado")
                        .font(.caption2)
                        .foregroundStyle(.white.opacity(0.3))
                }
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

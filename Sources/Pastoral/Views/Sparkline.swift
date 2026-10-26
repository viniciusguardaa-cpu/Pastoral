import SwiftUI

/// A tiny inline sparkline drawn from a series of throughput samples.
/// Uses a monotone-ish polyline; cheap and good enough for a table cell.
struct Sparkline: View {
    let samples: [Double]
    var color: Color = .accentColor
    var height: CGFloat = 16

    var body: some View {
        GeometryReader { geo in
            Canvas { ctx, size in
                guard samples.count > 1 else { return }
                let maxV = max(samples.max() ?? 1, 1)
                let stepX = size.width / CGFloat(samples.count - 1)
                var path = Path()
                for (i, v) in samples.enumerated() {
                    let x = CGFloat(i) * stepX
                    let y = size.height - CGFloat(v / maxV) * size.height
                    if i == 0 { path.move(to: .init(x: x, y: y)) }
                    else { path.addLine(to: .init(x: x, y: y)) }
                }
                ctx.stroke(path, with: .color(color), lineWidth: 1.25)
            }
        }
        .frame(height: height)
    }
}

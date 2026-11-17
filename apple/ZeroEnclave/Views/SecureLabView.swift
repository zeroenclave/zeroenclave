#if DEBUG
    import AVFoundation
    import SwiftUI
    import UIKit

    /// Debug-only test bench for capture-protected rendering (launch argument `-ze-lab`).
    struct SecureLabView: View {
        var body: some View {
            let candidates = SecureLab.candidates()
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    Text(verbatim: "Secure lab").font(.headline)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 110))], spacing: 8) {
                        ForEach(candidates.indices, id: \.self) { index in
                            VStack(spacing: 2) {
                                SecureLabCell(strategy: candidates[index])
                                    .frame(height: 110)
                                Text(verbatim: "\(index): \(candidates[index].name)")
                                    .font(.system(size: 9))
                                    .lineLimit(2)
                            }
                        }
                    }
                    Text(verbatim: "SecureImage (production)").font(.caption)
                    HStack {
                        SecureImage(image: SecureLab.testImage()).frame(width: 110, height: 110)
                        SecureImage(image: SecureLab.testImage(), contentMode: .scaleAspectFill)
                            .aspectRatio(1, contentMode: .fit).frame(width: 110)
                    }
                }
                .padding()
            }
            .onAppear { SecureLab.dump() }
            .task {
                guard ProcessInfo.processInfo.arguments.contains("-ze-lab-video"),
                    let url = await SecureLab.testVideo()
                else { return }
                let player = AVPlayer(url: url)
                player.actionAtItemEnd = .pause
                NativeVideoPlayer.present(player: player, onStart: { player.play() }, onClose: {})
            }
        }
    }

    struct SecureLabStrategy {
        let name: String
        /// Returns the view to put into the cell; the probe image must end up inside it.
        let build: (UIImageView) -> UIView
    }

    enum SecureLab {
        static func testImage() -> UIImage {
            UIGraphicsImageRenderer(size: CGSize(width: 120, height: 120)).image { ctx in
                UIColor.systemRed.setFill()
                ctx.fill(CGRect(x: 0, y: 0, width: 120, height: 120))
                ("TEST" as NSString).draw(
                    at: CGPoint(x: 20, y: 45),
                    withAttributes: [.font: UIFont.boldSystemFont(ofSize: 28), .foregroundColor: UIColor.white])
            }
        }

        /// Writes a ten second H.264 clip of the test image to the temporary directory.
        static func testVideo() async -> URL? {
            let url = FileManager.default.temporaryDirectory.appendingPathComponent("ze-lab.mp4")
            try? FileManager.default.removeItem(at: url)
            guard let writer = try? AVAssetWriter(outputURL: url, fileType: .mp4) else { return nil }
            let size = 240
            let input = AVAssetWriterInput(
                mediaType: .video,
                outputSettings: [
                    AVVideoCodecKey: AVVideoCodecType.h264, AVVideoWidthKey: size, AVVideoHeightKey: size,
                ])
            let adaptor = AVAssetWriterInputPixelBufferAdaptor(
                assetWriterInput: input,
                sourcePixelBufferAttributes: [
                    kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
                    kCVPixelBufferWidthKey as String: size, kCVPixelBufferHeightKey as String: size,
                ])
            writer.add(input)
            writer.startWriting()
            writer.startSession(atSourceTime: .zero)
            guard let cgImage = testImage().cgImage else { return nil }
            for frame in 0..<300 {
                while !input.isReadyForMoreMediaData { try? await Task.sleep(for: .milliseconds(5)) }
                var buffer: CVPixelBuffer?
                CVPixelBufferCreate(nil, size, size, kCVPixelFormatType_32BGRA, nil, &buffer)
                guard let buffer else { return nil }
                CVPixelBufferLockBaseAddress(buffer, [])
                let context = CGContext(
                    data: CVPixelBufferGetBaseAddress(buffer), width: size, height: size, bitsPerComponent: 8,
                    bytesPerRow: CVPixelBufferGetBytesPerRow(buffer), space: CGColorSpaceCreateDeviceRGB(),
                    bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)
                context?.draw(cgImage, in: CGRect(x: 0, y: 0, width: size, height: size))
                CVPixelBufferUnlockBaseAddress(buffer, [])
                adaptor.append(buffer, withPresentationTime: CMTime(value: CMTimeValue(frame), timescale: 30))
            }
            input.markAsFinished()
            await writer.finishWriting()
            return writer.status == .completed ? url : nil
        }

        static func secureField() -> UITextField {
            let field = UITextField(frame: CGRect(x: 0, y: 0, width: 110, height: 110))
            field.isSecureTextEntry = true
            field.layoutIfNeeded()
            return field
        }

        static func describe(_ view: UIView, depth: Int = 0) -> [String] {
            var lines = [String(repeating: "  ", count: depth) + "view \(type(of: view))"]
            for layer in view.layer.sublayers ?? [] where !view.subviews.contains(where: { $0.layer === layer }) {
                lines.append(String(repeating: "  ", count: depth + 1) + "layer \(type(of: layer))")
            }
            for sub in view.subviews { lines += describe(sub, depth: depth + 1) }
            return lines
        }

        static func dump() {
            let field = secureField()
            print("ZE-LAB secure field tree:\n" + describe(field).joined(separator: "\n"))
        }

        static func candidates() -> [SecureLabStrategy] {
            var list: [SecureLabStrategy] = [
                SecureLabStrategy(name: "plain") { $0 }
            ]
            // Every subview of the secure field as a container.
            let probe = secureField()
            func paths(_ view: UIView, _ path: [Int]) -> [[Int]] {
                var result: [[Int]] = []
                for (i, sub) in view.subviews.enumerated() {
                    result.append(path + [i])
                    result += paths(sub, path + [i])
                }
                return result
            }
            for path in paths(probe, []) {
                list.append(
                    SecureLabStrategy(name: "subview \(path)") { imageView in
                        let field = secureField()
                        var container: UIView = field
                        for i in path where container.subviews.indices.contains(i) { container = container.subviews[i] }
                        container.subviews.forEach { $0.removeFromSuperview() }
                        container.isUserInteractionEnabled = true
                        imageView.frame = CGRect(x: 0, y: 0, width: 110, height: 110)
                        container.addSubview(imageView)
                        return field
                    })
            }
            // Every sublayer of the field's own layer as a container.
            for i in (probe.layer.sublayers ?? []).indices {
                list.append(
                    SecureLabStrategy(name: "layer \(i)") { imageView in
                        let field = secureField()
                        imageView.frame = CGRect(x: 0, y: 0, width: 110, height: 110)
                        field.layer.sublayers?[i].addSublayer(imageView.layer)
                        return field
                    })
            }
            // Secure entry toggled after the content is in place.
            list.append(
                SecureLabStrategy(name: "toggle after") { imageView in
                    let field = UITextField(frame: CGRect(x: 0, y: 0, width: 110, height: 110))
                    field.layoutIfNeeded()
                    let container = field.subviews.first ?? field
                    imageView.frame = CGRect(x: 0, y: 0, width: 110, height: 110)
                    container.addSubview(imageView)
                    field.isSecureTextEntry = true
                    return field
                })
            return list
        }
    }

    struct SecureLabCell: UIViewRepresentable {
        let strategy: SecureLabStrategy

        func makeUIView(context: Context) -> UIView {
            let host = UIView(frame: CGRect(x: 0, y: 0, width: 110, height: 110))
            let imageView = UIImageView(image: SecureLab.testImage())
            imageView.contentMode = .scaleAspectFill
            let built = strategy.build(imageView)
            built.frame = host.bounds
            host.addSubview(built)
            host.clipsToBounds = true
            return host
        }

        func updateUIView(_ view: UIView, context: Context) {}
    }
#endif

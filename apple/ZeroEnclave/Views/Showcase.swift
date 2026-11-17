import SwiftUI

/// Hero of the Premium and Enclave Link pages: gradient, a slow sheen and a glow behind the icon.
struct ShowcaseHero<Icon: View>: View {
    let gradient: LinearGradient
    let title: Text
    let subtitle: Text
    let badge: Label<Text, Image>
    @ViewBuilder let icon: Icon

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: 14) {
            icon
                .background {
                    Circle()
                        .fill(.white.opacity(0.35))
                        .frame(width: 120, height: 120)
                        .blur(radius: 36)
                }
                .shadow(color: .black.opacity(0.25), radius: 12, y: 6)
            title
                .font(.largeTitle.bold())
                .multilineTextAlignment(.center)
            subtitle
                .font(.subheadline)
                .multilineTextAlignment(.center)
                .opacity(0.9)
            badge
                .font(.footnote.weight(.semibold))
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(.white.opacity(0.18), in: .capsule)
                .overlay(Capsule().strokeBorder(.white.opacity(0.3), lineWidth: 0.5))
        }
        .foregroundStyle(.white)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
        .padding(.horizontal, 20)
        .background {
            ZStack {
                gradient
                if !reduceMotion { Sheen() }
            }
            .clipShape(.rect(cornerRadius: 32))
        }
        .overlay(RoundedRectangle(cornerRadius: 32).strokeBorder(.white.opacity(0.18), lineWidth: 1))
        .shadow(color: .black.opacity(0.18), radius: 20, y: 10)
    }
}

/// A soft diagonal light band that drifts across the hero every few seconds.
private struct Sheen: View {
    var body: some View {
        GeometryReader { proxy in
            let width = proxy.size.width
            PhaseAnimator([false, true]) { moved in
                LinearGradient(
                    colors: [.clear, .white.opacity(0.22), .clear],
                    startPoint: .leading, endPoint: .trailing
                )
                .frame(width: width * 0.6)
                .rotationEffect(.degrees(20))
                .offset(x: moved ? width * 1.2 : -width * 0.9)
            } animation: { moved in
                moved ? .easeInOut(duration: 2.4).delay(1.2) : .linear(duration: 0)
            }
            .frame(maxHeight: .infinity)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// Card on the Premium and Enclave Link pages: icon on a gradient tile, title, one line.
struct FeatureCard: View {
    let icon: String
    let title: LocalizedStringResource
    let detail: LocalizedStringResource
    var soon = false
    var highlighted = false
    var tile = Theme.premiumGradient

    init(feature: Feature, soon: Bool, highlighted: Bool) {
        self.init(icon: feature.icon, title: feature.title, detail: feature.detail, soon: soon, highlighted: highlighted)
    }

    init(
        icon: String, title: LocalizedStringResource, detail: LocalizedStringResource, soon: Bool = false,
        highlighted: Bool = false, tile: LinearGradient = Theme.premiumGradient
    ) {
        self.icon = icon
        self.title = title
        self.detail = detail
        self.soon = soon
        self.highlighted = highlighted
        self.tile = tile
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: icon)
                .font(.system(.title3, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 42, height: 42)
                .background(tile, in: .rect(cornerRadius: 12))
                .shadow(color: .black.opacity(0.15), radius: 4, y: 2)
                .saturation(soon ? 0.4 : 1)
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(16)
        .background(.background.secondary, in: .rect(cornerRadius: 22))
        .overlay {
            RoundedRectangle(cornerRadius: 22)
                .strokeBorder(highlighted ? AnyShapeStyle(Theme.mint) : AnyShapeStyle(.separator.opacity(0.6)),
                              lineWidth: highlighted ? 2 : 0.5)
        }
        .overlay(alignment: .topTrailing) {
            if soon {
                Text("Available soon")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(.fill.secondary, in: .capsule)
                    .padding(12)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

extension View {
    /// Fades and lifts the view in on appear; `order` staggers a group of views.
    func revealOnAppear(order: Int = 0) -> some View {
        modifier(Reveal(order: order))
    }
}

private struct Reveal: ViewModifier {
    let order: Int
    @State private var shown = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .opacity(shown || reduceMotion ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : 14)
            .onAppear {
                withAnimation(.smooth(duration: 0.5).delay(0.05 * Double(order))) { shown = true }
            }
    }
}

/// Header of the step flows (PIN, Face ID, album code): icon, optional step, title, one line.
/// An error replaces the line and shows as a notice.
struct FlowHeader: View {
    let icon: String
    var step: Text?
    let title: Text
    let subtitle: String
    var isError = false
    var bounce = false

    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 44

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: iconSize))
                .foregroundStyle(Theme.mint)
                .contentTransition(.symbolEffect(.replace))
                .symbolEffect(.bounce, value: bounce)
                .accessibilityHidden(true)
            if let step {
                step
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            title
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
            Group {
                if isError {
                    Notice(verbatim: subtitle)
                } else {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .multilineTextAlignment(.center)
            .frame(minHeight: 40, alignment: .top)
        }
        .padding(.top, 24)
        .padding(.horizontal, 24)
        .animation(.default, value: subtitle)
    }
}

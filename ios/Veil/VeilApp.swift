import SwiftUI

@main
struct VeilApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ZStack {
                content
                if scenePhase != .active {
                    PrivacyOverlayView()
                }
            }
            .environmentObject(model)
            .onAppear { model.setActive(scenePhase == .active) }
            .onChange(of: scenePhase) { _, phase in
                model.setActive(phase == .active)
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        if let failure = model.bootstrapFailure {
            // A throwing vault load must never be papered over with an empty state.
            FatalBootView(message: failure)
        } else if model.vaultState.account == nil {
            OnboardingView()
        } else {
            MainTabView()
        }
    }
}

struct MainTabView: View {
    var body: some View {
        TabView {
            ChatsListView()
                .tabItem {
                    Label("Чати", systemImage: "bubble.left.and.bubble.right.fill")
                }
            SettingsView()
                .tabItem {
                    Label("Налаштування", systemImage: "gearshape.fill")
                }
        }
    }
}

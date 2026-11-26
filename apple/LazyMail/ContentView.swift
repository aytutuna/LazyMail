import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Text("Lazy Mail")
            Text(coreVersion())
                .accessibilityIdentifier("CoreVersion")
        }
        .padding()
    }
}

import XCTest

final class CoreVersionTests: XCTestCase {
    func testShowsCoreVersion() throws {
        let expected = try XCTUnwrap(
            Bundle(for: Self.self).object(forInfoDictionaryKey: "CoreVersion") as? String)
        XCTAssertFalse(expected.isEmpty)

        let app = XCUIApplication()
        app.launch()

        let version = app.staticTexts["CoreVersion"]
        XCTAssertTrue(version.waitForExistence(timeout: 30))
        // macOS exposes a static text's string as its value, iOS as its label
        let shown = version.label.isEmpty ? (version.value as? String ?? "") : version.label
        XCTAssertEqual(shown, expected)
    }
}

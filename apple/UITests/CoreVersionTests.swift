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
        XCTAssertEqual(version.label, expected)
    }
}

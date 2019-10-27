import XCTest
@testable import URLRequest_AWS

final class URLRequest_AWSTests: XCTestCase {
    let credentials = Credentials(
        accessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        accessKeyID: "AKIDEXAMPLE"
    )

    let date = Date(timeIntervalSince1970: 1440938160)

    /// Example request per https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    ///
    /// ```
    /// GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 HTTP/1.1
    /// Host: iam.amazonaws.com
    /// Content-Type: application/x-www-form-urlencoded; charset=utf-8
    /// X-Amz-Date: 20150830T123600Z
    ///
    ///
    /// ```
    func testCanonicalRequest() {
        var request = URLRequest(url: URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!)
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")

        // Set an authorization header to test it not affecting the outcome,
        // even if we will override it.
        request.setValue("meh", forHTTPHeaderField: "Authorization")

        request.httpBody = "".data(using: .utf8)

        request.sign(credentials: credentials, date: date, region: "us-east-1", service: "iam")

        XCTAssertEqual(request.allHTTPHeaderFields?["Authorization"], "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")

        // Signing should be idempotent.
        request.sign(credentials: credentials, date: date, region: "us-east-1", service: "iam")

        XCTAssertEqual(request.allHTTPHeaderFields?["Authorization"], "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
    }
}

import CryptoKit
import Foundation

public struct Credentials: Codable {
    public let accessKey: String

    public let accessKeyID: String

    fileprivate var prefixedKey: String {
        "AWS4" + accessKey
    }
}

public extension URLRequest {
    mutating func sign(credentials: Credentials, date now: Date = Date(), region: String, service: String) {
        precondition(httpBodyStream == nil, "Streaming reqeuests using `httpBodyStream` are not supported.")

        let date = dateTimeFormatter.string(from: now)

        setValue(date, forHTTPHeaderField: "x-amz-date")
        setValue(nil, forHTTPHeaderField: "Authorization")
        setValue(nil, forHTTPHeaderField: "x-amz-content-sha256")
        setValue(url?.host, forHTTPHeaderField: "host")

        let parameters = [
            dayFormatter.string(from: now),
            region,
            service,
            "aws4_request"
        ]

        let derivedSigningKey = parameters
            .reduce(into: SymmetricKey(data: Data(credentials.prefixedKey.utf8))) { key, parameter in
                var hmac = HMAC<SHA256>(key: key)
                hmac.update(data: Data(parameter.utf8))

                key = SymmetricKey(data: Data(hmac.finalize()))
            }

        let credentialScope = parameters.joined(separator: "/")

        let canonicalHeaders = allHTTPHeaderFields?
            .mapValues { value in
                value
                    .trimmingCharacters(in: .whitespaces)
                    .split(separator: " ")
                    .joined(separator: " ")
            }
            .map { key, value in
                key.lowercased() + ":" + value
            }
            .sorted()
            .joined(separator: "\n")
            .appending("\n")

        let signedHeaders = allHTTPHeaderFields?
            .keys
            .sorted()
            .joined(separator: ";")
            .lowercased()

        let encodedPayloadSignature = SHA256.hash(data: httpBody ?? Data()).hexEncodedString()

        let canonicalRequestComponents = [
            httpMethod ?? "GET", "\n",
            url?.canonicalURI ?? "", "\n",
            url?.canonicalQueryString ?? "", "\n",
            canonicalHeaders ?? "", "\n",
            signedHeaders ?? "", "\n",
            encodedPayloadSignature
        ]

        let requestSignature = canonicalRequestComponents
            .reduce(into: SHA256()) { f, parameter in
                f.update(data: Data(parameter.utf8))
            }
            .finalize()

        let signatureComponents = [
            "AWS4-HMAC-SHA256", "\n",
            date, "\n",
            credentialScope, "\n",
            requestSignature.hexEncodedString()
        ]

        let signature = signatureComponents
            .reduce(into: HMAC<SHA256>(key: derivedSigningKey)) { f, component in
                f.update(data: Data(component.utf8))
            }
            .finalize()

        let authorization = "AWS4-HMAC-SHA256 Credential=\(credentials.accessKeyID)/\(credentialScope), SignedHeaders=\(signedHeaders ?? ""), Signature=\(signature.hexEncodedString())"

        setValue(authorization, forHTTPHeaderField: "Authorization")
        setValue(encodedPayloadSignature, forHTTPHeaderField: "x-amz-content-sha256")
    }
}

private let urlPathAllowed = CharacterSet.urlPathAllowed.subtracting(CharacterSet(charactersIn: "@"))

private extension URL {
    var canonicalURI: String? {
        path.addingPercentEncoding(withAllowedCharacters: urlPathAllowed)
    }

    var canonicalQueryString: String? {
        query?
            .split(separator: "&")
            .sorted()
            .joined(separator: "&")
    }
}

private extension Sequence where Element == UInt8 {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private let dateTimeFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(abbreviation: "UTC")

    return formatter
}()

private let dayFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyyMMdd"
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(abbreviation: "UTC")

    return formatter
}()

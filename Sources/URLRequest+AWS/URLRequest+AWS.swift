import CommonCrypto
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
            .map { $0.utf8Data }
            .reduce(credentials.prefixedKey.utf8Data, hmacDigest)

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

        let encodedPayloadHash = (httpBody ?? Data()).sha256Hash().hexEncodedString()

        let canonicalRequest = [
            httpMethod ?? "GET",
            url?.canonicalURI ?? "",
            url?.canonicalQueryString ?? "",
            canonicalHeaders ?? "",
            signedHeaders ?? "",
            encodedPayloadHash
        ].joined(separator: "\n")

        let stringToSign = [
            "AWS4-HMAC-SHA256",
            date,
            credentialScope,
            canonicalRequest.sha256Hash.hexEncodedString()
        ].joined(separator: "\n")

        let signature = hmacDigest(derivedSigningKey, stringToSign.utf8Data).hexEncodedString()

        let authorization = "AWS4-HMAC-SHA256 Credential=\(credentials.accessKeyID)/\(credentialScope), SignedHeaders=\(signedHeaders ?? ""), Signature=\(signature)"

        setValue(authorization, forHTTPHeaderField: "Authorization")
        setValue(encodedPayloadHash, forHTTPHeaderField: "x-amz-content-sha256")
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

private extension String {
    var sha256Hash: Data {
        utf8Data.sha256Hash()
    }

    var utf8Data: Data {
        data(using: .utf8) ?? Data()
    }
}

private func hmacDigest(_ key: Data, _ data: Data) -> Data {
    var digest = Array(repeating: 0x00 as UInt8, count: Int(CC_SHA256_DIGEST_LENGTH))

    key.withUnsafeBytes { rawKey in
        data.withUnsafeBytes { bytes in
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), rawKey.baseAddress, key.count, bytes.baseAddress, data.count, &digest)
        }
    }

    return Data(bytes: &digest, count: Int(CC_SHA256_DIGEST_LENGTH))
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

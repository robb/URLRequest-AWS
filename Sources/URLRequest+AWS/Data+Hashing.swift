import CommonCrypto
import Foundation

public extension Data {
    func md5Hash() -> Data {
        var hash = Array(repeating: 0x00 as UInt8, count: Int(CC_MD5_DIGEST_LENGTH))

        withUnsafeBytes { bytes in
            _ = CC_MD5(bytes.baseAddress, CC_LONG(count), &hash)
        }

        return Data(hash)
    }

    func sha256Hash() -> Data {
        var hash = Array(repeating: 0x00 as UInt8, count: Int(CC_SHA256_DIGEST_LENGTH))

        withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(count), &hash)
        }

        return Data(hash)
    }
}

public extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

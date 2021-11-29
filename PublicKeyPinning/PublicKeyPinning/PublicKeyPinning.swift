//
//  PublicKeyPinning.swift
//  PublicKeyPinning
//
//  Created by Anwesh M on 29/11/21.
//

import Foundation
import CryptoKit
import OSLog


class PublicKeyPinning{
    
    static func verifyPublicKey(url: String, serverPublicKeysHashes: [String], completionHandler: @escaping ( _ status: Bool, _ error: Error?) -> Void){
        let session = URLSession(configuration: URLSessionConfiguration.default, delegate: PinningDelegate(serverPublicKeysHashes: serverPublicKeysHashes), delegateQueue: OperationQueue.main)
        let urlRequest = URLRequest(url: URL(string: url)!)
        let task = session.dataTask(with: urlRequest) { (data, response, error) in
            completionHandler(error == nil, error)
        }
        task.resume()
    }
    
    static func findHash()-> String{
        return ""
    }
}


class PinningDelegate: NSObject, URLSessionDelegate {
    private  let serverPublicKeysHashes: [String]
    private  let rsa2048Asn1Header: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    init(serverPublicKeysHashes: [String]) {
        self.serverPublicKeysHashes = serverPublicKeysHashes
    }
    
    @available(OSX 10.15, *)
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
       
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult: CFError? = nil
                let certTrusted = SecTrustEvaluateWithError(serverTrust, &secresult)
                let certCount = SecTrustGetCertificateCount(serverTrust)
                
                if (certTrusted && certCount > 0) {
                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) { // 0 is a leaf certificate
                        if let publicKey = SecCertificateCopyKey(serverCertificate) {
                            var error: Unmanaged<CFError>?
                            if let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
                                var keyWithHeader = Data(rsa2048Asn1Header)
                                keyWithHeader.append(publicKeyData)
                                let digest = SHA256.hash(data: keyWithHeader)
                                let digestString = Data(digest).base64EncodedString()
                                
                                if serverPublicKeysHashes.contains(digestString) {
                                    // Pinning successfull
                                    os_log("Public key pinning successful for %@", challenge.protectionSpace.host)
                                    completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust: serverTrust))
                                    return
                                } else {
                                    
                                    AppDelegate.returnedPublicKeyHash = digestString
                                    
                                    os_log("Public key pinning failed for %@, returned Hash:- %@", challenge.protectionSpace.host, digestString)
                                }
                            }
                        }
                    }
                }
            }
        }
        // Pinning failed
        os_log("Public key pinning challenge failed: %@ ", challenge.protectionSpace.host)
        completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
    }
}


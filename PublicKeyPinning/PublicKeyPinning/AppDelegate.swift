//
//  AppDelegate.swift
//  PublicKeyPinning
//
//  Created by Anwesh M on 29/11/21.
//

import Cocoa
import OSLog

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet var window: NSWindow!
    @IBOutlet weak var label: NSTextField!
    @IBOutlet weak var urltextField: NSTextField!
    @IBOutlet weak var publicKeyhashTextField: NSTextField!
    @IBOutlet weak var serverPublicKeyLabel: NSTextField!
    
    static var returnedPublicKeyHash = ""

    func applicationDidFinishLaunching(_ aNotification: Notification) {
       
    }
    
    @IBAction func verifyButtonAction(_ sender: Any) {
        serverPublicKeyLabel.stringValue = ""
        performPublicKeyPinning()
    }
    
    func printReturnedPublicKeyHash(){
        serverPublicKeyLabel.stringValue = "Public key returned for \(urltextField.stringValue) is \(AppDelegate.returnedPublicKeyHash)"
    }
    
    

    func performPublicKeyPinning() {
        label.stringValue = "Performing Public Key pinning..."
        let url = urltextField.stringValue
        let publicKeyHash = publicKeyhashTextField.stringValue
        
        let completionHandler = { [self] (status: Bool, error: Error?) in
            if status{
                os_log("Public Key Pinning Successful")
                // Proceed for further operations
                label.stringValue = "Public Key Pinning for \(url) is Success"
            }
            else{
                label.stringValue = "PublicKeyPinning Failed for \(url)"
                guard let err = error as? URLError else{
                    return
                }
                guard err.code  == URLError.Code.cancelled else{
                    if error!.localizedDescription == "The Internet connection appears to be offline."{
                       os_log("No internet available")
                        label.stringValue = "No internet connection"
                    }
                    else{
                        if err.code == .unsupportedURL{
                            label.stringValue = "Please enter a valid URL example: https://github.com"
                            return
                        }
                        
                        os_log("Public key pinning failed")
                        label.stringValue = err.localizedDescription
                    }
                    return
                }
                printReturnedPublicKeyHash()
                os_log("Authenticity of server is not established")
                label.stringValue = "PublicKeyPinning Failed because public key returned from \(url) not matches with given public key \(publicKeyHash)"
            }
        }

        PublicKeyPinning.verifyPublicKey(url: url, serverPublicKeysHashes: [publicKeyHash], completionHandler: completionHandler)
    }
}


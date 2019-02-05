//
//  ViewControllerX.swift
//  002 - Credit Card Checkout
//
//  Created by Mark Moeykens on 1/4/17.
//  Copyright © 2017 Moeykens. All rights reserved.
//

import UIKit

@IBDesignable
class UIViewControllerX: UIViewController {
    
    @IBInspectable var lightStatusBar: Bool = false
    
    override var preferredStatusBarStyle: UIStatusBarStyle {
        get {
            if lightStatusBar {
                return UIStatusBarStyle.lightContent
            } else {
                return UIStatusBarStyle.default
            }
        }
    }
}

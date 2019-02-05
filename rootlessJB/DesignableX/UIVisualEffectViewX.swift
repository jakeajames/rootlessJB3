//
//  UIVisualEffectViewX.swift
//  DesignableXTesting
//
//  Created by Mark Moeykens on 2/3/17.
//  Copyright © 2017 Moeykens. All rights reserved.
//

import UIKit

class UIVisualEffectViewX: UIVisualEffectView {

    // MARK: - Border
    
    @IBInspectable public var borderColor: UIColor = UIColor.clear {
        didSet {
            layer.borderColor = borderColor.cgColor
        }
    }
    
    @IBInspectable public var borderWidth: CGFloat = 0 {
        didSet {
            layer.borderWidth = borderWidth
        }
    }
    
    @IBInspectable public var cornerRadius: CGFloat = 0 {
        didSet {
            layer.cornerRadius = cornerRadius
            if cornerRadius > 0 {
                clipsToBounds = true
            } else {
                clipsToBounds = false
            }
        }
    }
}

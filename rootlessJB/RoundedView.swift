//
//  RoundedView.swift
//  Ignition
//
//  Created by Ignition on 5/8/18.
//  Copyright © 2018 Ignition. All rights reserved.
//

import Foundation
import UIKit

@IBDesignable class RoundedImage: UIImageView
{
    override func layoutSubviews() {
        super.layoutSubviews()
        
        updateCornerRadius()
    }
    
    @IBInspectable var rounded: Bool = false {
        didSet {
            updateCornerRadius()
        }
    }
    
    @IBInspectable var cornerRadius: CGFloat = 0.1 {
        didSet {
            updateCornerRadius()
        }
    }
    
    func updateCornerRadius() {
        layer.cornerRadius = rounded ? cornerRadius : 0
        layer.masksToBounds = rounded ? true : false
    }
}

@IBDesignable class RoundedView: UIView
{
    override func layoutSubviews() {
        super.layoutSubviews()
        
        updateCornerRadius()
    }
    
    @IBInspectable var rounded: Bool = false {
        didSet {
            updateCornerRadius()
        }
    }
    
    @IBInspectable var cornerRadius: CGFloat = 0.1 {
        didSet {
            updateCornerRadius()
        }
    }
    
    func updateCornerRadius() {
        layer.cornerRadius = rounded ? cornerRadius : 0
        layer.masksToBounds = rounded ? true : false
    }
}

@IBDesignable class RoundedVisualEffectView: UIVisualEffectView
{
    override func layoutSubviews() {
        super.layoutSubviews()
        
        updateCornerRadius()
    }
    
    @IBInspectable var rounded: Bool = false {
        didSet {
            updateCornerRadius()
        }
    }
    
    @IBInspectable var cornerRadius: CGFloat = 0.1 {
        didSet {
            updateCornerRadius()
        }
    }
    
    func updateCornerRadius() {
        layer.cornerRadius = rounded ? cornerRadius : 0
        layer.masksToBounds = rounded ? true : false
    }
}

@IBDesignable class RoundedButton: UIButton
{
    override func layoutSubviews() {
        super.layoutSubviews()
        
        updateCornerRadius()
    }
    
    @IBInspectable var rounded: Bool = false {
        didSet {
            updateCornerRadius()
        }
    }
    
    @IBInspectable var cornerRadius: CGFloat = 0.1 {
        didSet {
            updateCornerRadius()
        }
    }
    
    func updateCornerRadius() {
        layer.cornerRadius = rounded ? cornerRadius : 0
        layer.masksToBounds = rounded ? true : false
    }
}

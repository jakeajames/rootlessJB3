//
//  ViewController.swift
//  Samaritan
//
//  Created by Ben Mitchell on 09/11/2018.
//  Copyright © 2018 Libr8. All rights reserved.
//

import UIKit

class Gradient: UIViewController {
    override var preferredStatusBarStyle: UIStatusBarStyle {
        return .lightContent
    }
    
    //gradient
    var colorArray: [(color1: UIColor, color2: UIColor)] = []
    @IBOutlet weak var gradientView: UIViewX!
    var currentColorArrayIndex = -1
    //gradient
    override func viewDidLoad() {
        super.viewDidLoad()
        //gradient
        colorArray.append((color1: UIColor(red: 156/255, green: 39/255, blue: 176/255, alpha: 1.0) , color2:UIColor(red: 255/255, green: 64/255, blue: 129/255, alpha: 1.0)))
        colorArray.append((UIColor(red: 123/255, green: 31/255, blue: 162/255, alpha: 1.0) , color2:UIColor(red: 32/255, green: 76/255, blue: 255/255, alpha: 1.0)))
        colorArray.append((color1: UIColor(red: 32/255, green: 158/255, blue: 255/255, alpha: 1.0) , color2: UIColor(red: 90/255, green: 120/255, blue: 127/255, alpha: 1.0)))
        
        animateBackgroundColor()
        //gradient
    }
    //gradient
    func animateBackgroundColor() {
        currentColorArrayIndex = currentColorArrayIndex == (colorArray.count - 1) ? 0 : currentColorArrayIndex + 1
        
        UIView.transition(with: gradientView, duration: 1.5, options: [.transitionCrossDissolve], animations: {
            self.gradientView.firstColor = self.colorArray[self.currentColorArrayIndex].color1
            self.gradientView.secondColor = self.colorArray[self.currentColorArrayIndex].color2
        }) { (success) in
            self.animateBackgroundColor()
        }
    }
    //gradient
    
}


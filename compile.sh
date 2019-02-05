#!/bin/bash
echo "[*] Compiling rootlessJB.."
$(which xcodebuild) clean build -sdk `xcrun --sdk iphoneos --show-sdk-path` -arch arm64
mv build/Release-iphoneos/rootlessJB.app rootlessJB.app
mkdir Payload
mv rootlessJB.app Payload/rootlessJB.app
echo "[*] Zipping into .ipa"
zip -r9 rootlessJB.ipa Payload/rootlessJB.app
rm -rf build Payload
echo "[*] Done! Install .ipa with Impactor"

# Description

Blah blah, read this: [How to make a jailbreak without a filesystem remount as r/w](https://github.com/jakeajames/rootlessJB/blob/master/writeup.pdf)

- Powered by jelbrekLib


## Support

- All A9-A11 devices
- iPad Air 2

## To be supported (sorted by priority)

- 4K devices whose kernels got symbols
- Rest of 4K devices
- A12 devices

**DO NOT ASK FOR ETA**

## Usage notes

- voucher_swap is used for 16K devices, and v3ntex for 4K ones.
- Binaries are located in: /var/containers/Bundle/iosbinpack64
- Launch daemons are located in /var/containers/Bundle/iosbinpack64/LaunchDaemons
- /var/containers/Bundle/tweaksupport contains a filesystem simulation where tweaks and stuff get installed
- Symlinks include: /var/LIB, /var/ulb, /var/bin, /var/sbin, /var/Apps, /var/libexec

All executables must have at least these two entitlements:

    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>platform-application</key>
        <true/>
        <key>com.apple.private.security.container-required</key>
        <false/>
    </dict>
    </plist>


- Tweaks and stuff get installed in: /var/containers/Bundle/tweaksupport the same way you did with Electra betas.
- Tweaks must be patched using the patcher script provided. (Mac/Linux/iOS only) or manually with a hex editor
- Apps get installed in /var/Apps and later you need to run /var/containers/Bundle/iosbinpack64/usr/bin/uicache (other uicache binaries won't work)

# iOS 12
- No amfid patch, either run "inject /path/to/executable_or_dylib" after adding stuff, or reboot and rejailbreak
- Sandbox exceptions are broken. You can't tweak App Store apps + some system apps yet. However, on the app's second run the backup sandbox patches will have triggered and you'll be able to read from the tweak directories. Tweaking will still not work on the second run unless you run jailbreakd's fixupdylib() on the target dylibs manually.
- PreferenceLoader is broken, I suspect the preference bundles are some special kind of macho which amfid can understand but not the trustcache injector.
- This is not dangerous and cannot screw you up but not likely to be unstable/buggy
- Tweaks pre-patched for rootlessJB 1.0 and 2.0 will not work. Use new patcher script. (ldid was replaced with ldid2!)

patcher usage:
./patcher /path/to/deb /path/to/output_folder

Thanks to: Ian Beer, Brandon Azad, Jonathan Levin, Electra Team, IBSparkes, Sam Bingner, Sammy Guichelaar.



# Information about this particular fork

- I've removed Dropbear... Sorry, I prefer OpenSSH.
- OpenSSH v7.9p1 is the version that has been compiled with customizations to support a rootless JB.
  - Primarily paths have been conditionally prepended with /var where necessary
  - Some defaults for binaries were moved to `/var/usr/bin` instead of places like `/usr/libexec` and `/usr/local/bin` and `/usr/bin`
- sftp/scp/ssh/sshd/ssh-keygen etc et al work as they should.
- The default sshd_config is located at `/var/etc/ssh/sshd_config` and has been pre-baked with _NO_ password authentication to protect those rootless folks unable to change the default user/root password from 'alpine'.
  - Instead of password auth, pubkey auth is used.
  - The private key is located at `rootlessJB/bootstrap/bins/id_rsa_rjb3` next to the public key.
  - If your device already has a `/var/root/.ssh/authorized_keys` file, it will not be overwritten.
  - If your device already has a `/var/mobile/.ssh/authorized_keys` file, it will not be overwritten.
  - Otherwise `rootlessJB/bootstrap/bins/id_rsa_rjb3.pub` will be added to a new `<user>/.ssh/authorized_keys` file for you.
  - Make sure that you `ssh -i LOCATION_OF/rootlessJB/bootstrap/bins/id_rsa_rjb3 root@YOUR_DEVICE_IP` or simply add it to your `~/.ssh` and modifiy your `~/.ssh/config` accordingly.
- The UI logging has also been fixed/upgraded/copied shamelessly from unc0ver/Undecimus. Thank you @sbingner and @Pwn20wnd and unc0ver team

# Description

Blah blah, read this: [How to make a jailbreak without a filesystem remount as r/w](https://github.com/jakeajames/rootlessJB/blob/master/writeup.pdf)

- Powered by jelbrekLib


## Support

- All A9-A11 devices
- All A7-A8 devices

## To be supported (sorted by priority)

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
- amfid is patched, however it'll require you to resign everything with a cert. Use `codesign -s 'IDENTITY' --entitlements /path/to/entitlements.xml --force /path/to/binary` **or** inject everything as usual. However note that soon I won't be injecting stuff automatically on jailbreak anymore!
- You **can** tweak App Store apps, but you'll either have to call jailbreakd's fixMmap() yourself **or** resign things with a real cert and amfid will handle that for you. Second option is preferred. See previous point on how to.
- This is not dangerous and cannot screw you up.
- Tweaks pre-patched for rootlessJB 1.0 and 2.0 will not work. Use new patcher script. (ldid was replaced with ldid2!)

patcher usage:
./patcher /path/to/deb /path/to/output_folder

Thanks to: Ian Beer, Brandon Azad, Jonathan Levin, Electra Team, IBSparkes, Sam Bingner, Sammy Guichelaar.



//
//  ViewController.m
//  rootlessJB
//
//  Created by Jake James on 8/28/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import "ViewController.h"
#import "jelbrekLib.h"
#import "exploit/voucher_swap/voucher_swap.h"
#import "libjb.h"
#import "payload.h"
#import "offsetsDump.h"
#import "exploit/voucher_swap/kernel_slide.h"
#import "insert_dylib.h"
#import "vnode.h"

#import <mach/mach.h>
#import <sys/stat.h>

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UISwitch *enableTweaks;
@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;
@property (weak, nonatomic) IBOutlet UISwitch *installiSuperSU;

@property (weak, nonatomic) IBOutlet UITextView *logs;
@end

@implementation ViewController

-(void)log:(NSString*)log {
    self.logs.text = [NSString stringWithFormat:@"%@%@", self.logs.text, log];
}

#define LOG(what, ...) [self log:[NSString stringWithFormat:@what"\n", ##__VA_ARGS__]];\
printf("\t"what"\n", ##__VA_ARGS__)

#define in_bundle(obj) strdup([[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@obj] UTF8String])

#define failIf(condition, message, ...) if (condition) {\
LOG(message);\
goto end;\
}
#define maxVersion(v)  ([[[UIDevice currentDevice] systemVersion] compare:@v options:NSNumericSearch] != NSOrderedDescending)


#define fileExists(file) [[NSFileManager defaultManager] fileExistsAtPath:@(file)]
#define removeFile(file) if (fileExists(file)) {\
[[NSFileManager defaultManager]  removeItemAtPath:@(file) error:&error]; \
if (error) { \
LOG("[-] Error: removing file %s (%s)", file, [[error localizedDescription] UTF8String]); \
error = NULL; \
}\
}

#define copyFile(copyFrom, copyTo) [[NSFileManager defaultManager] copyItemAtPath:@(copyFrom) toPath:@(copyTo) error:&error]; \
if (error) { \
LOG("[-] Error copying item %s to path %s (%s)", copyFrom, copyTo, [[error localizedDescription] UTF8String]); \
error = NULL; \
}

#define moveFile(copyFrom, moveTo) [[NSFileManager defaultManager] moveItemAtPath:@(copyFrom) toPath:@(moveTo) error:&error]; \
if (error) {\
LOG("[-] Error moviing item %s to path %s (%s)", copyFrom, moveTo, [[error localizedDescription] UTF8String]); \
error = NULL; \
}

int system_(char *cmd) {
    return launch("/var/bin/bash", "-c", cmd, NULL, NULL, NULL, NULL, NULL);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (IBAction)jailbrek:(id)sender {
    //---- tfp0 ----//
    mach_port_t taskforpidzero = MACH_PORT_NULL;
    
    uint64_t sb = 0;
    BOOL debug = NO; // kids don't enable this
    
    // for messing with files
    NSError *error = NULL;
    NSArray *plists;
    
    if (debug) {
        kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskforpidzero);
        if (ret) {
            printf("[-] Error using hgsp! '%s'\n", mach_error_string(ret));
            printf("[*] Using exploit!\n");
            
            if (maxVersion("12.1.2")) {
                taskforpidzero = voucher_swap();
            }
            else {
                [sender setTitle:@"Not supported!" forState:UIControlStateNormal];
                [sender setEnabled:false];
                return;
            }
            if (!MACH_PORT_VALID(taskforpidzero)) {
                LOG("[-] Exploit failed");
                LOG("[i] Please try again");
                sleep(1);
                return;
            }
        }
    }
    else {
        if (maxVersion("12.1.2")) {
            taskforpidzero = voucher_swap();
        }
        else {
            [sender setTitle:@"Not supported!" forState:UIControlStateNormal];
            [sender setEnabled:false];
            return;
        }
        if (!MACH_PORT_VALID(taskforpidzero)) {
            LOG("[-] Exploit failed");
            LOG("[i] Please try again");
            sleep(1);
            return;
        }
    }
    
    LOG("[*] Starting fun");
    
    kernel_slide_init();
    init_with_kbase(taskforpidzero, 0xfffffff007004000 + kernel_slide);
    
    LOG("[i] Kernel base: 0x%llx", KernelBase);
    
    //---- basics ----//
    rootify(getpid()); // give us root
    failIf(getuid(), "[-] Failed to get root");
    LOG("[i] uid: %d\n", getuid());
    
    sb = unsandbox(getpid()); // escape sandbox
    FILE *f = fopen("/var/mobile/.roottest", "w");
    failIf(!f, "[-] Failed to escape sandbox!");
    
    LOG("[+] Escaped sandbox!\n\tWrote file %p", f);
    fclose(f);
    removeFile("/var/mobile/.roottest");
    
    setcsflags(getpid()); // set some csflags
    platformize(getpid()); // set TF_PLATFORM
    
    //---- host special port 4 ----//
    failIf(setHSP4(), "[-] Failed to set tfp0 as hsp4!");
    if (debug) PatchHostPriv(mach_host_self());
    
    //---- remount -----//
    // this is against the point of this jb but if you can why not do it
    
    if (maxVersion("11.4.1")) {
        if (remountRootFS()) LOG("[-] Failed to remount rootfs, no big deal");
    }
    
    //---- nvram ----//
    // people say that this ain't stable
    // and that ya should lock it later
    // but, I haven't experienced issues
    // nor so rootlessJB people
    
    UnlockNVRAM(); // use nvram command for nonce setting!
    
    //---- bootstrap ----//
    if (!fileExists("/var/containers/Bundle/.installed_rootlessJB3")) {
        
        LOG("[*] Uninstalling previous build...");

        if(fileExists("/var/LIB")) removeFile("/var/LIB");
        if(fileExists("/var/ulb")) removeFile("/var/ulb");
        if(fileExists("/var/bin")) removeFile("/var/bin");
        if(fileExists("/var/sbin")) removeFile("/var/sbin");
        if(fileExists("/var/containers/Bundle/tweaksupport/Applications")) removeFile("/var/containers/Bundle/tweaksupport/Applications");
        if(fileExists("/var/Apps")) removeFile("/var/Apps");
        if(fileExists("/var/profile")) removeFile("/var/profile");
        if(fileExists("/var/motd")) removeFile("/var/motd");
        if(fileExists("/var/dropbear")) removeFile("/var/dropbear");
        if(fileExists("/var/containers/Bundle/tweaksupport")) removeFile("/var/containers/Bundle/tweaksupport");
        if(fileExists("/var/containers/Bundle/iosbinpack64")) removeFile("/var/containers/Bundle/iosbinpack64");
        if(fileExists("/var/containers/Bundle/dylibs")) removeFile("/var/containers/Bundle/dylibs");
        if(fileExists("/var/log/testbin.log")) removeFile("/var/log/testbin.log");

        if (fileExists("/var/log/jailbreakd-stdout.log")) removeFile("/var/log/jailbreakd-stdout.log");
        if (fileExists("/var/log/jailbreakd-stderr.log")) removeFile("/var/log/jailbreakd-stderr.log");

        LOG("[*] Installing bootstrap...");
        
        chdir("/var/containers/Bundle/");
        FILE *bootstrap = fopen((char*)in_bundle("tars/iosbinpack.tar"), "r");
        untar(bootstrap, "/var/containers/Bundle/");
        fclose(bootstrap);
        
        FILE *tweaks = fopen((char*)in_bundle("tars/tweaksupport.tar"), "r");
        untar(tweaks, "/var/containers/Bundle/");
        fclose(tweaks);
        
        failIf(!fileExists("/var/containers/Bundle/tweaksupport") || !fileExists("/var/containers/Bundle/iosbinpack64"), "[-] Failed to install bootstrap");
        
        LOG("[+] Creating symlinks...");
        
        symlink("/var/containers/Bundle/tweaksupport/Library", "/var/LIB");
        symlink("/var/containers/Bundle/tweaksupport/usr/lib", "/var/ulb");
        symlink("/var/containers/Bundle/tweaksupport/Applications", "/var/Apps");
        symlink("/var/containers/Bundle/tweaksupport/bin", "/var/bin");
        symlink("/var/containers/Bundle/tweaksupport/sbin", "/var/sbin");
        symlink("/var/containers/Bundle/tweaksupport/usr/libexec", "/var/libexec");
        
        close(open("/var/containers/Bundle/.installed_rootlessJB3", O_CREAT));
        
        LOG("[+] Installed bootstrap!");
    }
    
    //---- for jailbreakd & amfid ----//
    failIf(dumpOffsetsToFile("/var/containers/Bundle/tweaksupport/offsets.data"), "[-] Failed to save offsets");
    
    
    //---- update jailbreakd ----//
    
    removeFile("/var/containers/Bundle/tweaksupport/bin/jailbreakd");
    
    if (!fileExists(in_bundle("bins/jailbreakd"))) {
        chdir(in_bundle("bins/"));
        
        FILE *jbd = fopen(in_bundle("bins/jailbreakd.tar"), "r");
        untar(jbd, in_bundle("bins/jailbreakd"));
        fclose(jbd);
        
        removeFile(in_bundle("bins/jailbreakd.tar"));
    }
    
    copyFile(in_bundle("bins/jailbreakd"), "/var/containers/Bundle/iosbinpack64/bin/jailbreakd");
    
    //---- codesign patch ----//
    
    if (!fileExists(in_bundle("bins/tester"))) {
        chdir(in_bundle("bins/"));
        
        FILE *f1 = fopen(in_bundle("bins/tester.tar"), "r");
        untar(f1, in_bundle("bins/tester"));
        fclose(f1);
        
        removeFile(in_bundle("bins/tester.tar"));
    }
    
    chmod(in_bundle("bins/tester"), 0777); // give it proper permissions
    
    if (launch(in_bundle("bins/tester"), NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
        failIf(trustbin("/var/containers/Bundle/iosbinpack64"), "[-] Failed to trust binaries!");
        failIf(trustbin("/var/containers/Bundle/tweaksupport"), "[-] Failed to trust binaries!");
        
        // test
        int ret = launch("/var/containers/Bundle/iosbinpack64/test", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        failIf(ret, "[-] Failed to trust binaries!");
        LOG("[+] Successfully trusted binaries!");
    }
    else {
        LOG("[+] binaries already trusted?");
    }
    
    //---- let's go! ----//
    
    prepare_payload(); // this will chmod 777 everything
    
    //----- setup SSH -----//
    mkdir("/var/dropbear", 0777);
    removeFile("/var/profile");
    removeFile("/var/motd");
    chmod("/var/profile", 0777);
    chmod("/var/motd", 0777);
    
    copyFile("/var/containers/Bundle/iosbinpack64/etc/profile", "/var/profile");
    copyFile("/var/containers/Bundle/iosbinpack64/etc/motd", "/var/motd");
    copyFile("/var/containers/Bundle/iosbinpack64/usr/bin/scp", "/var/bin/scp");

    // kill it if running
    launch("/var/containers/Bundle/iosbinpack64/usr/bin/killall", "-SEGV", "dropbear", NULL, NULL, NULL, NULL, NULL);
    LOG("[?] launching SSH...");
    failIf(launchAsPlatform("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear", "-R", "--shell", "/var/containers/Bundle/iosbinpack64/bin/bash", "-E", "-p", "22", NULL), "[-] Failed to launch dropbear");
    LOG("[*] SSH started successfully");

    //------------- launch daeamons -------------//
    //-- you can drop any daemon plist in iosbinpack64/LaunchDaemons and it will be loaded automatically --//
    
    plists = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/iosbinpack64/LaunchDaemons" error:nil];
    
    for (__strong NSString *file in plists) {
        printf("[*] Adding permissions to plist %s\n", [file UTF8String]);
        
        file = [@"/var/containers/Bundle/iosbinpack64/LaunchDaemons" stringByAppendingPathComponent:file];
        
        if (strstr([file UTF8String], "jailbreakd")) {
            printf("[*] Found jailbreakd plist, special handling\n");
            
            NSMutableDictionary *job = [NSPropertyListSerialization propertyListWithData:[NSData dataWithContentsOfFile:file] options:NSPropertyListMutableContainers format:nil error:nil];
            
            job[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@"0x%16llx", KernelBase];
            [job writeToFile:file atomically:YES];
        }
        
        chmod([file UTF8String], 0644);
        chown([file UTF8String], 0, 0);
    }
    
    // clean up
    removeFile("/var/log/testbin.log");
    removeFile("/var/log/jailbreakd-stderr.log");
    removeFile("/var/log/jailbreakd-stdout.log");
    
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "unload", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "load", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);
    
    sleep(1);
    
    failIf(!fileExists("/var/log/testbin.log"), "[-] Failed to load launch daemons");
    failIf(!fileExists("/var/log/jailbreakd-stdout.log"), "[-] Failed to load jailbreakd");
    
    if (self.enableTweaks.isOn) {
        
        //----- magic start here -----//
        LOG("[*] Time for magic");
        
        char *xpcproxy = "/var/libexec/xpcproxy";
        char *dylib = "/var/ulb/pspawn.dylib";
        
        if (!fileExists(xpcproxy)) {
            bool cp = copyFile("/usr/libexec/xpcproxy", xpcproxy);
            failIf(!cp, "[-] Can't copy xpcproxy!");
            symlink("/var/containers/Bundle/iosbinpack64/pspawn.dylib", dylib);
            
            LOG("[*] Patching xpcproxy");
            
            const char *args[] = { "insert_dylib", "--all-yes", "--inplace", "--overwrite", dylib, xpcproxy, NULL};
            int argn = 6;
            
            failIf(add_dylib(argn, args), "[-] Failed to patch xpcproxy :(");
            
            LOG("[*] Resigning xpcproxy");
            
            failIf(system_("/var/containers/Bundle/iosbinpack64/usr/local/bin/jtool --sign --inplace /var/libexec/xpcproxy"), "[-] Failed to resign xpcproxy!");
        }
        
        chown(xpcproxy, 0, 0);
        chmod(xpcproxy, 755);
        failIf(trustbin(xpcproxy), "[-] Failed to trust xpcproxy!");
        
        uint64_t realxpc = getVnodeAtPath("/usr/libexec/xpcproxy");
        uint64_t fakexpc = getVnodeAtPath(xpcproxy);
        
        struct vnode rvp, fvp;
        KernelRead(realxpc, &rvp, sizeof(struct vnode));
        KernelRead(fakexpc, &fvp, sizeof(struct vnode));
        
        fvp.v_usecount = rvp.v_usecount;
        fvp.v_kusecount = rvp.v_kusecount;
        fvp.v_parent = rvp.v_parent;
        fvp.v_freelist = rvp.v_freelist;
        fvp.v_mntvnodes = rvp.v_mntvnodes;
        fvp.v_ncchildren = rvp.v_ncchildren;
        fvp.v_nclinks = rvp.v_nclinks;
        
        KernelWrite(realxpc, &fvp, sizeof(struct vnode)); // :o
        
        // kernel is smart enough not to fall for a fake amfid :(
        /*char *amfid = "/var/libexec/amfid";
         dylib = "/var/ulb/amfid.dylib";
         
         if (!fileExists(amfid)) {
         bool cp = copyFile("/usr/libexec/amfid", amfid);
         failIf(!cp, "[-] Can't copy xpcproxy!");
         symlink("/var/containers/Bundle/iosbinpack64/amfid_payload.dylib", dylib);
         
         LOG("[*] Patching amfid");
         
         const char *args[] = { "insert_dylib", "--all-yes", "--inplace", "--overwrite", dylib, amfid, NULL};
         int argn = 6;
         failIf(add_dylib(argn, args), "[-] Failed to patch amfid :(");
         
         LOG("[*] Resigning amfid");
         
         failIf(system_("/var/containers/Bundle/iosbinpack64/usr/local/bin/jtool --sign --inplace /var/libexec/amfid"), "[-] Failed to resign amfid!");
         }
         
         chown(amfid, 0, 0);
         chmod(amfid, 755);
         failIf(trustbin(amfid), "[-] Failed to trust amfid!");
         
         realxpc = getVnodeAtPath("/usr/libexec/amfid");
         fakexpc = getVnodeAtPath(amfid);
         
         KernelRead(realxpc, &rvp, sizeof(struct vnode));
         KernelRead(fakexpc, &fvp, sizeof(struct vnode));
         
         fvp.v_usecount = rvp.v_usecount;
         fvp.v_kusecount = rvp.v_kusecount;
         fvp.v_parent = rvp.v_parent;
         fvp.v_freelist = rvp.v_freelist;
         fvp.v_mntvnodes = rvp.v_mntvnodes;
         fvp.v_ncchildren = rvp.v_ncchildren;
         fvp.v_nclinks = rvp.v_nclinks;
         
         KernelWrite(realxpc, &fvp, 248);
         
         LOG("[?] Are we still alive?!");*/
        
        //----- magic end here -----//
        
        // cache pid and we're done
        pid_t installd = pid_of_procName("installd");
        pid_t bb = pid_of_procName("backboardd");

        // AppSync
        
        fixMmap("/var/ulb/libsubstitute.dylib");
        fixMmap("/var/LIB/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        fixMmap("/var/LIB/MobileSubstrate/DynamicLibraries/AppSyncUnified.dylib");
        
        if (installd) kill(installd, SIGKILL);
        
        if ([self.installiSuperSU isOn]) {
            LOG("[*] Installing iSuperSU");
            
            removeFile("/var/containers/Bundle/tweaksupport/Applications/iSuperSU.app");
            copyFile(in_bundle("apps/iSuperSU.app"), "/var/containers/Bundle/tweaksupport/Applications/iSuperSU.app");
            
            failIf(system_("/var/containers/Bundle/tweaksupport/usr/local/bin/jtool --sign --inplace --ent /var/containers/Bundle/tweaksupport/Applications/iSuperSU.app/ent.xml /var/containers/Bundle/tweaksupport/Applications/iSuperSU.app/iSuperSU && /var/containers/Bundle/tweaksupport/usr/bin/inject /var/containers/Bundle/tweaksupport/Applications/iSuperSU.app/iSuperSU"), "[-] Failed to sign iSuperSU");
            
            
            // just in case
            fixMmap("/var/ulb/libsubstitute.dylib");
            fixMmap("/var/LIB/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
            fixMmap("/var/LIB/MobileSubstrate/DynamicLibraries/AppSyncUnified.dylib");
            
            failIf(launch("/var/containers/Bundle/tweaksupport/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL, NULL, NULL), "[-] Failed to install iSuperSU");
        }
        
        LOG("[+] Really jailbroken!");
        term_jelbrek();
        
        // bye bye
        kill(bb, 9);
        //launch("/var/containers/Bundle/iosbinpack64/bin/bash", "-c", "/var/containers/Bundle/iosbinpack64/usr/bin/nohup /var/containers/Bundle/iosbinpack64/bin/bash -c \"/var/containers/Bundle/iosbinpack64/bin/launchctl unload /System/Library/LaunchDaemons/com.apple.backboardd.plist && /var/containers/Bundle/iosbinpack64/usr/bin/ldrestart; /var/containers/Bundle/iosbinpack64/bin/launchctl load /System/Library/LaunchDaemons/com.apple.backboardd.plist\" 2>&1 >/dev/null &", NULL, NULL, NULL, NULL, NULL);
        exit(0);
    }
    
    /// FIX THIS
    /*
     pid_t installd = pid_of_procName("installd");
     failIf(!installd, "[-] Can't find installd's pid");
     
     failIf(!setcsflags(installd), "[-] Failed to entitle installd");
     failIf(!entitlePidOnAMFI(installd, "get-task-allow", true), "[-] Failed to entitle installd");
     failIf(!entitlePidOnAMFI(installd, "com.apple.private.skip-library-validation", true), "[-] Failed to entitle installd");
     
     inject_dylib(installd, "/var/containers/Bundle/tweaksupport/usr/lib/TweakInject/AppSyncUnified.dylib");
     
     if ([self.installiSuperSU isOn]) {
     LOG("[*] Installing iSuperSU");
     copyFile(in_bundle("apps/iSuperSU.app"), "/var/containers/Bundle/tweaksupport/Applications/iSuperSU.app");
     launch("/var/containers/Bundle/tweaksupport/usr/bin/uicache", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
     } */
    
    LOG("[+] Jailbreak succeeded. Enjoy");
    
end:;
    
    if (sb) sandbox(getpid(), sb);
    term_jelbrek();
}
- (IBAction)uninstall:(id)sender {
    //---- tfp0 ----//
    mach_port_t taskforpidzero = MACH_PORT_NULL;
    
    uint64_t sb = 0;
    BOOL debug = NO; // kids don't enable this
    
    NSError *error = NULL;
    
    if (debug) {
        kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskforpidzero);
        if (ret) {
            printf("[-] Error using hgsp! '%s'\n", mach_error_string(ret));
            printf("[*] Using exploit!\n");
            
            if (maxVersion("12.1.2")) {
                taskforpidzero = voucher_swap();
            }
            else {
                
            }
            
            if (!MACH_PORT_VALID(taskforpidzero)) {
                LOG("[-] Exploit failed");
                LOG("[i] Please try again");
                sleep(1);
                return;
            }
        }
    }
    else {
        if (maxVersion("12.1.2")) {
            taskforpidzero = voucher_swap();
        }
        else {
            
        }
        
        if (!MACH_PORT_VALID(taskforpidzero)) {
            LOG("[-] Exploit failed");
            LOG("[i] Please try again");
            sleep(1);
            return;
        }
    }
    LOG("[*] Starting fun");
    
    if (!maxVersion("11.4.1") && maxVersion("12.1.2")) {
        kernel_slide_init();
        init_with_kbase(taskforpidzero, 0xfffffff007004000 + kernel_slide);
    }
    else if (maxVersion("11.3.1")) {
        init_jelbrek(taskforpidzero);
    }
    
    LOG("[i] Kernel base: 0x%llx", KernelBase);
    
    //---- basics ----//
    rootify(getpid()); // give us root
    LOG("[i] uid: %d\n", getuid());
    failIf(getuid(), "[-] Failed to get root");
    
    sb = unsandbox(getpid()); // escape sandbox
    FILE *f = fopen("/var/mobile/.roottest", "w");
    failIf(!f, "[-] Failed to escape sandbox!");
    
    LOG("[+] Escaped sandbox!\n\tWrote file %p", f);
    fclose(f);
    removeFile("/var/mobile/.roottest");
    
    setcsflags(getpid()); // set some csflags
    platformize(getpid()); // set TF_PLATFORM
    
    if (debug) setHSP4();
    if (debug) PatchHostPriv(mach_host_self());
    
    LOG("[*] Uninstalling...");
    
    failIf(!fileExists("/var/containers/Bundle/.installed_rootlessJB3"), "[-] rootlessJB was never installed before! (this version of it)");
    
    removeFile("/var/LIB");
    removeFile("/var/ulb");
    removeFile("/var/bin");
    removeFile("/var/sbin");
    removeFile("/var/libexec");
    removeFile("/var/containers/Bundle/tweaksupport/Applications");
    removeFile("/var/Apps");
    removeFile("/var/profile");
    removeFile("/var/motd");
    removeFile("/var/dropbear");
    removeFile("/var/containers/Bundle/tweaksupport");
    removeFile("/var/containers/Bundle/iosbinpack64");
    removeFile("/var/log/testbin.log");
    removeFile("/var/log/jailbreakd-stdout.log");
    removeFile("/var/log/jailbreakd-stderr.log");
    removeFile("/var/containers/Bundle/.installed_rootlessJB3");

    LOG("[*] Uninstall complete!");
end:;
    if (sb) sandbox(getpid(), sb);
    term_jelbrek();
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end


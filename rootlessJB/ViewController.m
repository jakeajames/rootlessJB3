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
#import "util.h"
#import "offsetsDump.h"
#import "exploit/voucher_swap/kernel_slide.h"
#import "insert_dylib.h"
#import "vnode.h"
#import "exploit/v3ntex/exploit.h"

#import <sys/stat.h>
#import <sys/utsname.h>

#ifdef DEBUG
#undef DEBUG
#endif

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UISwitch *enableTweaks;
@property (weak, nonatomic) IBOutlet UIButton *jailbreakButton;
@property (weak, nonatomic) IBOutlet UIButton *unJailbreakButton;
@property (weak, nonatomic) IBOutlet UISwitch *installiSuperSU;

- (void)updateOutputViewFromQueue:(NSNumber *)fromQueue;

- (void)updateOutputView;

- (void)jelbrekDun:(mach_port_t)tfp0;

- (void)uninstallJelbrekDun:(mach_port_t)tfp0;
@end

@implementation ViewController
static NSMutableString *output = nil;
static ViewController *sharedController = nil;

+ (ViewController *)sharedController {
//    static dispatch_once_t once;
//    dispatch_once(&once, ^{
//        NSLog(@"Init ViewController sharedInstance");
//        sharedController = [ViewController new];
//    });
    return sharedController;
}

- (id)init {
    @synchronized(sharedController) {
        if (sharedController == nil) {
            sharedController = (ViewController *) [super init];
        }
    }
    self = sharedController;
    return self;
}


-(void)updateOutputViewFromQueue:(NSNumber*)fromQueue {
    static BOOL updateQueued = NO;
    static struct timeval last = {0,0};
    static dispatch_queue_t updateQueue;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        updateQueue = dispatch_queue_create("updateView", NULL);
    });

    dispatch_async(updateQueue, ^{
        struct timeval now;

        if (fromQueue.boolValue) {
            updateQueued = NO;
        }

        if (updateQueued) {
            return;
        }

        if (gettimeofday(&now, NULL)) {
            LOG("gettimeofday failed");
            return;
        }

        __darwin_time_t elapsed = (now.tv_sec - last.tv_sec) * 1000000 + now.tv_usec - last.tv_usec;
        // 30 FPS
        if (elapsed > 1000000/30) {
            updateQueued = NO;
            gettimeofday(&last, NULL);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logs.text = output;
                [self.logs scrollRangeToVisible:NSMakeRange(self.logs.text.length, 0)];
            });
        } else {
            NSTimeInterval waitTime = ((1000000/30) - elapsed) / 1000000.0;
            updateQueued = YES;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self performSelector:@selector(updateOutputViewFromQueue:) withObject:@YES afterDelay:waitTime];
            });
        }
    });
}

-(void)updateOutputView {
    [self updateOutputViewFromQueue:@NO];
}

-(void)appendTextToOutput:(NSString *)text {
    if (self.logs == nil) {
        return;
    }
    static NSRegularExpression *remove = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        remove = [NSRegularExpression regularExpressionWithPattern:@"^\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\.\\d+[-\\d\\s]+\\S+\\[\\d+:\\d+\\]\\s+"
                                                           options:NSRegularExpressionAnchorsMatchLines error:nil];
        output = [NSMutableString new];
    });

    text = [remove stringByReplacingMatchesInString:text options:0 range:NSMakeRange(0, text.length) withTemplate:@""];

    @synchronized (output) {
        [output appendString:text];
    }
    [self updateOutputView];
}

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

char* dumpFile(const char* filename) {
    char * buffer = 0;
    size_t length;
    FILE * pfile = fopen (filename, "rb");

    if (pfile)
    {
        fseek (pfile, 0, SEEK_END);
        length = (size_t) ftell (pfile);
        fseek (pfile, 0, SEEK_SET);
        buffer = malloc (length);// derpfree.
        if (buffer)
        {
            fread (buffer, 1, length, pfile);
        }
        fclose (pfile);
    }
    return buffer;
}

struct utsname u;
vm_size_t psize;
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

- (void)viewDidLoad {
    [super viewDidLoad];
    
    uint32_t flags;
    csops(getpid(), 0, &flags, 0);
    
    if ((flags & 0x4000000)) { // platform
        [self.jailbreakButton setTitle:@"Jailbroken" forState:UIControlStateNormal];
        [self.jailbreakButton setEnabled:NO];
        [self.enableTweaks setEnabled:NO];
        [self.installiSuperSU setEnabled:NO];
    }

    sharedController = self;

    LOG("rootlessJB Version: %@", appVersion());
    
    uname(&u);
    if (strstr(u.machine, "iPad5,")) psize = 0x1000;
    else _host_page_size(mach_host_self(), &psize);
    LOG("%s with page size: 0x%llx", u.machine, psize);
    LOG("Logging code shamelessly lifted from @sbingner and the rest of the unc0ver team. Thank you <3");
    LOG("While uncommon, your device may reboot. If it does, simply run rootlessJB again and try %s/%s again.", [[self.jailbreakButton titleForState:UIControlStateNormal] UTF8String],[[self.unJailbreakButton titleForState:UIControlStateNormal] UTF8String] );
}

- (IBAction)jailbreak:(id)sender {
    LOG("Starting jelbrek...");
    [self.jailbreakButton setEnabled:NO];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        //---- tfp0 ----//
#ifdef DEBUG
        kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskforpidzero);
        if (ret) {
            printf("[-] Error using hgsp! '%s'\n", mach_error_string(ret));
            printf("[*] Using exploit!\n");
            
            if (psize == 0x1000 && maxVersion("12.1.2")) {
                
                // v3ntex is so bad we have to treat it specially for it not to freak out
                dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0);
                dispatch_group_t group = dispatch_group_create();
                dispatch_semaphore_t sm = dispatch_semaphore_create(0);
                
                dispatch_group_async(group, queue, ^{
                    taskforpidzero = v3ntex();
                    dispatch_semaphore_signal(sm);
                });
                
                dispatch_semaphore_wait(sm, DISPATCH_TIME_FOREVER);
            }
            
            else if (maxVersion("12.1.2")) {
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
                [self.unJailbreakButton setEnabled:YES];
                return;
            }
        }
#else
        mach_port_t taskforpidzero;
        if (psize == 0x1000 && maxVersion("12.1.2")) {
            taskforpidzero = v3ntex();
            [self jelbrekDun:taskforpidzero];
        } else if (maxVersion("12.1.2")) {
            taskforpidzero = voucher_swap();
            [self jelbrekDun:taskforpidzero];
        } else {
            [sender setTitle:@"Not supported!" forState:UIControlStateNormal];
            [sender setEnabled:false];
            [self.jailbreakButton setEnabled:YES];
            return;
        }
#endif
    });
}


-(void) jelbrekDun:(mach_port_t) tfp0  {
    LOG("TPF0: %d", tfp0);
    if (!MACH_PORT_VALID(tfp0)) {
            LOG("[-] Exploit failed");
            LOG("[i] Please try again");
            sleep(1);
            [self.jailbreakButton setEnabled:YES];
            return;
        }
    // for messing with files
    NSError *error = NULL;
    NSArray *plists;

    uint64_t sb = 0;

    LOG("[*] Starting fun");
    
    if (!KernelBase) {
        kernel_slide_init();
        init_with_kbase(tfp0, 0xfffffff007004000 + kernel_slide);
    }
    else init_with_kbase(tfp0, KernelBase);
    
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

#ifdef DEBUG
    PatchHostPriv(mach_host_self());
#endif
    
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
        
        if (fileExists("/var/containers/Bundle/iosbinpack64")) {
            
            LOG("[*] Uninstalling previous build...");
            
            removeFile("/var/LIB");
            removeFile("/var/ulb");
            removeFile("/var/bin");
            removeFile("/var/sbin");
            removeFile("/var/containers/Bundle/tweaksupport/Applications");
            removeFile("/var/Apps");
            removeFile("/var/profile");
            removeFile("/var/motd");
            removeFile("/var/dropbear");
            removeFile("/var/containers/Bundle/tweaksupport");
            removeFile("/var/containers/Bundle/iosbinpack64");
            removeFile("/var/containers/Bundle/dylibs");
            removeFile("/var/log/testbin.log");
            
            if (fileExists("/var/log/jailbreakd-stdout.log")) removeFile("/var/log/jailbreakd-stdout.log");
            if (fileExists("/var/log/jailbreakd-stderr.log")) removeFile("/var/log/jailbreakd-stderr.log");
        }
        
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

        //limneos
        symlink("/var/containers/Bundle/iosbinpack64/etc", "/var/etc");
        symlink("/var/containers/Bundle/tweaksupport/usr", "/var/usr");
        symlink("/var/containers/Bundle/iosbinpack64/usr/bin/killall", "/var/bin/killall");

        symlink("/var/containers/Bundle/iosbinpack64/usr/sbin", "/var/usr/sbin"); //kinda forgot an important one: chown etc.

        close(open("/var/containers/Bundle/.installed_rootlessJB3", O_CREAT));
        
        LOG("[+] Installed bootstrap!");
    }
    
    //---- for jailbreakd & amfid ----//
    failIf(dumpOffsetsToFile("/var/containers/Bundle/tweaksupport/offsets.data"), "[-] Failed to save offsets");
    
    //---- different tools ----//
    
    if (!fileExists("/var/bin/strings")) {
        chdir("/");
        FILE *essentials = fopen((char*)in_bundle("tars/bintools.tar"), "r");
        untar(essentials, "/");
        fclose(essentials);
        
        FILE *dpkg = fopen((char*)in_bundle("tars/dpkg-rootless.tar"), "r");
        untar(dpkg, "/");
        fclose(dpkg);
    }
   
    //---- update/remove dropbear ----//

    BOOL noDropbear = fileExists(in_bundle("tars/nodropbear.tar"));

    if(noDropbear) {
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/bin/scp");
        removeFile("/var/containers/Bundle/iosbinpack64/dropbear.plist");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/dropbear");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/dropbear.orig");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/dropbearconvert");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/dropbearkey");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dbclient");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear.orig");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbearconvert");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbearkey");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbearmulti");

        removeFile("/var/containers/Bundle/iosbinpack64/etc/profile");
        removeFile("/var/containers/Bundle/iosbinpack64/etc/motd");

        removeFile("/var/etc/ssh/sshd_config");
        removeFile("/var/etc/ssh/ssh_config");
        removeFile("/var/etc/profile");
        removeFile("/var/usr/bin/ssh-keyscan");
        removeFile("/var/usr/bin/sshd");
        removeFile("/var/usr/bin/sftp");
        removeFile("/var/usr/bin/ssh-pkcs11-helper");
        removeFile("/var/usr/bin/ssh-agent");
        removeFile("/var/usr/bin/ssh");
        removeFile("/var/usr/bin/ssh-keysign");
        removeFile("/var/usr/bin/ssh-add");
        removeFile("/var/usr/bin/ssh-keygen");
        removeFile("/var/usr/bin/sftp-server");
        removeFile("/var/usr/bin/scp");

        chdir("/var");
        FILE *nodropbear = fopen(in_bundle("tars/nodropbear.tar"), "r");
        untar(nodropbear, "/var");
        fclose(nodropbear);

        if(!fileExists("/var/etc/ssh")) mkdir("/var/etc/ssh", 0777);

        if(fileExists("/var/containers/Bundle/iosbinpack64/LaunchDaemons/jailbreakd.plist")) {
            LOG("[+] jailbreakd.plist still exists");
        } else {
            LOG("[-] ERROR: jailbreakd.plist not found");
        }
        
    } else {
        chdir("/var/containers/Bundle/");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear");
        removeFile("/var/containers/Bundle/iosbinpack64/usr/bin/scp");

        FILE *fixed_dropbear = fopen(in_bundle("tars/dropbear.v2018.76.tar"), "r");
        untar(fixed_dropbear, "/var/containers/Bundle/");
        fclose(fixed_dropbear);
    }


    //---- update jailbreakd ----//
    
    removeFile("/var/containers/Bundle/iosbinpack64/bin/jailbreakd");
    if (!fileExists(in_bundle("bins/jailbreakd"))) {
        chdir(in_bundle("bins/"));
        
        FILE *jbd = fopen(in_bundle("bins/jailbreakd.tar"), "r");
        untar(jbd, in_bundle("bins/jailbreakd"));
        fclose(jbd);
        
        removeFile(in_bundle("bins/jailbreakd.tar"));
    }
    copyFile(in_bundle("bins/jailbreakd"), "/var/containers/Bundle/iosbinpack64/bin/jailbreakd");
    
    removeFile("/var/containers/Bundle/iosbinpack64/pspawn.dylib");
    if (!fileExists(in_bundle("bins/pspawn.dylib"))) {
        chdir(in_bundle("bins/"));
        
        FILE *jbd = fopen(in_bundle("bins/pspawn.dylib.tar"), "r");
        untar(jbd, in_bundle("bins/pspawn.dylib"));
        fclose(jbd);
        
        removeFile(in_bundle("bins/pspawn.dylib.tar"));
    }
    copyFile(in_bundle("bins/pspawn.dylib"), "/var/containers/Bundle/iosbinpack64/pspawn.dylib");
    
    removeFile("/var/containers/Bundle/iosbinpack64/amfid_payload.dylib");
    if (!fileExists(in_bundle("bins/amfid_payload.dylib"))) {
        chdir(in_bundle("bins/"));
        
        FILE *jbd = fopen(in_bundle("bins/amfid_payload.dylib.tar"), "r");
        untar(jbd, in_bundle("bins/amfid_payload.dylib"));
        fclose(jbd);
        
        removeFile(in_bundle("bins/amfid_payload.dylib.tar"));
    }
    copyFile(in_bundle("bins/amfid_payload.dylib"), "/var/containers/Bundle/iosbinpack64/amfid_payload.dylib");
    
    removeFile("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");
    if (!fileExists(in_bundle("bins/TweakInject.dylib"))) {
        chdir(in_bundle("bins/"));
        
        FILE *jbd = fopen(in_bundle("bins/TweakInject.tar"), "r");
        untar(jbd, in_bundle("bins/TweakInject.dylib"));
        fclose(jbd);
        
        removeFile(in_bundle("bins/TweakInject.tar"));
    }
    copyFile(in_bundle("bins/TweakInject.dylib"), "/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");
    
    removeFile("/var/log/pspawn_payload_xpcproxy.log");
    
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
    
    //----- setup real SSH or dropbear -----//

    if(noDropbear) {
        LOG("[*] Setting up ssh");
        removeFile("/var/profile");
        removeFile("/var/bashrc");
        symlink("/var/etc/profile", "/var/profile");

        if(!fileExists("/var/root/.ssh")) {
            mkdir("/var/root/.ssh", 0700);
            chown("/var/root/.ssh", 0, 0);
        }
        if(!fileExists("/var/root/.ssh/authorized_keys")) {
            LOG("[+] Generating root ssh Keys...");
            copyFile(in_bundle("bins/id_rsa_rjb3.pub"), "/var/root/.ssh/authorized_keys");
            copyFile(in_bundle("bins/id_rsa_rjb3"), "/var/root/.ssh/id_rsa_rjb3");
            copyFile(in_bundle("bins/id_rsa_rjb3.pub"), "/var/root/.ssh/id_rsa_rjb3.pub");
            chown("/var/root/.ssh/authorized_keys", 0, 0);
            chmod("/var/root/.ssh/authorized_keys", 0600);
            LOG("[*] Created authorized_keys for root. Use this key to login (copy this to your HOME/.ssh/ folder) %s", [defaultAuthorizedKey UTF8String]);
            LOG("[*] NOTE: this file can be found under the bins directory in the project");
        }
        if(!fileExists("/var/mobile/.ssh")) {
            mkdir("/var/mobile/.ssh", 0700);
            chown("/var/mobile/.ssh", 501, 501);
        }
        if(!fileExists("/var/mobile/.ssh/authorized_keys")) {
            LOG("[+] Generating mobile ssh Keys...");
            copyFile(in_bundle("bins/id_rsa_rjb3.pub"), "/var/mobile/.ssh/authorized_keys");
            copyFile(in_bundle("bins/id_rsa_rjb3"), "/var/mobile/.ssh/id_rsa_rjb3");
            copyFile(in_bundle("bins/id_rsa_rjb3.pub"), "/var/mobile/.ssh/id_rsa_rjb3.pub");
            chown("/var/mobile/.ssh/authorized_keys", 501, 501);
            chmod("/var/mobile/.ssh/authorized_keys", 0600);
            LOG("[*] Created authorized_keys for mobile. Use this key to login (copy this to your HOME/.ssh/ folder) %s", [defaultAuthorizedKey UTF8String]);
            LOG("[*] NOTE: this file can be found under the bins directory in the project");
        }

        LOG("[+] Generating Host Keys...");
        if(!fileExists("/var/etc/ssh/ssh_host_rsa_key")) launch("/var/usr/bin/ssh-keygen", "-q", "-f/var/etc/ssh/ssh_host_rsa_key", "-trsa", NULL, NULL, NULL, NULL );
        if(!fileExists("/var/etc/ssh/ssh_host_dsa_key")) launch("/var/usr/bin/ssh-keygen", "-q", "-f/var/etc/ssh/ssh_host_dsa_key", "-tdsa", NULL, NULL, NULL, NULL );
        if(!fileExists("/var/etc/ssh/ssh_host_ecdsa_key")) launch("/var/usr/bin/ssh-keygen", "-q", "-f/var/etc/ssh/ssh_host_ecdsa_key", "-tecdsa", "-b521", NULL, NULL, NULL);
        if(!fileExists("/var/etc/ssh/ssh_host_ed25519_key")) launch("/var/usr/bin/ssh-keygen", "-q", "-f/var/etc/ssh/ssh_host_ed25519_key", "-ted25519", NULL, NULL, NULL, NULL);

        if(fileExists("/var/etc/ssh/ssh_host_rsa_key")) LOG("[+] Host key %s", "/var/etc/ssh/ssh_host_rsa_key");
        if(fileExists("/var/etc/ssh/ssh_host_dsa_key")) LOG("[+] Host key %s", "/var/etc/ssh/ssh_host_dsa_key");
        if(fileExists("/var/etc/ssh/ssh_host_ecdsa_key")) LOG("[+] Host key %s", "/var/etc/ssh/ssh_host_ecdsa_key");
        if(fileExists("/var/etc/ssh/ssh_host_ed25519_key")) LOG("[+] Host key %s", "/var/etc/ssh/ssh_host_ed25519_key");

    } else {
        LOG("[*] Setting up dropbear");
        mkdir("/var/dropbear", 0777);
        removeFile("/var/profile");
        removeFile("/var/motd");
        chmod("/var/profile", 0777);
        chmod("/var/motd", 0777);

        copyFile("/var/containers/Bundle/iosbinpack64/etc/profile", "/var/profile");
        copyFile("/var/containers/Bundle/iosbinpack64/etc/motd", "/var/motd");

        // kill it if running
        launch("/var/containers/Bundle/iosbinpack64/usr/bin/killall", "-SEGV", "dropbear", NULL, NULL, NULL, NULL, NULL);
        failIf(launchAsPlatform("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear", "-R", "-E", NULL, NULL, NULL, NULL, NULL), "[-] Failed to launch dropbear");
        pid_t dpd = pid_of_procName("dropbear");
        usleep(1000);
        if (!dpd) failIf(launchAsPlatform("/var/containers/Bundle/iosbinpack64/usr/local/bin/dropbear", "-R", "-E", NULL, NULL, NULL, NULL, NULL), "[-] Failed to launch dropbear");
    }

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

    if(noDropbear) {
        pid_t sshdPid = pid_of_procName("sshd");
        if(!sshdPid) {
            char* log = dumpFile("/var/log/sshd.log");
            if(log) {
                LOG("[-] sshd did not start. Check log output");
                printf("[-] sshd did not start. printing log: \n******************\n\n%s\n\n******************", log);
                free(log);
            } else {
                LOG("[-] sshd did not start. but not log exists... wtf?");
            }
        }
    }

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
            
            failIf(system_("/var/containers/Bundle/iosbinpack64/usr/local/bin/jtool --sign --inplace --ent /var/containers/Bundle/iosbinpack64/default.ent /var/libexec/xpcproxy"), "[-] Failed to resign xpcproxy!");
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
  
        LOG("[?] Are we still alive?!");

        //----- magic end here -----//

        // cache pid and we're done
        pid_t installd = pid_of_procName("installd");
        pid_t bb = pid_of_procName("backboardd");
        pid_t amfid = pid_of_procName("amfid");
        if (amfid) kill(amfid, SIGKILL);

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
        
        // kill any daemon/executable being hooked by tweaks (except for the obvious, assertiond, backboardd and SpringBoard)

        NSArray *tweaks = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/ulb/TweakInject" error:NULL];
        for (NSString *afile in tweaks) {
            if ([afile hasSuffix:@"plist"]) {
                
                NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"/var/ulb/TweakInject/%@",afile]];
                NSString *dylibPath = [afile stringByReplacingOccurrencesOfString:@".plist" withString:@".dylib"];
                fixMmap((char *)[[NSString stringWithFormat:@"/var/ulb/TweakInject/%@", dylibPath] UTF8String]);
                NSArray *executables = [[plist objectForKey:@"Filter"] objectForKey:@"Executables"];

                for (NSString *processName in executables) {
                    if (![processName isEqual:@"SpringBoard"] && ![processName isEqual:@"backboardd"] && ![processName isEqual:@"assertiond"] && ![processName isEqual:@"launchd"]) { //really?
                        int procpid = pid_of_procName((char *)[processName UTF8String]);
                        if (procpid) {
                            kill(procpid, SIGKILL);
                        }
                    }
                }
                
                NSArray *bundles = [[plist objectForKey:@"Filter"] objectForKey:@"Bundles"];
                for (NSString *bundleID in bundles) {
                    if (![bundleID isEqual:@"com.apple.springboard"] && ![bundleID isEqual:@"com.apple.backboardd"] && ![bundleID isEqual:@"com.apple.assertiond"] && ![bundleID isEqual:@"com.apple.launchd"]) {
                        NSString *processName = [bundleID stringByReplacingOccurrencesOfString:@"com.apple." withString:@""];
                        int procpid = pid_of_procName((char *)[processName UTF8String]);
                        if (procpid) {
                            kill(procpid, SIGKILL);
                        }
                    }
                    
                }
            }
        }
     
        // find which applications are jailbreak applications and inject their executable
        NSArray *applications = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application/" error:NULL];
        
        for (NSString *string in applications) {
            NSString *fullPath = [@"/var/containers/Bundle/Application/" stringByAppendingString:string];
            NSArray *innerContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:fullPath error:NULL];
            for (NSString *innerFile in innerContents) {
                if ([innerFile hasSuffix:@"app"]) {
                    
                    NSString *fullAppBundlePath = [fullPath stringByAppendingString:[NSString stringWithFormat:@"/%@",innerFile]];
                    NSString *_CodeSignature = [fullPath stringByAppendingString:[NSString stringWithFormat:@"/%@/_CodeSignature",innerFile]];
                    
                    NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist",fullAppBundlePath]];
                    NSString *executable = [infoPlist objectForKey:@"CFBundleExecutable"];
                    NSString *BuildMachineOSBuild = [infoPlist objectForKey:@"BuildMachineOSBuild"];
                    BOOL hasDTCompilerRelatedKeys=NO;
                    for (NSString *KEY in [infoPlist allKeys]) {
                        if ([KEY rangeOfString:@"DT"].location==0) {
                            hasDTCompilerRelatedKeys=YES;
                            break;
                        }
                    }
                    // check for keys added by native/appstore apps and exclude (theos and friends don't add BuildMachineOSBuild and DT_ on apps :-D )
                    // Xcode-added apps set CFBundleExecutable=Executable, exclude them too
                    
                    executable = [NSString stringWithFormat:@"%@/%@", fullAppBundlePath, executable];
                    
                    if (([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithFormat:@"%@/.jb",fullAppBundlePath]] || ![[NSFileManager defaultManager] fileExistsAtPath:_CodeSignature] || (executable && ![executable isEqual:@"Executable"] && !BuildMachineOSBuild & !hasDTCompilerRelatedKeys)) && fileExists([executable UTF8String])) {
                        
                        LOG("Injecting executable %s",[executable UTF8String]);
                        system_((char *)[[NSString stringWithFormat:@"/var/containers/Bundle/iosbinpack64/usr/bin/inject %s", [executable UTF8String]] UTF8String]);
                    }
                    
                }
            }
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
    LOG("[*] Starting uninstall jelbrek...");
    [self.unJailbreakButton setEnabled:NO];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
    //---- tfp0 ----//
#ifdef DEBUG
        kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &taskforpidzero);
        if (ret) {
            printf("[-] Error using hgsp! '%s'\n", mach_error_string(ret));
            printf("[*] Using exploit!\n");
            
            if (psize == 0x1000 && maxVersion("12.1.2")) {
                
                // v3ntex is so bad we have to treat it specially for it not to freak out
                dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0);
                dispatch_group_t group = dispatch_group_create();
                dispatch_semaphore_t sm = dispatch_semaphore_create(0);
                
                dispatch_group_async(group, queue, ^{
                    taskforpidzero = v3ntex();
                    dispatch_semaphore_signal(sm);
                });
                
                dispatch_semaphore_wait(sm, DISPATCH_TIME_FOREVER);
            }
            
            else if (maxVersion("12.1.2")) {
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
                [self.unJailbreakButton setEnabled:YES];
                sleep(1);
                return;
            }
        }
#else
        mach_port_t taskforpidzero;
        if (psize == 0x1000 && maxVersion("12.1.2")) {
            taskforpidzero = v3ntex();
            [self uninstallJelbrekDun:taskforpidzero];
        } else if (maxVersion("12.1.2")) {
            taskforpidzero = voucher_swap();
            [self uninstallJelbrekDun:taskforpidzero];
        } else {
            [sender setTitle:@"Not supported!" forState:UIControlStateNormal];
            [sender setEnabled:false];
            return;
        }
#endif
    });
}


-(void) uninstallJelbrekDun:(mach_port_t) tfp0 {
    if (!MACH_PORT_VALID(tfp0)) {
            LOG("[-] Exploit failed");
            LOG("[i] Please try again");
            sleep(1);
        [self.unJailbreakButton setEnabled:NO];
        return;
        }
    uint64_t sb = 0;
    NSError *error = NULL;

    LOG("[*] Starting fun");
    
    if (!KernelBase) {
        kernel_slide_init();
        init_with_kbase(tfp0, 0xfffffff007004000 + kernel_slide);
    }
    else init_with_kbase(tfp0, KernelBase);
    
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
    
#ifdef DEBUG
    setHSP4();
    PatchHostPriv(mach_host_self());
#endif
    
    LOG("[*] Uninstalling...");
    
    launch("/var/containers/Bundle/iosbinpack64/bin/launchctl", "unload", "/var/containers/Bundle/iosbinpack64/LaunchDaemons", NULL, NULL, NULL, NULL, NULL);

    pid_t sshd = pid_of_procName("sshd");

    if(sshd != 0) {
        LOG("[-] could not shut sshd down...");
    }

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
    removeFile("/var/log/pspawn_payload_xpcproxy.log");
    removeFile("/var/containers/Bundle/.installed_rootlessJB3");
    removeFile("/var/lib");
    removeFile("/var/etc");
    removeFile("/var/usr");
    
end:;
    reboot(0);
// ... whats the point? Need to reboot clean anyway.
//    if (sb) sandbox(getpid(), sb);
//    term_jelbrek();
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end


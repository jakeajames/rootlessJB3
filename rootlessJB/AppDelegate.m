//
//  AppDelegate.m
//  rootlessJB
//
//  Created by Jake James on 8/28/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#include <sys/time.h>
#import "AppDelegate.h"
#import "util.h"
#import "ViewController.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

-(AppDelegate*)init {
    self = [super init];
    enableLogging();
    _combinedPipe = [NSPipe pipe];
    _orig_stdout = dup(STDOUT_FILENO);
    _orig_stderr = dup(STDERR_FILENO);
    dup2(_combinedPipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO);
    dup2(_combinedPipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO);
    [self performSelectorInBackground:@selector(handlePipe) withObject:nil];
    return self;
}

-(NSString*)readDataFromFD:(int)infd toFD:(int)outfd {
    char s[0x10000];

    ssize_t nread = read(infd, s, sizeof(s));
    if (nread <= 0)
        return nil;

    write(outfd, s, nread);
    if (logfd > 0) {
        if (write(logfd, s, nread) != nread) {
            write(_orig_stderr, "error writing to logfile\n", 26);
        }
    }
    return [[NSString alloc] initWithBytes:s length:nread encoding:NSUTF8StringEncoding];
}

- (void)handlePipe {
    fd_set fds;
    NSMutableString *outline = [NSMutableString new];

    int input_fd = _combinedPipe.fileHandleForReading.fileDescriptor;
    int rv;

    do {
        FD_ZERO(&fds);
        FD_SET(input_fd, &fds);
        rv = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
        if (FD_ISSET(input_fd, &fds)) {
            NSString *read = [self readDataFromFD:input_fd toFD:_orig_stdout];
            if (read == nil)
                continue;
            [outline appendString:read];
            NSRange lastNewline = [read rangeOfString:@"\n" options:NSBackwardsSearch];
            if (lastNewline.location != NSNotFound) {
                lastNewline.location = outline.length - (read.length - lastNewline.location);
                NSRange wanted = {0, lastNewline.location + 1};
                [ViewController.sharedController appendTextToOutput:[outline substringWithRange:wanted]];
                [outline deleteCharactersInRange:wanted];
            }
        }
    } while (rv > 0);
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end

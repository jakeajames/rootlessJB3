#import <sys/types.h>
#import <sys/stat.h>

#include <stdint.h>             // uint*_t
#include <stdbool.h>
#include <mach-o/loader.h>
#ifdef __OBJC__
#include <Foundation/Foundation.h>
#define LOG(str, args...) do { NSLog(@"[*] " str "\n", ##args); } while(false)
#else
#include <CoreFoundation/CoreFoundation.h>
extern void NSLog(CFStringRef, ...);
#define LOG(str, args...) do { NSLog(CFSTR("[*] " str "\n"), ##args); } while(false)
#endif
extern int logfd;

bool debuggerEnabled(void);
NSString *getLogFile(void);
void enableLogging(void);
void disableLogging(void);
NSString *appVersion();
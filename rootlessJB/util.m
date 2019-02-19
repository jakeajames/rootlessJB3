#import "util.h"
int logfd=-1;

NSString *getLogFile() {
    static NSString *logfile;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        logfile = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/log_file.txt"];
    });
    return logfile;
}

bool debuggerEnabled() {
    return (getppid() != 1);
}

void enableLogging() {
    if (!debuggerEnabled()) {
        int old_logfd = logfd;
        int newfd = open(getLogFile().UTF8String, O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (newfd < 0) {
            LOG("Error opening logfile: %s", strerror(errno));
        }
        logfd = newfd;
        if (old_logfd > 0)
            close(old_logfd);
    }
}

void disableLogging() {
    if (!debuggerEnabled()) {
        int old_logfd = logfd;
        logfd = -1;
        if (old_logfd > 0)
            close(old_logfd);
    }
}

NSString *appVersion() {
    NSBundle *bundle = [NSBundle mainBundle];
    return [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

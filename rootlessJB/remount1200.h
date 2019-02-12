//
//  remount1200.h
//  rootlessJB
//
//  Created by Lakr Sakura on 2019/2/13.
//  Copyright © 2019 Jake James. All rights reserved.
//

#ifndef remount1200_h
#define remount1200_h

#include <stdio.h>

#endif /* remount1200_h */

#define LKM_RMT_SUCCESS (0)
#define LKM_RMT_REBOOT_REQUIRED (1)
#define LKM_RMT_UNEXCEPT_ERROR (-1)
#define LKM_RMT_EXCEPT_ERROR (-2)


int remount1200(void);
int renameSP1200(void);
int relockFileSystem(void);

//
//  remount.h
//  rootlessJB
//
//  Created by Misty on 2019/2/6.
//  Copyright © 2019年 Jake James. All rights reserved.
//

#ifndef remount_h
#define remount_h


#include "remount1200_PF.h"

#define LKM_RMT_SUCCESS (0)
#define LKM_RMT_REBOOT_REQUIRED (1)
#define LKM_RMT_UNEXCEPT_ERROR (-1)
#define LKM_RMT_EXCEPT_ERROR (-2)

int remount1200(void);
int renameSP1200(void);

#endif /* remount_h */

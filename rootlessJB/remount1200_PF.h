//
//  remount1200_PF.h
//  rootlessJB
//
//  Created by ZIQING ZHOU on 2019/2/10.
//  Copyright © 2019 Jake James. All rights reserved.
//

#ifndef remount1200_PF_h
#define remount1200_PF_h


#endif /* remount1200_PF_h */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>


int InitPatchfinder(uint64_t base, const char *filename);
void TermPatchfinder(void);


unsigned long long Find_fs_lookup_snap_metadata(void);
unsigned long long Find_apfs_jhash_getvnode(void);

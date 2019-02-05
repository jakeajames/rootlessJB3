//
//  offsetsDump.c
//  rootlessJB
//
//  Created by Jake James on 8/29/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#include "offsetsDump.h"
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdbool.h>
typedef bool BOOL;

#include "jelbrekLib.h"

int dumpOffsetsToFile(char *file) {
    
    int fd = open(file, O_RDONLY);
    if (fd >= 0) {
        unlink(file);
        close(fd);
    }
    
    struct offsets off;
    
    off.allproc = Find_allproc();
    off.gadget = Find_add_x0_x0_0x40_ret();
    off.OSBooleanFalse = Find_OSBoolean_False();
    off.OSBooleanTrue = Find_OSBoolean_True();
    off.OSUnserializeXML = Find_osunserializexml();
    off.smalloc = Find_smalloc();
    off.zone_map_ref = Find_zone_map_ref();
    off.vfs_context = find_symbol("_vfs_context_current", false);
    off.vnode_lookup = find_symbol("_vnode_lookup", false);
    off.vnode_put = find_symbol("_vnode_put", false);
    off.kernelbase = KernelBase;
    
    FILE *f = fopen(file, "wb");
    fwrite(&off, sizeof(struct offsets), 1, f);
    fclose(f);
    
    fd = open(file, O_RDONLY);
    
    return (fd < 0);
}

//
//  remount.c
//  rootlessJB
//
//  Created by Misty on 2019/2/6.
//  Copyright © 2019 Jake James. All rights reserved.
//  Copyright © 2019 Misty. All rights reserved.
//

#include "remount.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>

#include "jelbrekLib.h"
#include "libjb.h"
#include "payload.h"
#include "offsetsDump.h"
#include "utilities/apfs_util.h"

#include <mach/mach.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <sys/snapshot.h>

// Adapted from Electra & RootlessJB's version

uint64_t kernproc;
uint64_t ourproc;
uint64_t kern_ucred;
uint64_t our_ucred;

int remount1200() {
    
    kernproc = proc_of_pid(0);
    ourproc = proc_of_pid(getpid());
    kern_ucred = KernelRead_64bits(kernproc + 248);
    our_ucred = KernelRead_64bits(ourproc + 248);
    
    int test_mp_sp = open("/", O_RDONLY);
    if (test_mp_sp < 0) {
        return LKM_RMT_UNEXCEPT_ERROR;
    }
    
    bool rename_happened = false;
    char *rename_name = "orig-fs";
    
    struct attrlist alist = { 0 };
    char buf[2048];
    alist.commonattr = ATTR_BULK_REQUIRED;
    int count = fs_snapshot_list(test_mp_sp, &alist, &buf[0], sizeof(buf), 0);
    if (count < 0) {
        return LKM_RMT_UNEXCEPT_ERROR;
    }
    char *p = &buf[0];
    for (int i = 0; i < count; i++) {
        char *field = p;
        field += sizeof(uint32_t);
        attribute_set_t attrs = *(attribute_set_t *)field;
        field += sizeof(attribute_set_t);
        
        if (attrs.commonattr & ATTR_CMN_NAME) {
            attrreference_t ar = *(attrreference_t *)field;
            char *name = field + ar.attr_dataoffset;
            field += sizeof(attrreference_t);
            (void) printf("[D] there is a snapshot named: %s\n", name);
            if (*name == *rename_name) {
                rename_happened = true;
            }
        }
    }
    close(test_mp_sp);
    
    if (rename_happened) {
        int rmv = remountRootFS();
        if (rmv != 0) {
            return LKM_RMT_UNEXCEPT_ERROR;
        }
    }else{
        return renameSP1200();
    }
    unlink("/RWTEST");
    return LKM_RMT_SUCCESS;
}

int renameSP1200() {
    
    uint64_t devVnode = getVnodeAtPath("/dev/disk0s1s1");
    uint64_t specinfo = KernelRead_64bits(devVnode + 0x78);
    KernelWrite_64bits(specinfo + 0x10, 0);
    
    rmdir("/var/rootfsmnt");
    mkdir("/var/rootfsmnt", 0777);
    chown("/var/rootfsmnt", 0, 0);
    
    printf("Temporarily setting kern ucred\n");
    KernelWrite_64bits(ourproc + 248, kern_ucred);
    int rv = LKM_RMT_UNEXCEPT_ERROR;
    
    if (mountDevAtPathAsRW("/dev/disk0s1s1", "/var/rootfsmnt")) {
        printf("Error mounting root at %s\n", "/var/rootfsmnt");
        return LKM_RMT_UNEXCEPT_ERROR;
    }
    else {
        printf("Disabling the APFS snapshot mitigations\n");
        char *_snap = find_system_snapshot();
        char *snap = (char *)malloc(strlen(_snap) + 10);
        memset(snap, 0, strlen(_snap) + 10);
        strcpy(snap, _snap);
        
        int dirfd = get_dirfd("/var/rootfsmnt");
        if (dirfd < 0) {
            perror("open");
        }
        
        // iPhone 7 with iOS 12.0.1
        uint64_t p_vnode_get_snapshot = 0xFFFFFFF007245FF0 + KASLR_Slide;
        uint64_t p_IOMalloc = 0xFFFFFFF007567894 + KASLR_Slide;
        
        // Kernel_alloc should also be OK
        uint64_t p_rvpp = ZmFixAddr(Kernel_Execute(p_IOMalloc, 8, 0, 0, 0, 0, 0, 0));
        uint64_t p_sdvpp = ZmFixAddr(Kernel_Execute(p_IOMalloc, 8, 0, 0, 0, 0, 0, 0));
        uint64_t buf_ndp = ZmFixAddr(Kernel_Execute(p_IOMalloc, 816, 0, 0, 0, 0, 0, 0));
        
        uint64_t vfsContext = get_vfs_context();
        uint64_t kEXECerr = Kernel_Execute(p_vnode_get_snapshot, dirfd, p_rvpp, p_sdvpp, (uint64_t)snap, buf_ndp, 2, vfsContext);
        if (kEXECerr != 0){
            return LKM_RMT_UNEXCEPT_ERROR;
        }
        uint64_t sdvpp = KernelRead_64bits(p_sdvpp);
        uint64_t v_sdvpp_mount = KernelRead_64bits(sdvpp + 0xD8);
        uint64_t v_mntdata = KernelRead_64bits(v_sdvpp_mount + 0x8F8);
        
        uint64_t p_fs_lookup_snapshot_metadata_by_name_and_return_name = Find_fs_lookup_snap_metadata();
        printf("Find_fs_lookup_snap_metadata:0x%llx\n", Find_fs_lookup_snap_metadata());
        
        uint64_t pSnapMeta = Kernel_alloc(8);
        uint64_t pOldName = Kernel_alloc(8);
        uint32_t ndpOldNameLen = KernelRead_32bits(buf_ndp + 336 + 48);
        uint64_t ndpOldName = KernelRead_64bits(buf_ndp + 336 + 40);
        
        kEXECerr = Kernel_Execute(p_fs_lookup_snapshot_metadata_by_name_and_return_name, v_mntdata, ndpOldName, ndpOldNameLen, pSnapMeta, pOldName, 0, 0);
        if (kEXECerr != 0){
            return LKM_RMT_UNEXCEPT_ERROR;
        }
        uint64_t snapMeta = KernelRead_64bits(pSnapMeta);
        
        uint64_t p_apfs_jhash_getvnode = Find_apfs_jhash_getvnode();
        printf("Find_apfs_jhash_getvnode:0x%llx\n", Find_apfs_jhash_getvnode());
        
        uint64_t retVnode = 0;
        retVnode = ZmFixAddr(Kernel_Execute(p_apfs_jhash_getvnode, v_mntdata, KernelRead_32bits(v_mntdata + 440), KernelRead_64bits(snapMeta+8), 1, 0, 0, 0));
        if (retVnode == 0){
            return LKM_RMT_UNEXCEPT_ERROR;
        }
        
        uint64_t snap_vdata = KernelRead_64bits(retVnode + 0xE0);
        uint32_t v_data_flag = KernelRead_32bits(snap_vdata + 49);
        v_data_flag &= ~0x40;
        KernelWrite_32bits(snap_vdata + 49, v_data_flag);
        
        int ret = fs_snapshot_rename(dirfd, snap, "orig-fs", 0);
        if (ret != 0){
            rv = LKM_RMT_UNEXCEPT_ERROR;
            perror("fs_snapshot_rename");
        }else{
            return LKM_RMT_REBOOT_REQUIRED;
        }
    }
    return LKM_RMT_UNEXCEPT_ERROR;
}

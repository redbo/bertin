package main

/*
#include <stdlib.h>
#include <sys/types.h>
#include <attr/xattr.h>
*/
import "C"
import "unsafe"

func FGetXattr(fd int, name string, value []byte) (int) {
    cname := C.CString(name)
    bytes := C.fgetxattr(C.int(fd), cname, unsafe.Pointer(&value[0]), C.size_t(len(value)))
    C.free(unsafe.Pointer(cname))
    return int(bytes)
}

func FSetXattr(fd int, name string, value []byte) (int) {
    cname := C.CString(name)
    ret := C.fsetxattr(C.int(fd), cname, unsafe.Pointer(&value[0]), C.size_t(len(value)), 0)
    C.free(unsafe.Pointer(cname))
    return int(ret)
}


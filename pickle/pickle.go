package pickle

/*
#cgo pkg-config: python
#include <Python.h>

#define INLINE __attribute__((always_inline))

INLINE int myPyString_Check(PyObject *o) {return PyString_Check(o);}
INLINE int myPyDict_Check(PyObject *o) {return PyDict_Check(o);}
INLINE int myPyInt_Check(PyObject *o) {return PyInt_Check(o);}
INLINE PyObject *PyObject_CallFunction1(PyObject *f, PyObject *o1)
    {return PyObject_CallFunctionObjArgs(f, o1, NULL);}
INLINE PyObject *PyNone() {Py_INCREF(Py_None); return Py_None;}
*/
import "C"
import (
    "sync"
    "unsafe"
)

var initialized int = 0
var pickle_loads *C.PyObject
var pickle_dumps *C.PyObject
var pickle_lock sync.Mutex

func _pickle_init () {
    if initialized == 0 {
        C.Py_Initialize()
        var cPickle *C.PyObject = C.PyImport_ImportModule(C.CString("cPickle"))
        pickle_loads = C.PyObject_GetAttrString(cPickle, C.CString("loads"))
        pickle_dumps = C.PyObject_GetAttrString(cPickle, C.CString("dumps"))
        C.Py_DecRef(cPickle)
        initialized = 1
    }
}

func PyObjToInterface(o *C.PyObject) (interface {}) {
    if C.myPyString_Check(o) != 0 {
        return C.GoStringN(C.PyString_AsString(o), C.int(C.PyString_Size(o)))
    } else if C.myPyInt_Check(o) != 0 {
        return int64(C.PyInt_AsLong(o))
    } else if C.myPyDict_Check(o) != 0 {
        v := make(map[interface{}]interface{})
        items := C.PyDict_Items(o)
        for i := 0; i < int(C.PyList_Size(items)); i++ {
            item := C.PyList_GetItem(items, C.Py_ssize_t(i))
            key := C.PyTuple_GetItem(item, 0)
            value := C.PyTuple_GetItem(item, 1)
            v[PyObjToInterface(key)] = PyObjToInterface(value)
        }
        C.Py_DecRef(items)
        return v
    }
    return nil
}

func DictAddItem(dict *C.PyObject, key interface{}, value interface{}) {
    pykey := InterfaceToPyObj(key)
    pyvalue := InterfaceToPyObj(value)
    C.PyDict_SetItem(dict, pykey, pyvalue)
    C.Py_DecRef(pykey)
    C.Py_DecRef(pyvalue)
}

func InterfaceToPyObj(o interface{}) (*C.PyObject) {
    switch o.(type) {
        case int:
            return C.PyInt_FromLong(C.long(o.(int)))
        case int64:
            return C.PyInt_FromLong(C.long(o.(int64)))
        case string:
            strvalue := C.CString(o.(string))
            defer C.free(unsafe.Pointer(strvalue))
            return C.PyString_FromStringAndSize(strvalue, C.Py_ssize_t(len(o.(string))))
        case map[interface{}]interface{}:
            dict := C.PyDict_New()
            for key, value := range o.(map[interface{}]interface{}) {DictAddItem(dict, key, value)}
            return dict
        case map[string]string:
            dict := C.PyDict_New()
            for key, value := range o.(map[string]string) {DictAddItem(dict, key, value)}
            return dict
        case map[string]interface{}:
            dict := C.PyDict_New()
            for key, value := range o.(map[string]interface{}) {DictAddItem(dict, key, value)}
            return dict
        case nil:
            return C.PyNone()
        default:
            return nil
    }
    return nil
}

func Loads(data string) (interface{}) {
    pickle_lock.Lock()
    _pickle_init()
    datastr := C.CString(data)
    str := C.PyString_FromStringAndSize(datastr, C.Py_ssize_t(len(data)))
    C.free(unsafe.Pointer(datastr))
    obj := C.PyObject_CallFunction1(pickle_loads, str)
    v := PyObjToInterface(obj)
    C.Py_DecRef(obj)
    C.Py_DecRef(str)
    pickle_lock.Unlock()
    return v
}

func Dumps(v interface{}) (string) {
    pickle_lock.Lock()
    _pickle_init()
    obj := InterfaceToPyObj(v)
    str := C.PyObject_CallFunction1(pickle_dumps, obj)
    gostr := PyObjToInterface(str)
    C.Py_DecRef(obj)
    C.Py_DecRef(str)
    pickle_lock.Unlock()
    return gostr.(string)
}


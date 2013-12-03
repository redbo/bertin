package main

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
var pickleLoads *C.PyObject
var pickleDumps *C.PyObject
var pickleLock sync.Mutex

func pickleInit() {
	if initialized == 0 {
		C.Py_Initialize()
		var cPickle *C.PyObject = C.PyImport_ImportModule(C.CString("cPickle"))
		pickleLoads = C.PyObject_GetAttrString(cPickle, C.CString("loads"))
		pickleDumps = C.PyObject_GetAttrString(cPickle, C.CString("dumps"))
		C.Py_DecRef(cPickle)
		initialized = 1
	}
}

func pyObjToInterface(o *C.PyObject) interface{} {
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
			v[pyObjToInterface(key)] = pyObjToInterface(value)
		}
		C.Py_DecRef(items)
		return v
	}
	return nil
}

func dictAddItem(dict *C.PyObject, key interface{}, value interface{}) {
	pykey := interfaceToPyObj(key)
	pyvalue := interfaceToPyObj(value)
	C.PyDict_SetItem(dict, pykey, pyvalue)
	C.Py_DecRef(pykey)
	C.Py_DecRef(pyvalue)
}

func interfaceToPyObj(o interface{}) *C.PyObject {
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
		for key, value := range o.(map[interface{}]interface{}) {
			dictAddItem(dict, key, value)
		}
		return dict
	case map[string]string:
		dict := C.PyDict_New()
		for key, value := range o.(map[string]string) {
			dictAddItem(dict, key, value)
		}
		return dict
	case map[string]interface{}:
		dict := C.PyDict_New()
		for key, value := range o.(map[string]interface{}) {
			dictAddItem(dict, key, value)
		}
		return dict
	default:
		return C.PyNone()
	}
}

func PickleLoads(data string) interface{} {
	pickleLock.Lock()
	pickleInit()
	datastr := C.CString(data)
	str := C.PyString_FromStringAndSize(datastr, C.Py_ssize_t(len(data)))
	C.free(unsafe.Pointer(datastr))
	obj := C.PyObject_CallFunction1(pickleLoads, str)
	v := pyObjToInterface(obj)
	C.Py_DecRef(obj)
	C.Py_DecRef(str)
	pickleLock.Unlock()
	return v
}

func PickleDumps(v interface{}) string {
	pickleLock.Lock()
	pickleInit()
	obj := interfaceToPyObj(v)
	str := C.PyObject_CallFunction1(pickleDumps, obj)
	gostr := pyObjToInterface(str)
	C.Py_DecRef(obj)
	C.Py_DecRef(str)
	pickleLock.Unlock()
	return gostr.(string)
}

package kv

// #cgo CFLAGS: -I${SRCDIR}/../../
// #include "valkyky.c"
import "C"
import (
	"fmt"
	"testing"
	"unsafe"
)

func testKvGetSetSingleKey(t *testing.T) {
	store := &C.kv_store_t{}
	C.kvStoreInit(store)
	if C.kvStoreGrow(store, 20) != 0 {
		t.Fatal("failed to allocate for C.kv_store_t")
	}

	key := stringt(128, "kyky")
	value := stringt(128, "val")

	if C.kvStoreSet(store, *key, *value, nil) != 0 {
		t.Fatal("run out of memory during C.kvStoreSet")
	}

	storedValue := C.kvStoreGet(store, *key)
	if storedValue == nil {
		s := C.GoStringN(value.data, C.int(value.len))
		t.Fatalf("set value to %+v but was not found\nstring:%s",
			*value, s)
	}

	if C.stringCmp(*storedValue, *value) != 0 {
		expected := C.GoStringN(value.data, C.int(value.len))
		actual := C.GoStringN(storedValue.data, C.int(storedValue.len))
		t.Fatalf("set value to %+v, got %+v\nexpected:%s\nactual:  %s",
			value, storedValue, expected, actual)
	}
}

func testKvGetSetSmallMap(t *testing.T) {
	expected := largeMap()
	sizes := []int{8, 16, 21, 32, 64, 100, 128, 256}

	for _, nbuckets := range sizes {
		name := fmt.Sprintf("%d_buckets", nbuckets)

		t.Run(name, func(t *testing.T) {
			_testKvStoreGetSet(t, nbuckets, expected)
		})
	}
}

func _testKvStoreGetSet(t *testing.T, nbuckets int, expected map[string]string) {
	store := &C.kv_store_t{}
	C.kvStoreInit(store)
	if C.kvStoreGrow(store, C.size_t(nbuckets)) != 0 {
		t.Fatal("failed to allocate for C.kv_store_t")
	}

	for key, value := range expected {
		k := stringt(len(key), key)
		v := stringt(len(value), value)

		if C.kvStoreSet(store, *k, *v, nil) != 0 {
			t.Fatal("failed to allocate for extra node in C.kv_store_t")
		}
	}

	if int(store.size) != len(expected) {
		t.Fatalf("kv_store should cotain %d elements, got %d", len(expected), store.size)
	}

	for key, value := range expected {
		k := stringt(len(key), key)
		v := stringt(len(value), value)

		stored := C.kvStoreGet(store, *k)
		if stored == nil {
			t.Errorf("expected key %s to be present, got nil", key)
		} else if C.stringCmp(*stored, *v) != 0 {
			t.Errorf("expected key %s to have %s != %s", key, value, stringDebug(*stored))
		}
		C.stringDrop(k)
		C.stringDrop(v)
	}
}

func stringDebug(str C.string_t) string {
	var data string
	if str.data == nil {
		data = "nil"
	} else {
		data = C.GoStringN(str.data, C.int(str.len))
	}
	return fmt.Sprintf("{cap:%d len:%d data:%s}", str.cap, str.len, data)
}

func stringt(capa int, gostr string) *C.string_t {
	if capa < len(gostr) {
		panic("capacity to small to allocate C.string_t")
	}

	str := &C.string_t{}
	C.stringInit(str)
	if C.stringGrow(str, C.size_t(capa)) != 0 {
		panic("failed to allocate for C.string_t")
	}

	bytes := []byte(gostr)
	mem := (*[1 << 32]C.char)(unsafe.Pointer(str.data))[:]
	for i, b := range bytes {
		mem[i] = C.char(b)
	}
	str.len = C.size_t(len(bytes))

	return str
}

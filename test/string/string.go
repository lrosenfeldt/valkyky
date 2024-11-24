package string

// #cgo CFLAGS: -I${SRCDIR}/../../
// #include "valkyky.c"
// #include "string_test_da.c"
import "C"
import (
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
	"unsafe"
)

func testStringPut(t *testing.T) {
	inputs := []string{
		"",
		"golang",
		"   ",
		"very long and even longer",
		"Bratöl",
		"*1\r\n$4\r\nPING\r\n",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			str := &C.string_t{}
			C.stringInit(str)

			if C.stringGrow(str, 128) != 0 {
				t.Fatal("failed to allocate string")
			}

			bytes := []byte(input)
			for _, b := range bytes {
				C.stringPut(str, C.char(b))
			}

			if int(str.len) != len(bytes) {
				t.Fatalf("string should contain %d chars, got %d",
					len(bytes), str.len)
			}
			if s := C.GoStringN(str.data, C.int(str.len)); s != input {
				t.Fatalf("string should contain '%s', got '%s'",
					input, s)
			}
		})
	}
}

func testStringPutN(t *testing.T) {
	inputs := []string{
		"Everything",
		" you see here ",
		"will",
		" be",
		"              ",
		"appended",
	}

	var sb strings.Builder
	str := &C.string_t{}
	C.stringInit(str)
	if C.stringGrow(str, 256) != 0 {
		t.Fatal("failed to allocate for C.string_t")
	}

	for _, input := range inputs {
		sb.WriteString(input)

		current := sb.String()
		buffer := C.CString(input)
		length := C.size_t(len(input))
		defer C.free(unsafe.Pointer(buffer))

		C.stringPutN(str, buffer, length)

		if int(str.len) != len(current) {
			t.Fatalf("string should contain %d chars, got %d\nfailed at '%s'",
				length, str.len, current)
		}
		if s := C.GoStringN(str.data, C.int(str.len)); s != current {
			t.Fatalf("string should contain '%s', got '%s'",
				current, s)
		}
	}
}

func testStringHash(t *testing.T) {
	inputs := []string{
		"Elixir is a programming language created by Jose Valim, based on the Erlang VM.",
		"awesome fluffy unicorn rainbow",
		"",
		strings.Repeat(" ", 100),
		strings.Repeat("Very long and even longer", 256),
	}

	for _, input := range inputs {
		hasher := fnv.New64()
		_, err := hasher.Write([]byte(input))
		if err != nil {
			t.Fatalf("could not setup expected fnv-Hash: %s", err.Error())
		}
		expected := hasher.Sum64()

		str := stringt(len(input), input)

		if actual := C.stringHash(*str); uint64(actual) != expected {
			t.Errorf("hash should be %d, got %d", actual, expected)
		}
	}

}

func testStringCmp(t *testing.T) {
	table := []struct {
		left, right string
		sgn         int
	}{
		{"", "abc", -1},
		{"not so empty", "", 1},
		{"utf-8", "Bratöl", 1},
		{"long", "longer", -1},
		{"ends", "end", 1},
		{"         ", "whitespace", -1},
		{"Ryan Carniato", "Rich Harris", 1},
		{"first", "second", -1},
		{"go programming language", "go programming language", 0},
	}

	for _, entry := range table {
		var op string
		if entry.sgn < 0 {
			op = "<"
		} else if entry.sgn > 0 {
			op = ">"
		} else {
			op = "=="
		}

		name := fmt.Sprintf("%s %s %s", entry.left, op, entry.right)
		t.Run(name, func(t *testing.T) {
			l := stringt(128, entry.left)
			r := stringt(128, entry.right)

			cmp := C.stringCmp(*l, *r)
			if entry.sgn != sign(int(cmp)) {
				if entry.sgn == 0 {
					t.Errorf("strings should match, got %d\nleft: %s\nright:%s\n",
						cmp, entry.left, entry.right)
				} else {
					t.Errorf("strings should compare to %d but matched\nleft: %s\nright:%s\n",
						cmp, entry.left, entry.right)
				}
			}
		})
	}
}

func stringt(capa int, gostr string) *C.string_t {
	if capa < len(gostr) {
		panic("capacity too small to allocate string_t")
	}
	bytes := []byte(gostr)

	str := &C.string_t{}
	C.stringInit(str)
	ptr := C.malloc(C.size_t(capa))
	if ptr == nil {
		panic("failed to allocate for string_t")
	}
	data := (*[1 << 32]C.char)(unsafe.Pointer(ptr))[:]
	for i, b := range bytes {
		data[i] = C.char(b)
	}

	str.data = (*C.char)(ptr)
	str.len = C.size_t(len(gostr))
	str.cap = C.size_t(capa)
	return str
}

func sign(n int) int {
	if n < 0 {
		return -1
	} else if n > 0 {
		return 1
	}
	return 0
}

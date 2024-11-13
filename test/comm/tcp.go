package comm

// #cgo CFLAGS: -I${SRCDIR}/../../
// #include "valkyky.c"
import "C"
import (
	"net"
	"testing"
	"time"
	"unsafe"
)

func testCommListenAndAcceptTcp(t *testing.T) {
	port := ":12345"
	cport := C.CString(port)
	defer C.free(unsafe.Pointer(cport))

	cerr := (*C.char)(C.malloc(C.size_t(C.COMM_ERROR_LENGTH)))
	defer C.free(unsafe.Pointer(cerr))

	sfd := C.commListenTcp(cerr, cport)
	if sfd < 0 {
		t.Fatalf("failed to listen: %s", C.GoString(cerr))
	}

	done := make(chan struct{}, 1)
	go func() {
		defer func() {
			done <- struct{}{}
		}()

		conn, err := net.DialTimeout("tcp", port, 100*time.Millisecond)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		t.Logf("connected to %s", conn.RemoteAddr().String())
	}()

	var cfd C.int
	for {
		cfd = C.commAcceptTcp(cerr, sfd)
		if cfd < 0 {
			if errMsg := C.GoString(cerr); errMsg != "" {
				t.Fatalf("failed to accept: %s", errMsg)
			}
			continue
		}
		break
	}

	<-done
}

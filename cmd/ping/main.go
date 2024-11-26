package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const port string = ":12345"

func main() {
	nclients := 1
	if len(os.Args) > 1 {
		n, err := strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		nclients = n
	}

	var wg sync.WaitGroup
	wg.Add(nclients)

	for i := 0; i < nclients; i++ {
		go func() {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", port, 100 * time.Millisecond)
			if err != nil {
				log.Println("ERROR connection", i, err)
				return
			}
			defer conn.Close()

			// msg := []byte("*2\r\n$4\r\nPING\r\n$7\r\nhellope\r\n")
			msg := []byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")
			// msg := []byte("*1\r\n$4\r\nPING\r\n")
			_, err = conn.Write(msg)
			if err != nil {
				log.Println("ERROR Write", i, err)
				return
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				log.Println("ERROR Read", i, err)
				return
			}
			log.Println("OK", i, escape(buf, n))
		}()
	}

	wg.Wait()
}

func escape(bytes []byte, length int) string {
	var sb strings.Builder

	for i := 0; i < length; i++ {
		b := bytes[i]

		switch b {
		case '\n':
			sb.WriteString("\\n")
		case '\r':
			sb.WriteString("\\r")
		case '\t':
			sb.WriteString("\\t")
		default:
			sb.WriteByte(b)
		}
	}

	return sb.String()
}

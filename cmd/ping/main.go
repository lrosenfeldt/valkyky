package main

import (
	"log"
	"net"
	"os"
	"strconv"
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

			msg := []byte("*1\r\n$4\r\nPING\r\n")
			_, err = conn.Write(msg)
			if err != nil {
				log.Println("ERROR Write", i, err)
				return
			}

			buf := make([]byte, 1024)
			_, err = conn.Read(buf)
			if err != nil {
				log.Println("ERROR Read", i, err)
				return
			}
			log.Println("OK", i, string(buf))
		}()
	}

	wg.Wait()
}

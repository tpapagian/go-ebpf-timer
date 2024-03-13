// Sample output:
//
// $ go run ./fcntl/
// Running fcntl system call on /tmp/fcntl-2744338193

package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

// this is a simple program that creates a temporary file and runs the fcntl
// system call on it
func main() {
	file, err := os.CreateTemp("", "fcntl-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())

	fmt.Println("Running fcntl system call on", file.Name())

	unix.FcntlInt(file.Fd(), 5674, 3454)
}

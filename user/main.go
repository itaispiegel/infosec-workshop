package main

import (
	"os"

	"github.com/itaispiegel/infosec-workshop/user/cmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	cmd.Execute()
	// clientSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	// if err != nil {
	// 	panic(err)
	// }

	// if err := syscall.Bind(clientSock, &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
	// 	panic(err)
	// }

	// sockAddr, err := syscall.Getsockname(clientSock)
	// if err != nil {
	// 	panic(err)
	// }

	// port := sockAddr.(*syscall.SockaddrInet4).Port
	// fmt.Println("Connecting via port: ", port)

	// if err := syscall.Connect(clientSock, &syscall.SockaddrInet4{Port: 12345, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
	// 	panic(err)
	// }

	// conn, err := net.FileConn(os.NewFile(uintptr(clientSock), "socket"))
	// if err != nil {
	// 	panic(err)
	// }

	// conn.Write([]byte("Hello, world!"))
	// conn.Close()
}

package proxy

import "fmt"

type FtpProxy struct {
	Address string
	Port    uint16
}

func NewFtpProxy(address string, port uint16) *FtpProxy {
	return &FtpProxy{
		Address: address,
		Port:    port,
	}
}

func (p *FtpProxy) Start() error {
	fmt.Println("Starting FTP proxy server on port", p.Port)
	return nil
}

package proxy

func httpCallback(data []byte) bool {
	return true
}

func NewHttpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Address:      address,
		Port:         port,
		DataCallback: httpCallback,
	}
}

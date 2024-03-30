package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/proxy"
	"github.com/spf13/cobra"
)

const defaultAddress = "10.1.1.3"

var addr string
var httpPort, ftpPort, nifiPort uint16

var baseProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a proxy server",
}

var httpProxyCmd = &cobra.Command{
	Use:   "http",
	Short: "Start an HTTP proxy server",
	RunE:  executeHttpProxy,
}

var ftpProxyCmd = &cobra.Command{
	Use:   "ftp",
	Short: "Start an FTP proxy server",
	RunE:  executeFtpProxy,
}

var nifiProxyCmd = &cobra.Command{
	Use:   "nifi",
	Short: "Start a NiFi proxy server",
	RunE:  executeNifiProxy,
}

func executeHttpProxy(cmd *cobra.Command, args []string) error {
	httpProxy := proxy.NewHttpProxy(addr, httpPort)
	return httpProxy.Start()
}

func executeFtpProxy(cmd *cobra.Command, args []string) error {
	ftpProxy := proxy.NewFtpProxy(addr, ftpPort)
	return ftpProxy.Start()
}

func executeNifiProxy(cmd *cobra.Command, args []string) error {
	nifiProxy := proxy.NewNifiProxy(addr, nifiPort)
	return nifiProxy.Start()
}

func init() {
	httpProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	httpProxyCmd.Flags().Uint16Var(&httpPort, "port", 800, "The port to listen on")
	ftpProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	ftpProxyCmd.Flags().Uint16Var(&ftpPort, "port", 210, "The port to listen on")
	nifiProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	nifiProxyCmd.Flags().Uint16Var(&nifiPort, "port", 8444, "The port to listen on")

	baseProxyCmd.AddCommand(httpProxyCmd)
	baseProxyCmd.AddCommand(ftpProxyCmd)
	baseProxyCmd.AddCommand(nifiProxyCmd)
	RootCmd.AddCommand(baseProxyCmd)
}

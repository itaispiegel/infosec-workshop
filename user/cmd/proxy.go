package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/proxy"
	"github.com/spf13/cobra"
)

const defaultAddress = "127.0.0.1"

var addr string
var port uint16

var proxyCmd = &cobra.Command{
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

func executeHttpProxy(cmd *cobra.Command, args []string) error {
	httpProxy := proxy.NewHttpProxy(addr, port)
	return httpProxy.Start()
}

func executeFtpProxy(cmd *cobra.Command, args []string) error {
	ftpProxy := proxy.NewFtpProxy(addr, port)
	return ftpProxy.Start()
}

func init() {
	httpProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	httpProxyCmd.Flags().Uint16Var(&port, "port", 800, "The port to listen on")
	ftpProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	ftpProxyCmd.Flags().Uint16Var(&port, "port", 800, "The port to listen on") // TODO: Fix this port

	proxyCmd.AddCommand(httpProxyCmd)
	proxyCmd.AddCommand(ftpProxyCmd)
	RootCmd.AddCommand(proxyCmd)
}

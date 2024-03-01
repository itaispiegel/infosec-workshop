package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/proxy"
	"github.com/spf13/cobra"
)

const defaultAddress = "10.1.1.3"

var addr string
var httpPort, ftpPort uint16

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
	httpProxy := proxy.NewHttpProxy(addr, httpPort)
	return httpProxy.Start()
}

func executeFtpProxy(cmd *cobra.Command, args []string) error {
	ftpProxy := proxy.NewFtpProxy(addr, ftpPort)
	return ftpProxy.Start()
}

func init() {
	httpProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	httpProxyCmd.Flags().Uint16Var(&httpPort, "port", 800, "The port to listen on")
	ftpProxyCmd.Flags().StringVar(&addr, "address", defaultAddress, "The address to listen on")
	ftpProxyCmd.Flags().Uint16Var(&ftpPort, "port", 210, "The port to listen on")

	proxyCmd.AddCommand(httpProxyCmd)
	proxyCmd.AddCommand(ftpProxyCmd)
	RootCmd.AddCommand(proxyCmd)
}

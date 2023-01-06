package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/json"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/spf13/cobra"
)

var (
	ListenArray  []string
	ForwardArray []string
	DumpConfig   bool
	ConfigPath   string
)

var commandGo = &cobra.Command{
	Use:   "go",
	Short: "模仿 Gost 方式运行",
	Run: func(cmd *cobra.Command, args []string) {
		err := gostRun()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGo.Flags().StringArrayVarP(&ListenArray, "listen", "L", nil, "监听地址")
	commandGo.Flags().StringArrayVarP(&ForwardArray, "forward", "F", nil, "代理连")
	commandGo.Flags().BoolVar(&DumpConfig, "dump", false, "输出配置文件")
	commandGo.Flags().StringVar(&ConfigPath, "config-path", "std", "文件路径, 'std' 输出到标准输出")
	mainCommand.AddCommand(commandGo)
}

func gostRun() error {
	log.Info("Hello gost!")

	if len(ListenArray) <= 0 {
		log.Fatal("Listen config is empty")
	}
	inbounds, err := parseInbound()
	if err != nil {
		log.Fatal(err)
	}

	outbounds, err := parseOutBound()
	if err != nil {
		log.Fatal(err)
	}

	options := option.Options{
		Inbounds:  inbounds,
		Outbounds: outbounds,
	}
	if DumpConfig {
		DumpSingboxConfig(options)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	instance, err := box.New(ctx, options)
	if err != nil {
		cancel()
		return exceptions.Cause(err, "create service")
	}
	err = instance.Start()
	if err != nil {
		cancel()
		return exceptions.Cause(err, "start service")
	}

	waitForExit(cancel, instance)
	return nil
}

func DumpSingboxConfig(options option.Options) error {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(options)
	if err != nil {
		return exceptions.Cause(err, "encode config")
	}

	if ConfigPath == "std" {
		os.Stdout.WriteString(buffer.String() + "\n")
		return nil
	}
	file, err := os.Create(ConfigPath)
	if err != nil {
		return err
	}
	_, err = file.Write(buffer.Bytes())
	file.Close()
	if err != nil {
		return exceptions.Cause(err, "write output")
	}
	outputPath, _ := filepath.Abs(ConfigPath)
	log.Info("write to configfile: ", outputPath)
	return nil
}

func waitForExit(cancel context.CancelFunc, instance *box.Box) {
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	for {
		osSignal := <-osSignals
		log.Info("get singal ", osSignal, " exist ...")
		cancel()
		instance.Close()
		break
	}
}

func parseOutBound() ([]option.Outbound, error) {
	outbounds := make([]option.Outbound, 0, len(ForwardArray))

	detourName := ""
	for i, f := range ForwardArray {
		log.Info("try to parse forward config ", f)
		u, err := parseUrl(f)
		if err != nil {
			log.Error("parse ", f, " error: ", err)
			return nil, err
		}
		outbound, err := GetOutboundFromURL(u, i+1, detourName)
		if err != nil {
			return nil, exceptions.Cause(err, "parse outbound error: ", f)
		}
		outbounds = append(outbounds, outbound)
		detourName = outbound.Tag
	}

	reverse(outbounds)

	return outbounds, nil
}

func GetOutboundFromURL(url *url.URL, index int, detourName string) (option.Outbound, error) {
	switch strings.ToLower(url.Scheme) {
	case constant.TypeSocks, "socks5", "auto":
		return parseOutboundSocks(url, index, detourName, false)
	case "ssl":
		return parseOutboundSocks(url, index, detourName, true)
	case constant.TypeHTTP:
		return parseOutboundHttp(url, index, detourName, false)
	case "https":
		return parseOutboundHttp(url, index, detourName, true)
	case "ssh", "sshd":
		return parseOutboundSSH(url, index, detourName)
	default:
		return option.Outbound{}, exceptions.New("unknown outbound type ", url.Scheme)
	}
}

func parseOutboundSSH(url *url.URL, index int, detourName string) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	c := option.Outbound{
		Type: constant.TypeSSH,
		Tag:  "jump-" + strconv.Itoa(index),
		SSHOptions: option.SSHOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
		},
	}
	if auth != nil {
		c.SSHOptions.User = auth.Username
		c.SSHOptions.Password = auth.Password
	}
	return c, nil
}

func parseOutboundHttp(url *url.URL, index int, detourName string, enableTLS bool) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	var tls *option.OutboundTLSOptions
	if enableTLS {
		tls = &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}

	c := option.Outbound{
		Type: constant.TypeHTTP,
		Tag:  "jump-" + strconv.Itoa(index),
		HTTPOptions: option.HTTPOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
			TLS: tls,
		},
	}
	if auth != nil {
		c.HTTPOptions.Username = auth.Username
		c.HTTPOptions.Password = auth.Password
	}
	return c, nil
}

func parseOutboundSocks(url *url.URL, index int, detourName string, enableTLS bool) (option.Outbound, error) {
	auth := GetAuthInfoFromUrl(url)

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Outbound{}, err
	}

	var tls *option.OutboundTLSOptions
	if enableTLS {
		tls = &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}

	c := option.Outbound{
		Type: constant.TypeSocks,
		Tag:  "jump-" + strconv.Itoa(index),
		SocksOptions: option.SocksOutboundOptions{
			DialerOptions: option.DialerOptions{
				Detour: detourName,
			},
			ServerOptions: option.ServerOptions{
				Server:     addr.String(),
				ServerPort: port,
			},
			TLS: tls,
		},
	}
	if auth != nil {
		c.SocksOptions.Username = auth.Username
		c.SocksOptions.Password = auth.Password
	}
	return c, nil
}

func parseInbound() ([]option.Inbound, error) {
	inbounds := make([]option.Inbound, 0, len(ListenArray))

	for i, l := range ListenArray {
		log.Info("try to parse listen config ", l)
		u, err := parseUrl(l)
		if err != nil {
			log.Error("parse ", l, " error: ", err)
			return nil, err
		}

		inbound, err := GetInboundFromURL(u, i)
		if err != nil {
			return nil, exceptions.Cause(err, "parse inbound error: ", l)
		}
		inbounds = append(inbounds, inbound)
	}
	return inbounds, nil
}

func GetInboundFromURL(url *url.URL, index int) (option.Inbound, error) {
	switch strings.ToLower(url.Scheme) {
	case constant.TypeSocks, "socks5":
		return parseInboundSocks(url, index, false)
	case "ssl":
		return parseInboundSocks(url, index, true)
	case constant.TypeMixed, "auto":
		return parseInboundMixed(url, index)
	case constant.TypeHTTP:
		return parseInboundHttp(url, index, false)
	case "https":
		return parseInboundHttp(url, index, true)
	default:
		return option.Inbound{}, exceptions.New("unknown inbound type ", url.Scheme)
	}
}

func parseInboundHttp(url *url.URL, index int, enableTLS bool) (option.Inbound, error) {
	var user []auth.User
	auth := GetAuthInfoFromUrl(url)
	if auth != nil {
		user = append(user, *auth)
	}

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Inbound{}, err
	}

	var tls *option.InboundTLSOptions

	if enableTLS {
		tls = &option.InboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}

	return option.Inbound{
		Type: constant.TypeMixed,
		Tag:  constant.TypeMixed + strconv.Itoa(index),
		HTTPOptions: option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     option.ListenAddress(addr),
				ListenPort: port,
			},
			Users: user,
			TLS:   tls,
		},
	}, nil
}

func parseInboundMixed(url *url.URL, index int) (option.Inbound, error) {
	var user []auth.User
	auth := GetAuthInfoFromUrl(url)
	if auth != nil {
		user = append(user, *auth)
	}

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Inbound{}, err
	}
	return option.Inbound{
		Type: constant.TypeMixed,
		Tag:  constant.TypeMixed + strconv.Itoa(index),
		MixedOptions: option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     option.ListenAddress(addr),
				ListenPort: port,
			},
			Users: user,
		},
	}, nil
}

func parseInboundSocks(url *url.URL, index int, enableTLS bool) (option.Inbound, error) {
	var user []auth.User
	auth := GetAuthInfoFromUrl(url)
	if auth != nil {
		user = append(user, *auth)
	}

	addr, port, err := GetHostAndPortFromUrl(url)
	if err != nil {
		return option.Inbound{}, err
	}

	var tls *option.InboundTLSOptions

	if enableTLS {
		tls = &option.InboundTLSOptions{
			Enabled:  true,
			Insecure: true,
		}
	}
	return option.Inbound{
		Type: constant.TypeSocks,
		Tag:  constant.TypeSocks + strconv.Itoa(index),
		SocksOptions: option.SocksInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     option.ListenAddress(addr),
				ListenPort: port,
			},
			Users: user,
			TLS:   tls,
		},
	}, nil
}

func GetHostAndPortFromUrl(url *url.URL) (netip.Addr, uint16, error) {
	host, p, err := net.SplitHostPort(url.Host)
	if err != nil {
		return netip.Addr{}, 0, exceptions.Cause(err, "get inbound config error")
	}

	if host == "" {
		host = "127.0.0.1"
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		return netip.Addr{}, 0, exceptions.Cause(err, p, "is not number")
	}
	if port >= 65535 || port <= 0 {
		return netip.Addr{}, 0, exceptions.New(p, "is not in range [1-65535]")
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, exceptions.New("error ip addr: ", host)
	}
	return addr, uint16(port), nil
}

func GetAuthInfoFromUrl(url *url.URL) *auth.User {
	if url.User != nil {
		username := url.User.Username()
		password, set := url.User.Password()
		if !set {
			password = ""
		}
		return &auth.User{
			Username: username,
			Password: password,
		}
	}

	return nil
}

func parseUrl(u string) (*url.URL, error) {
	if u == "" {
		return nil, exceptions.New("url is nil")
	}

	if u[0] == ':' || !strings.Contains(u, "://") {
		u = "auto://" + u
	}

	return url.Parse(u)
}

func reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

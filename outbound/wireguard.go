//go:build with_wireguard

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgTun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var _ adapter.Outbound = (*WireGuard)(nil)

type WireGuard struct {
	myOutboundAdapter
	ctx        context.Context
	serverAddr M.Socksaddr
	dialer     N.Dialer
	endpoint   conn.Endpoint
	device     *device.Device
	tunDevice  wireDevice
	connAccess sync.Mutex
	conn       *wireConn
}

func NewWireGuard(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardOutboundOptions) (*WireGuard, error) {
	outbound := &WireGuard{
		myOutboundAdapter: myOutboundAdapter{
			protocol: C.TypeWireGuard,
			network:  options.Network.Build(),
			router:   router,
			logger:   logger,
			tag:      tag,
		},
		ctx:        ctx,
		serverAddr: options.ServerOptions.Build(),
		dialer:     dialer.New(router, options.DialerOptions),
	}
	var endpointIp netip.Addr
	if !outbound.serverAddr.IsFqdn() {
		endpointIp = outbound.serverAddr.Addr
	} else {
		endpointIp = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	outbound.endpoint = conn.StdNetEndpoint(netip.AddrPortFrom(endpointIp, outbound.serverAddr.Port))
	localPrefixes := make([]netip.Prefix, len(options.LocalAddress))
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	for i, address := range options.LocalAddress {
		if strings.Contains(address, "/") {
			prefix, err := netip.ParsePrefix(address)
			if err != nil {
				return nil, E.Cause(err, "parse local address prefix ", address)
			}
			localPrefixes[i] = prefix
		} else {
			addr, err := netip.ParseAddr(address)
			if err != nil {
				return nil, E.Cause(err, "parse local address ", address)
			}
			localPrefixes[i], _ = addr.Prefix(addr.BitLen())
		}
	}
	var privateKey, peerPublicKey, preSharedKey string
	{
		bytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		privateKey = hex.EncodeToString(bytes)
	}
	{
		bytes, err := base64.StdEncoding.DecodeString(options.PeerPublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode peer public key")
		}
		peerPublicKey = hex.EncodeToString(bytes)
	}
	if options.PreSharedKey != "" {
		bytes, err := base64.StdEncoding.DecodeString(options.PreSharedKey)
		if err != nil {
			return nil, E.Cause(err, "decode pre shared key")
		}
		preSharedKey = hex.EncodeToString(bytes)
	}
	ipcConf := "private_key=" + privateKey
	ipcConf += "\npublic_key=" + peerPublicKey
	ipcConf += "\nendpoint=" + outbound.endpoint.DstToString()
	if preSharedKey != "" {
		ipcConf += "\npreshared_key=" + preSharedKey
	}
	var has4, has6 bool
	for _, address := range localPrefixes {
		if address.Addr().Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	if has4 {
		ipcConf += "\nallowed_ip=0.0.0.0/0"
	}
	if has6 {
		ipcConf += "\nallowed_ip=::/0"
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1408
	}
	var wireTunDevice wireDevice
	var err error
	if options.InterfaceName == "" {
		wireTunDevice, err = newWireStackDevice(localPrefixes, mtu)
	} else {
		wireTunDevice, err = newWireSystemDevice(router, options.InterfaceName, localPrefixes, mtu)
	}
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	wgDevice := device.NewDevice(wireTunDevice, (*wireClientBind)(outbound), &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	})
	if debug.Enabled {
		logger.Trace("created wireguard ipc conf: \n", ipcConf)
	}
	err = wgDevice.IpcSet(ipcConf)
	if err != nil {
		return nil, E.Cause(err, "setup wireguard")
	}
	outbound.device = wgDevice
	outbound.tunDevice = wireTunDevice
	return outbound, nil
}

func (w *WireGuard) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		addrs, err := w.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.tunDevice, network, destination, addrs)
	}
	return w.tunDevice.DialContext(ctx, network, destination)
}

func (w *WireGuard) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return w.tunDevice.ListenPacket(ctx, destination)
}

func (w *WireGuard) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, w, conn, metadata)
}

func (w *WireGuard) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, w, conn, metadata)
}

func (w *WireGuard) Start() error {
	w.tunDevice.Start()
	return nil
}

func (w *WireGuard) Close() error {
	return common.Close(
		w.tunDevice,
		common.PtrOrNil(w.device),
		common.PtrOrNil(w.conn),
	)
}

var _ conn.Bind = (*wireClientBind)(nil)

type wireClientBind WireGuard

func (c *wireClientBind) connect() (*wireConn, error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.conn != nil {
		select {
		case <-c.conn.done:
		default:
			return c.conn, nil
		}
	}
	udpConn, err := c.dialer.DialContext(c.ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, &wireError{err}
	}
	c.conn = &wireConn{
		Conn: udpConn,
		done: make(chan struct{}),
	}
	return c.conn, nil
}

func (c *wireClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *wireClientBind) receive(b []byte) (n int, ep conn.Endpoint, err error) {
	udpConn, err := c.connect()
	if err != nil {
		err = &wireError{err}
		return
	}
	n, err = udpConn.Read(b)
	if err != nil {
		udpConn.Close()
		err = &wireError{err}
	}
	ep = c.endpoint
	return
}

func (c *wireClientBind) Close() error {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	common.Close(common.PtrOrNil(c.conn))
	return nil
}

func (c *wireClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *wireClientBind) Send(b []byte, ep conn.Endpoint) error {
	udpConn, err := c.connect()
	if err != nil {
		return err
	}
	_, err = udpConn.Write(b)
	if err != nil {
		udpConn.Close()
	}
	return err
}

func (c *wireClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return c.endpoint, nil
}

type wireError struct {
	cause error
}

func (w *wireError) Error() string {
	return w.cause.Error()
}

func (w *wireError) Timeout() bool {
	if cause, causeNet := w.cause.(net.Error); causeNet {
		return cause.Timeout()
	}
	return false
}

func (w *wireError) Temporary() bool {
	return true
}

type wireConn struct {
	net.Conn
	access sync.Mutex
	done   chan struct{}
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	w.Conn.Close()
	close(w.done)
	return nil
}

type wireDevice interface {
	wgTun.Device
	Start()
	N.Dialer
}

var _ wireDevice = (*wireSystemDevice)(nil)

type wireSystemDevice struct {
	dialer N.Dialer
	device tun.Tun
	name   string
	mtu    int
	events chan wgTun.Event
}

func newWireSystemDevice(router adapter.Router, interfaceName string, localPrefixes []netip.Prefix, mtu uint32) (*wireSystemDevice, error) {
	var inet4Addresses []netip.Prefix
	var inet6Addresses []netip.Prefix
	for _, prefixes := range localPrefixes {
		if prefixes.Addr().Is4() {
			inet4Addresses = append(inet4Addresses, prefixes)
		} else {
			inet6Addresses = append(inet6Addresses, prefixes)
		}
	}
	if interfaceName == "" {
		interfaceName = tun.CalculateInterfaceName("wg")
	}
	tunInterface, err := tun.Open(tun.Options{
		Name:         interfaceName,
		Inet4Address: inet4Addresses,
		Inet6Address: inet6Addresses,
		MTU:          mtu,
	})
	if err != nil {
		return nil, err
	}
	return &wireSystemDevice{
		dialer.NewDefault(router, option.DialerOptions{
			BindInterface: interfaceName,
		}),
		tunInterface, interfaceName, int(mtu), make(chan wgTun.Event),
	}, nil
}

func (w *wireSystemDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return w.dialer.DialContext(ctx, network, destination)
}

func (w *wireSystemDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return w.dialer.ListenPacket(ctx, destination)
}

func (w *wireSystemDevice) Start() {
	w.events <- wgTun.EventUp
}

func (w *wireSystemDevice) File() *os.File {
	return nil
}

func (w *wireSystemDevice) Read(bytes []byte, index int) (int, error) {
	return w.device.Read(bytes[index-tunPacketOffset:])
}

func (w *wireSystemDevice) Write(bytes []byte, index int) (int, error) {
	return w.device.Write(bytes[index:])
}

func (w *wireSystemDevice) Flush() error {
	return nil
}

func (w *wireSystemDevice) MTU() (int, error) {
	return w.mtu, nil
}

func (w *wireSystemDevice) Name() (string, error) {
	return w.name, nil
}

func (w *wireSystemDevice) Events() chan wgTun.Event {
	return w.events
}

func (w *wireSystemDevice) Close() error {
	return w.device.Close()
}

var _ wireDevice = (*wireStackDevice)(nil)

const defaultNIC tcpip.NICID = 1

type wireStackDevice struct {
	stack      *stack.Stack
	mtu        uint32
	events     chan wgTun.Event
	outbound   chan *stack.PacketBuffer
	dispatcher stack.NetworkDispatcher
	done       chan struct{}
	addr4      tcpip.Address
	addr6      tcpip.Address
}

func newWireStackDevice(localAddresses []netip.Prefix, mtu uint32) (*wireStackDevice, error) {
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        true,
	})
	tunDevice := &wireStackDevice{
		stack:    ipStack,
		mtu:      mtu,
		events:   make(chan wgTun.Event, 4),
		outbound: make(chan *stack.PacketBuffer, 256),
		done:     make(chan struct{}),
	}
	err := ipStack.CreateNIC(defaultNIC, (*wireEndpoint)(tunDevice))
	if err != nil {
		return nil, E.New(err.String())
	}
	for _, prefix := range localAddresses {
		addr := tcpip.Address(prefix.Addr().AsSlice())
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			tunDevice.addr4 = addr
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			tunDevice.addr6 = addr
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		err = ipStack.AddProtocolAddress(defaultNIC, protoAddr, stack.AddressProperties{})
		if err != nil {
			return nil, E.New("parse local address ", protoAddr.AddressWithPrefix, ": ", err.String())
		}
	}
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: defaultNIC})
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: defaultNIC})
	return tunDevice, nil
}

func (w *wireStackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	addr := tcpip.FullAddress{
		NIC:  defaultNIC,
		Port: destination.Port,
		Addr: tcpip.Address(destination.Addr.AsSlice()),
	}
	bind := tcpip.FullAddress{
		NIC: defaultNIC,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = w.addr4
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = w.addr6
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return gonet.DialTCPWithBind(ctx, w.stack, bind, addr, networkProtocol)
	case N.NetworkUDP:
		return gonet.DialUDP(w.stack, &bind, &addr, networkProtocol)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (w *wireStackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind := tcpip.FullAddress{
		NIC: defaultNIC,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() || w.addr6 == "" {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = w.addr4
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = w.addr6
	}
	return gonet.DialUDP(w.stack, &bind, nil, networkProtocol)
}

func (w *wireStackDevice) Start() {
	w.events <- wgTun.EventUp
}

func (w *wireStackDevice) File() *os.File {
	return nil
}

func (w *wireStackDevice) Read(p []byte, offset int) (n int, err error) {
	packetBuffer, ok := <-w.outbound
	if !ok {
		return 0, os.ErrClosed
	}
	defer packetBuffer.DecRef()
	p = p[offset:]
	for _, slice := range packetBuffer.AsSlices() {
		n += copy(p[n:], slice)
	}
	return
}

func (w *wireStackDevice) Write(p []byte, offset int) (n int, err error) {
	p = p[offset:]
	if len(p) == 0 {
		return
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	switch header.IPVersion(p) {
	case header.IPv4Version:
		networkProtocol = header.IPv4ProtocolNumber
	case header.IPv6Version:
		networkProtocol = header.IPv6ProtocolNumber
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(p),
	})
	defer packetBuffer.DecRef()
	w.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
	n = len(p)
	return
}

func (w *wireStackDevice) Flush() error {
	return nil
}

func (w *wireStackDevice) MTU() (int, error) {
	return int(w.mtu), nil
}

func (w *wireStackDevice) Name() (string, error) {
	return "sing-box", nil
}

func (w *wireStackDevice) Events() chan wgTun.Event {
	return w.events
}

func (w *wireStackDevice) Close() error {
	select {
	case <-w.done:
		return os.ErrClosed
	default:
	}
	close(w.done)
	w.stack.Close()
	for _, endpoint := range w.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	w.stack.Wait()
	close(w.outbound)
	return nil
}

var _ stack.LinkEndpoint = (*wireEndpoint)(nil)

type wireEndpoint wireStackDevice

func (ep *wireEndpoint) MTU() uint32 {
	return ep.mtu
}

func (ep *wireEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *wireEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *wireEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (ep *wireEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *wireEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *wireEndpoint) Wait() {
}

func (ep *wireEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *wireEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (ep *wireEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		packetBuffer.IncRef()
		ep.outbound <- packetBuffer
	}
	return list.Len(), nil
}

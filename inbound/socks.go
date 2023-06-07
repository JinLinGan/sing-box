package inbound

import (
	"context"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

var (
	_ adapter.Inbound           = (*Socks)(nil)
	_ adapter.InjectableInbound = (*Socks)(nil)
)

type Socks struct {
	myInboundAdapter
	authenticator auth.Authenticator
	tlsConfig     tls.ServerConfig
}

func NewSocks(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SocksInboundOptions) (*Socks, error) {
	inbound := &Socks{
		myInboundAdapter: myInboundAdapter{
			protocol:      C.TypeSocks,
			network:       []string{N.NetworkTCP},
			ctx:           ctx,
			router:        router,
			logger:        logger,
			tag:           tag,
			listenOptions: options.ListenOptions,
		},
		authenticator: auth.NewAuthenticator(options.Users),
	}

	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, router, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	inbound.connHandler = inbound
	return inbound, nil
}

func (h *Socks) Start() error {
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	return h.myInboundAdapter.Start()
}

func (h *Socks) Close() error {
	return common.Close(
		&h.myInboundAdapter,
		h.tlsConfig,
	)
}

func (h *Socks) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	var err error
	if h.tlsConfig != nil {
		conn, err = tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			return err
		}
	}
	return socks.HandleConnection(ctx, conn, h.authenticator, h.upstreamUserHandler(metadata), adapter.UpstreamMetadata(metadata))
}

func (h *Socks) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}

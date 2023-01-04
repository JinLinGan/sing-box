package outbound

import (
	sysbufio "bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	syshttp "net/http"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/http"
)

var _ adapter.Outbound = (*HTTP)(nil)

type HTTP struct {
	myOutboundAdapter
	client *http.Client

	// 保存鉴权信息
	httpAuthString string
	// 保存detour 用于非conn模式（中间人模式）
	detour     N.Dialer
	serverAddr M.Socksaddr
}

func NewHTTP(router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (*HTTP, error) {
	detour, err := tls.NewDialerFromOptions(router, dialer.New(router, options.DialerOptions), options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}

	authStr := ""
	if options.Username != "" && options.Password != "" {
		authStr = base64.StdEncoding.EncodeToString([]byte(options.Username + ":" + options.Password))
	}
	serverAddr := options.ServerOptions.Build()
	return &HTTP{
		myOutboundAdapter{
			protocol: C.TypeHTTP,
			network:  []string{N.NetworkTCP},
			router:   router,
			logger:   logger,
			tag:      tag,
		},
		http.NewClient(detour, serverAddr, options.Username, options.Password),
		authStr,
		detour,
		serverAddr,
	}, nil
}

func (h *HTTP) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.client.DialContext(ctx, network, destination)
}

func (h *HTTP) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *HTTP) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if metadata.Protocol == C.ProtocolHTTP {
		outConn, err := h.detour.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return err
		}

		fConn := newFackConn(conn, func(req *syshttp.Request) {
			// 修改鉴权信息
			req.Header.Del("Proxy-Authorization")
			if h.httpAuthString != "" {
				req.Header.Add("Proxy-Authorization", "Basic "+h.httpAuthString)
			}
			req.URL.Scheme = "http"
		})

		return CopyConn(ctx, fConn, outConn)
	}
	return NewConnection(ctx, h, conn, metadata)
}

func (h *HTTP) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}

type (
	fcRequestProcesser func(req *syshttp.Request)
	fakeConn           struct {
		reqProc *requestProcesser

		// 新增一个连接

		// 代表原始客户连接，仅读取行为有差别
		net.Conn

		pipeReader io.Reader
	}
)

func newFackConn(clientConn net.Conn, process fcRequestProcesser) net.Conn {
	// reader 给 fakeConn 负责给外部提供读取功能
	// writer 给 process 负责写入
	reader, writer := io.Pipe()

	reqProcesser := &requestProcesser{
		clientConnReader: clientConn,
		serverConnWriter: writer,
		processFunc:      process,
	}

	go reqProcesser.process()

	return &fakeConn{
		reqProc:    reqProcesser,
		Conn:       clientConn,
		pipeReader: reader,
	}
}

func (f *fakeConn) Close() error {
	return f.Conn.Close()
}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	// read from pipe (pipe write by reqestProcesser)
	read, err := f.pipeReader.Read(b)
	return read, err
}

func (f *fakeConn) Write(p []byte) (n int, err error) {
	write, err := f.Conn.Write(p)
	return write, err
}

type requestProcesser struct {
	clientConnReader io.Reader
	serverConnWriter io.WriteCloser
	processFunc      fcRequestProcesser
}

func (p *requestProcesser) process() {
	defer p.serverConnWriter.Close()
	for {
		req, err := http.ReadRequest(sysbufio.NewReader(p.clientConnReader))
		if err != nil {
			break
		}

		p.processFunc(req)

		// 发送给代理服务器
		err = req.WriteProxy(p.serverConnWriter)
		if err != nil {
			break
		}
	}
	return
}

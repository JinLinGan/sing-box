package outbound

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/singledo"
	"github.com/sagernet/sing/common"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ adapter.Outbound      = (*AutoSelector)(nil)
	_ adapter.OutboundGroup = (*AutoSelector)(nil)
)

const (
	DefaultBlockTime        = time.Second * 60
	DefaultSingleReqTimeOut = time.Second * 30
)

type AutoSelector struct {
	myOutboundAdapter
	tags     []string
	selected string

	single *singledo.Single

	// TODO: 区分UDP和TCP

	// failedProxies 存储所有近期失败过的代理，当所有代理近期都失败过时，逐一尝试所有代理
	failedProxies sync.Map
	// blockTime 代理失败后被关小黑屋的时长
	blockTime time.Duration
}

func NewAutoSelector(router adapter.Router, logger log.ContextLogger, tag string, options option.AutoSelectorOutboundOptions) (*AutoSelector, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("outbounds is not setted")
	}
	outbound := &AutoSelector{
		myOutboundAdapter: myOutboundAdapter{
			protocol: C.TypeAutoSelector,
			router:   router,
			logger:   logger,
			tag:      tag,
		},
		tags:      options.Outbounds,
		single:    singledo.NewSingle(time.Second * 5),
		blockTime: DefaultBlockTime,
		selected:  options.Outbounds[0],
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *AutoSelector) Network() []string {
	outbound, loaded := s.myOutboundAdapter.router.Outbound(s.selected)
	if !loaded {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return outbound.Network()
}

func (s *AutoSelector) Now() string {
	return s.selected
}

func (s *AutoSelector) All() []string {
	return s.tags
}

func retry[T any](ctx context.Context, s *AutoSelector, fn func(context.Context, adapter.Outbound) (t T, err error)) (t T, err error) {
	outs, err := s.findOutBound()
	if err != nil {
		return t, E.Cause(err, "no available outbounds")
	}

	// ioCopyLock := &sync.Mutex{}
	for _, out := range outs {
		outbound, loaded := s.myOutboundAdapter.router.Outbound(out)
		if !loaded {
			s.logger.Error("outbound ", out, " not exists")
			s.failedProxies.Store(out, time.Now())
		}
		s.logger.InfoContext(ctx, "try use ", out)

		dialTimer := time.NewTimer(DefaultSingleReqTimeOut)

		// 容量要是1 不然底层 gorouting 会堵塞
		dialFinishChan := make(chan chan struct{}, 1)

		connCtx := context.WithValue(ctx, CtxDialFinishChannelKey, dialFinishChan)
		resultCh := make(chan struct {
			result T
			err    error
		}, 1)
		go func(out string) {
			fnRest, fnErr := fn(connCtx, outbound)
			if fnErr != nil {
				s.logger.DebugContext(ctx, "get Error from ", out, " errors: ", fnErr)
			}
			resultCh <- struct {
				result T
				err    error
			}{
				result: fnRest,
				err:    fnErr,
			}
		}(out)

		select {
		case r := <-resultCh:
			// 得到结果，判断
			select {
			case continueSingle := <-dialFinishChan:
				// 如果已经过了Dial阶段，io.copy 的结果
				close(continueSingle)
				s.selected = out
				return r.result, r.err
			default:
				// 如果还没有过dial阶段,重试下一个
				s.logger.InfoContext(ctx, out, " is error:", r.err)
			}
		case continueSingle := <-dialFinishChan:
			// 已经dial 完毕，等待结果,直接返回结果
			close(continueSingle)
			s.selected = out
			r := <-resultCh
			return r.result, r.err
		case <-dialTimer.C:
			// 如果还没有过dial阶段,重试下一个
			s.logger.InfoContext(ctx, out, " is timeout (", int(DefaultSingleReqTimeOut.Seconds()), "s)")
		}
		///
		s.failedProxies.Store(out, time.Now())
	}

	return t, E.New("no available proxies")
}

func (s *AutoSelector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return retry(ctx, s, func(ctx context.Context, outbound adapter.Outbound) (net.Conn, error) {
		conn, err := outbound.DialContext(ctx, network, destination)
		select {
		case <-ctx.Done():
			common.Close(conn)
			return nil, err
		default:
			return conn, err
		}
	})
}

func (s *AutoSelector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return retry(ctx, s, func(ctx context.Context, outbound adapter.Outbound) (net.PacketConn, error) {
		conn, err := outbound.ListenPacket(ctx, destination)
		select {
		case <-ctx.Done():
			common.Close(conn)
			return nil, err
		default:
			return conn, err
		}
	})
}

func (s *AutoSelector) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	_, err := retry(ctx, s, func(ctx context.Context, outbound adapter.Outbound) (struct{}, error) {
		err := outbound.NewConnection(ctx, conn, metadata)
		return struct{}{}, err
	})
	return err
}

func (s *AutoSelector) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	_, err := retry(ctx, s, func(ctx context.Context, outbound adapter.Outbound) (struct{}, error) {
		err := outbound.NewPacketConnection(ctx, conn, metadata)
		return struct{}{}, err
	})
	return err
}

func (s *AutoSelector) findOutBound() ([]string, error) {
	outs, err, _ := s.single.Do(func() (any, error) {
		// 小于这个时间的可以释放
		releaseTime := time.Now().Add(-1 * s.blockTime)
		// 安全的
		outs := make([]string, 0, len(s.tags))
		// 本次被释放的
		released := make([]string, 0, len(s.tags))
		for _, t := range s.tags {
			blockTime, ok := s.failedProxies.Load(t)
			// 没有错过
			if !ok {
				outs = append(outs, t)
			}
			// 刑满释放
			if ok && blockTime.(time.Time).Sub(releaseTime) < 0 {
				s.logger.Debug(t, " add to try list")
				// s.failedProxies.Delete(t)
				released = append(released, t)
			}
		}
		sort.Slice(released, func(i, j int) bool {
			iTime, iOk := s.failedProxies.Load(released[i])
			// 如果不存在i，i 排在前面
			if !iOk {
				return true
			}
			jTime, jOk := s.failedProxies.Load(released[j])
			// 如果 i 存在，j 不存在，j 排在前面
			if !jOk {
				return false
			}
			// 如果j 的时间比较大，说明j比较晚入狱，排在后面
			return jTime.(time.Time).After(iTime.(time.Time))
		})
		outs = append(outs, released...)
		if len(outs) == 0 {
			s.logger.Info("all node is blocked, use origin list")
			outs = s.tags
		}
		return outs, nil
	})
	return outs.([]string), err
}

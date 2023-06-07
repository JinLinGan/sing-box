package include

import (
	"context"
	"errors"
	"fmt"
	mDNS "github.com/miekg/dns"
	dns "github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"sync"
	"time"
)

func init() {
	dns.RegisterTransport([]string{"magic"}, func(name string, ctx context.Context, logger logger.ContextLogger, dialer N.Dialer, link string) (dns.Transport, error) {
		a, err := url.Parse(link)
		rs, ok := a.Query()["r"]
		if !ok {
			return nil, errors.New("not config ip range")
		}
		url, ok := a.Query()["u"]
		if !ok {
			return nil, errors.New("not config test url")
		}
		if err != nil {
			return nil, err
		}

		return &MagicDNS{
			logger:     logger,
			dialer:     dialer,
			name:       name,
			testURL:    url[0],
			testTimes:  3,
			concurrent: 2,
			dnsPipe:    make(chan netip.Addr, 1),
			netRanges:  rs,
		}, nil
	})

}

type MagicDNS struct {
	logger     logger.ContextLogger
	dialer     N.Dialer
	name       string
	testURL    string
	testTimes  int
	cacheSize  int
	dnsPipe    chan netip.Addr
	concurrent int
	netRanges  []string
}

func (m *MagicDNS) Name() string {
	return m.name
}

func (m *MagicDNS) Start() error {
	go m.StartFetch()
	return nil
}

func (m *MagicDNS) Close() error {
	return nil
}

func (m *MagicDNS) Raw() bool {
	return false
}

func (m *MagicDNS) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, nil
}

func (m *MagicDNS) Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	start := time.Now()
	timer := time.NewTimer(time.Second * 5)
	defer timer.Stop()
	select {
	case <-timer.C:

		m.logger.Warn(m.name, "解析", domain, "超时")
		return nil, errors.New(m.name + "- qurey " + domain + " timeout")
	case ip := <-m.dnsPipe:
		m.logger.Warn(m.name, "解析", domain, "使用", ip.String(), "耗时", time.Since(start))
		return []netip.Addr{ip}, nil
	}
}

func (m *MagicDNS) StartFetch() {

	ch := make(chan *net.IPAddr, m.concurrent*2)
	wg := sync.WaitGroup{}
	wg.Add(m.concurrent)
	for i := 0; i < m.concurrent; i++ {
		go func() {
			// defer recover

			defer func() {
				v := recover()
				if v != nil {
					debug.PrintStack()
					panic("panic on early close: " + fmt.Sprint(v))
				}
			}()
			defer wg.Done()
			for addr := range ch {

				success, duration := m.httping(addr, m.testURL)
				if success != m.testTimes {
					continue
				}
				a, _ := netip.AddrFromSlice(addr.IP)
				if duration/time.Duration(success) > time.Millisecond*600 {
					continue
					m.logger.Warn("延迟过高不使用")
				}
				m.logger.Warn("测试", addr.String(), "的延迟为", time.Duration(int(duration)/success), "，成功次数为", success, "/", m.testTimes)
				m.dnsPipe <- a
			}
		}()
	}
	for {

		for _, ip := range getIPList(m.netRanges) {
			ch <- ip
		}
	}
	wg.Wait()

}

func (m *MagicDNS) httping(ip *net.IPAddr, url string) (int, time.Duration) {
	hc := http.Client{
		Timeout: time.Second * 1,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return m.dialer.DialContext(ctx, network, M.ParseSocksaddr(ip.String()+":443"))
			},
			// TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 跳过证书验证
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 阻止重定向
		},
	}

	// 先访问一次获得 HTTP 状态码 及 Cloudflare Colo
	{
		requ, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return 0, 0
		}
		requ.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome")
		resp, err := hc.Do(requ)
		if err != nil {
			return 0, 0
		}
		defer resp.Body.Close()

		io.Copy(io.Discard, resp.Body)

	}

	// 循环测速计算延迟
	success := 0
	var delay time.Duration
	for i := 0; i < m.testTimes; i++ {
		requ, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			m.logger.Fatal("意外的错误，情报告：", err)
			return 0, 0
		}
		requ.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome")
		if i == m.testTimes-1 {
			requ.Header.Set("Connection", "close")
		}
		startTime := time.Now()
		resp, err := hc.Do(requ)
		if err != nil {
			continue
		}
		success++
		io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		duration := time.Since(startTime)
		delay += duration

	}

	return success, delay

}

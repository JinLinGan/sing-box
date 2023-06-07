package inbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	DirectForwardRequest = "direct-tcpip"
	DefautlServerVersion = "SSH-2.0-OpenSSH_7.4"
)

type SSH struct {
	myInboundAdapter
	config        *ssh.ServerConfig
	cqueue        chan net.Conn
	authenticator auth.Authenticator

	authorizedKeys [][]byte
}

func NewSSH(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSHInboundOptions) (*SSH, error) {
	inbound := &SSH{
		myInboundAdapter: myInboundAdapter{
			protocol:      C.TypeSSH,
			network:       []string{N.NetworkTCP},
			ctx:           ctx,
			router:        router,
			logger:        logger,
			tag:           tag,
			listenOptions: options.ListenOptions,
		},
		authenticator: auth.NewAuthenticator(options.Users),
	}
	inbound.connHandler = inbound

	for _, key := range options.ClientKeys {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			fmt.Printf("Failed to decode public key: %s\n", err.Error())
			continue
		}

		// Parse the public key
		parsedKey, err := ssh.ParsePublicKey(publicKeyBytes)
		if err != nil {
			fmt.Printf("Failed to parse public key: %s\n", err.Error())
			continue
		}

		i2 := parsedKey.Marshal()
		inbound.authorizedKeys = append(inbound.authorizedKeys, i2)
	}

	var signer ssh.Signer
	if options.PrivateKey != "" || options.PrivateKeyPath != "" {
		var privateKey []byte
		if options.PrivateKey != "" {
			privateKey = []byte(options.PrivateKey)
		} else {
			var err error
			privateKey, err = os.ReadFile(os.ExpandEnv(options.PrivateKeyPath))
			if err != nil {
				return nil, E.Cause(err, "read private key")
			}
		}
		var err error
		if options.PrivateKeyPassphrase == "" {
			signer, err = ssh.ParsePrivateKey(privateKey)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(options.PrivateKeyPassphrase))
		}
		if err != nil {
			return nil, E.Cause(err, "parse private key")
		}
	}
	if signer == nil {
		pair, err := tls.GenerateKeyPair(nil, "")
		if err != nil {
			return nil, E.Cause(err, "generate key pair")
		}
		signer, err = ssh.NewSignerFromKey(pair.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "new signer from auto generate key")
		}
	}

	config := &ssh.ServerConfig{
		PasswordCallback:  inbound.PasswordCallback,
		PublicKeyCallback: inbound.PublicKeyCallback,
	}
	if options.ServerVersion == "" {
		config.ServerVersion = DefautlServerVersion
	} else {
		config.ServerVersion = options.ServerVersion
	}
	config.AddHostKey(signer)
	// config.AddHostKey(l.md.signer)

	inbound.config = config
	return inbound, nil
}

func (i *SSH) PasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if i.authenticator.Verify(conn.User(), string(password)) {
		return nil, nil
	}
	return nil, fmt.Errorf("password rejected for %s", conn.User())
}

func (i *SSH) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	sc, chans, reqs, err := ssh.NewServerConn(conn, i.config)
	// go ssh.DiscardRequests(reqs)
	if err != nil {
		i.logger.Warn("new server conn: ", err)
		conn.Close()
		return E.Cause(err, "new server conn")
	}
	defer sc.Close()

	go func() {
		for newChannel := range chans {
			// Check the type of channel
			t := newChannel.ChannelType()
			switch t {
			case DirectForwardRequest:
				channel, requests, err := newChannel.Accept()
				if err != nil {
					i.logger.Warn("could not accept channel: %s", err.Error())
					continue
				}
				p := directForward{}
				ssh.Unmarshal(newChannel.ExtraData(), &p)

				// l.logger.Trace(p.String())

				if p.Host1 == "<nil>" {
					p.Host1 = ""
				}

				go ssh.DiscardRequests(requests)

				metadata.Destination = M.ParseSocksaddrHostPort(p.Host1, uint16(p.Port1))

				go i.newConnection(ctx, NewDirectForwardConn(sc, channel, net.JoinHostPort(p.Host1, strconv.Itoa(int(p.Port1)))), metadata)

			default:
				i.logger.Info("unsupported channel type: %s", t)
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unsupported channel type: %s", t))
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for req := range reqs {
			// switch req.Type {
			// case RemoteForwardRequest:
			// 	cc := sshd_util.NewRemoteForwardConn(ctx, sc, req)
			//
			// 	select {
			// 	case l.cqueue <- cc:
			// 	default:
			// 		l.logger.Warnf("connection queue is full, client %s discarded", conn.RemoteAddr())
			// 		req.Reply(false, []byte("connection queue is full"))
			// 		cc.Close()
			// 	}
			// default:
			i.logger.Warn("unsupported request type: ", req.Type, ", want reply: ", req.WantReply)
			req.Reply(false, nil)
			// }
		}
	}()
	sc.Wait()
	return nil
}

func (i *SSH) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}

func (i *SSH) PublicKeyCallback(conn ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
	for _, key := range i.authorizedKeys {

		pubkeyStr := pubkey.Marshal()
		if bytes.Equal(key, pubkeyStr) {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pubkey),
				},
			}, nil
		}
	}
	return nil, fmt.Errorf("unknown public key for %q", conn.User())

}

type directForward struct {
	Host1 string
	Port1 uint32
	Host2 string
	Port2 uint32
}

func (p directForward) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", p.Host2, p.Port2, p.Host1, p.Port1)
}

type DirectForwardConn struct {
	conn    ssh.Conn
	channel ssh.Channel
	dstAddr string
}

func NewDirectForwardConn(conn ssh.Conn, channel ssh.Channel, dstAddr string) net.Conn {
	return &DirectForwardConn{
		conn:    conn,
		channel: channel,
		dstAddr: dstAddr,
	}
}

func (c *DirectForwardConn) Read(b []byte) (n int, err error) {
	return c.channel.Read(b)
}

func (c *DirectForwardConn) Write(b []byte) (n int, err error) {
	return c.channel.Write(b)
}

func (c *DirectForwardConn) Close() error {
	return c.channel.Close()
}

func (c *DirectForwardConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *DirectForwardConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *DirectForwardConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *DirectForwardConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *DirectForwardConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *DirectForwardConn) DstAddr() string {
	return c.dstAddr
}

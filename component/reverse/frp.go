package reverse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"

	frpclient "github.com/fatedier/frp/client"
	frpproxy "github.com/fatedier/frp/client/proxy"
	frpconfig "github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	frplog "github.com/fatedier/frp/pkg/util/log"
	golog "github.com/fatedier/golib/log"
	"github.com/samber/lo"
)

type frpOption struct {
	outbound.BasicOption                // only dialer-proxy is used
	Config               map[string]any `proxy:"config"` // native frpc v1 config (serverAddr, auth, proxies, ...)
}

func parseFrp(t *Tunnel, mapping map[string]any, tunnel C.Tunnel) error {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	opt := frpOption{}
	if err := decoder.Decode(mapping, &opt); err != nil {
		return err
	}
	if len(opt.Config) == 0 {
		return errors.New("config is empty")
	}
	b, err := json.Marshal(opt.Config)
	if err != nil {
		return err
	}
	res, err := frpconfig.LoadClientConfigResultFromBytes(b, true)
	if err != nil {
		return err
	}
	common := res.Common
	common.LoginFailExit = lo.ToPtr(false) // keep retrying like any other mihomo component
	// frp falls back to $http_proxy, which usually points at mihomo itself; only honor an explicit proxyURL.
	if transport, _ := opt.Config["transport"].(map[string]any); transport["proxyURL"] == nil {
		common.Transport.ProxyURL = ""
	}

	proxies, visitors := frpconfig.FilterClientConfigurers(common, res.Proxies, res.Visitors)
	proxies = frpconfig.CompleteProxyConfigurers(proxies)
	visitors = frpconfig.CompleteVisitorConfigurers(visitors)
	if _, err := validation.ValidateAllClientConfig(common, proxies, visitors, nil); err != nil {
		return err
	}

	// The mihomo dialer carries tcp/websocket/wss; quic and kcp dial on their own.
	var connectorCreator func(context.Context, *v1.ClientCommonConfig) frpclient.Connector
	switch proto := common.Transport.Protocol; {
	case proto == "quic" || proto == "kcp":
		if opt.DialerProxy != "" {
			return fmt.Errorf("dialer-proxy does not support frp transport.protocol %s", proto)
		}
	case common.Transport.ProxyURL != "":
		if opt.DialerProxy != "" {
			return errors.New("dialer-proxy and transport.proxyURL are mutually exclusive")
		}
	default:
		opt.TunnelForAPI = tunnel
		d := opt.NewDialer(nil)
		connectorCreator = func(ctx context.Context, cfg *v1.ClientCommonConfig) frpclient.Connector {
			return frpclient.NewConnectorWithDialer(ctx, cfg, d.DialContext)
		}
	}

	// user sessions reach localIP:localPort through mihomo's rules instead of a direct dial
	localDialer := func(_ context.Context, cfg *v1.ProxyBaseConfig, network string, src net.Addr) (net.Conn, error) {
		target := socks5.ParseAddr(net.JoinHostPort(cfg.LocalIP, strconv.Itoa(cfg.LocalPort)))
		if target == nil {
			return nil, fmt.Errorf("invalid local address %s:%d", cfg.LocalIP, cfg.LocalPort)
		}
		additions := []inbound.Addition{inbound.WithInName(t.Name)}
		if network == "udp" {
			if src == nil {
				return nil, errors.New("udp session without user address")
			}
			return newUDPSession(tunnel, target, src, additions...), nil
		}
		if src != nil {
			additions = append(additions, inbound.WithSrcAddr(src))
		}
		local, remote := N.Pipe()
		go tunnel.HandleTCPConn(inbound.NewSocket(target, remote, C.FRP, additions...))
		return local, nil
	}

	var current atomic.Pointer[frpclient.Service]
	t.DialerProxy = opt.DialerProxy
	t.run = func(ctx context.Context) {
		ctx = frpproxy.WithLocalDialer(ctx, localDialer)
		t.retry(ctx, func(ctx context.Context, _ func()) error {
			src := source.NewConfigSource()
			if err := src.ReplaceAll(res.Proxies, res.Visitors); err != nil {
				return err
			}
			frplog.Logger = frplog.Logger.WithOptions(golog.WithLevel(frpLevel()))
			svc, err := frpclient.NewService(frpclient.ServiceOptions{
				Common:                 common,
				ConfigSourceAggregator: source.NewAggregator(src),
				ConnectorCreator:       connectorCreator,
			})
			if err != nil {
				return err
			}
			current.Store(svc)
			defer current.Store(nil)
			return svc.Run(ctx)
		})
	}
	// frp logs in and retries internally, so "running" means frps currently knows our proxies.
	t.detail = func(s *Status) {
		svc := current.Load()
		for _, p := range proxies {
			base := p.GetBaseConfig()
			f := ForwardStatus{Name: base.Name, Type: base.Type, Local: net.JoinHostPort(base.LocalIP, strconv.Itoa(base.LocalPort))}
			if base.Plugin.Type != "" {
				f.Local = "plugin:" + base.Plugin.Type
			}
			if svc != nil {
				if ws, ok := svc.StatusExporter().GetProxyStatus(base.Name); ok {
					f.Remote, f.State, f.Error = ws.RemoteAddr, ws.Phase, ws.Err
					if s.State == StateConnecting {
						s.State = StateRunning
					}
				}
			}
			s.Forwards = append(s.Forwards, f)
		}
	}
	return nil
}

// Route frp's global logger into mihomo's log. frp formats every line it is allowed to emit, so
// its level follows mihomo's; frpLevel is applied again whenever a tunnel starts.
func init() {
	frplog.Logger = frplog.Logger.WithOptions(golog.WithOutput(frpLogWriter{}), golog.WithLevel(frpLevel()), golog.WithCaller(false))
}

func frpLevel() golog.Level {
	switch log.Level() {
	case log.DEBUG:
		return golog.DebugLevel
	case log.INFO:
		return golog.InfoLevel
	case log.WARNING:
		return golog.WarnLevel
	default:
		return golog.ErrorLevel
	}
}

type frpLogWriter struct{}

// Write parses golib lines like "2006-01-02 15:04:05.000 [I] msg".
func (frpLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	level, msg := byte('I'), line
	if i := strings.Index(line, " ["); i >= 0 && len(line) > i+4 && line[i+3] == ']' {
		level, msg = line[i+2], strings.TrimSpace(line[i+4:])
	}
	switch level {
	case 'E':
		log.Errorln("[FRP] %s", msg)
	case 'W':
		log.Warnln("[FRP] %s", msg)
	case 'D', 'T':
		log.Debugln("[FRP] %s", msg)
	default:
		log.Infoln("[FRP] %s", msg)
	}
	return len(p), nil
}

package requester

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"

	"google.golang.org/grpc/credentials/insecure"

	"github.com/kinzaz/helpers/slices"
	//"gitlab.com/revoluterra-dev/common/helpers/slices"
	pb "github.com/kinzaz/types/pb/captcha"
	"google.golang.org/grpc"

	// "gitlab.com/revoluterra-dev/common/requester/cycletls"
	// hp "gitlab.com/revoluterra-dev/common/requester/proxy"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type (
	Requester struct {
		Cfg            *Config
		ctx            context.Context
		queriesCounter *uint64

		clientsMx     sync.Mutex
		clients       []*Client
		clientNoProxy *Client
		// uas           []*ApifyUA

		qMx    sync.RWMutex
		queues map[string]*queue
		logger *zap.SugaredLogger

		// proxy *hp.Cache

		captchaSolver pb.CaptchaClient

		httpCounter       *prometheus.CounterVec
		httpDuration      *prometheus.SummaryVec
		captchaCounter    *prometheus.CounterVec
		trottlerRPS       *prometheus.GaugeVec
		trottlerQueueSize *prometheus.GaugeVec
	}

	queue struct {
		r        *Requester
		input    chan *queueJob
		statuses chan int
		rps      int
		blocked  bool
		ctx      context.Context
	}

	Client struct {
		Transport http.RoundTripper
		Jar       http.CookieJar
		Timeout   time.Duration

		ID                    int
		WithoutCaptchaCounter *int64
		savedCookiesStr       string
		ProxyHost             string
		ProxyURL              string
	}

	queueJob struct {
		logger          *zap.SugaredLogger
		uri             *url.URL
		client          *Client
		headers         http.Header
		cookies         []*http.Cookie
		jar             http.CookieJar
		responseCookies string
		inData          []byte
		err             error
		code            int
		binary          bool
		data            []byte
		captchaFound    bool
		ready           chan struct{}
	}
)

// Используй готовую функцию WithoutCookies если куки не нужны

func NewRequester(ctx context.Context, cfg *Config, metricsNamespace string, getNCookies func(n int) ([]string, error), logger *zap.SugaredLogger) (*Requester, error) {
	r := Requester{
		queriesCounter: new(uint64),
		Cfg:            cfg,
		ctx:            ctx,
		queues:         make(map[string]*queue),
		logger:         logger.With("from", "requester"),
	}

	if r.Cfg.EnableMetrics {
		r.httpCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests",
		}, []string{"code", "proxy"})
		prometheus.Register(r.httpCounter)

		r.httpDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Namespace: metricsNamespace,
			Name:      "http_request_duration_seconds",
		}, []string{"segment"})
		prometheus.Register(r.httpDuration)

		r.captchaCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "captcha_counter",
		}, []string{"type", "status", "error", "proxy", "attempt"})
		prometheus.Register(r.captchaCounter)

		r.trottlerRPS = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "trottler_rps_counter",
		}, []string{"host", "client"})
		prometheus.Register(r.trottlerRPS)

		r.trottlerQueueSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "trottler_queue_size",
		}, []string{"host", "client"})
		prometheus.Register(r.trottlerQueueSize)
	}

	if r.Cfg.Proxy.Enabled {
		// dialCtx, cancelDial := context.WithTimeout(ctx, r.Cfg.Proxy.Timeout)
		// defer cancelDial()
		//proxConn, err := grpc.DialContext(dialCtx, fmt.Sprintf("%s:%d",
		//	r.Cfg.Proxy.Host,
		//	r.Cfg.Proxy.Port,
		//), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())

		//if err != nil {
		//	r.logger.Errorf("can't connect to proxy (%s:%d) grpc: %s",
		//		r.Cfg.Proxy.Host, r.Cfg.Proxy.Port, err.Error())
		//	return &r, fmt.Errorf("%w", err)
		//}

		//r.proxy = hp.NewProxyCache(
		//	ctx,
		//	r.Cfg.Proxy.Enabled,
		//	proxConn,
		//	r.Cfg.Proxy.List,
		//	0,
		//	r.logger.With("proxy", fmt.Sprintf("%s:%d", r.Cfg.Proxy.Host, r.Cfg.Proxy.Port)).Debugf)

	}

	if r.Cfg.Captcha.Enabled {
		addr := fmt.Sprintf("%s:%d", r.Cfg.Captcha.Solver.Host, r.Cfg.Captcha.Solver.Port)
		dCtx, cancelD := context.WithTimeout(context.Background(), r.Cfg.Captcha.Solver.Timeout)
		defer cancelD()

		conn, err := grpc.DialContext(dCtx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		if err != nil {
			err = fmt.Errorf("can't connect to captcha service grpc: %v", err)
			return &r, fmt.Errorf("%w", err)
		}
		r.captchaSolver = pb.NewCaptchaClient(conn)
	}

	if r.Cfg.EnableApifyUAs {
		//var err error
		//r.uas, err = r.LoadUAs()
		//if err != nil {
		//	return nil, fmt.Errorf("%w", err)
		//}
	}

	err := r.refreshClients(r.ctx, getNCookies)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if r.Cfg.RandomizeRoundrobinStart {
		atomic.StoreUint64(r.queriesCounter, uint64(rand.Intn(len(r.clients))))
	}
	go r.refreshClientsLoop(r.ctx, getNCookies)

	return &r, nil
}

func (r *Requester) getRoundTripper(proxy *url.URL) (http.RoundTripper, error) {
	dialer := &net.Dialer{
		Timeout: r.Cfg.QueryTimeout,
	}
	defaultTransport := http.Transport{
		TLSHandshakeTimeout: r.Cfg.QueryTimeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        r.Cfg.MaxIdleConns,
		IdleConnTimeout:     r.Cfg.IdleConnTimeout,
		Proxy:               http.ProxyURL(proxy),
		DialContext:         dialer.DialContext,
	}

	if r.Cfg.Trottler.Enabled {
		defaultTransport.MaxConnsPerHost = r.Cfg.Trottler.MaxRPS
	}

	var roundTripper http.RoundTripper = &defaultTransport

	if r.Cfg.Cycletls.Enabled {
		//ja3 := r.Cfg.Cycletls.Ja3
		//ua := r.Cfg.Cycletls.UA
		//if r.Cfg.Cycletls.Randomize {
		//	ja3 = ""
		//	ua = surferua.New().Desktop().String()
		//}
		//roundTripper = cycletls.ModifyRoundTripper(&defaultTransport, ja3, ua, r.Cfg.Cycletls.Randomize)
	}

	return roundTripper, nil
}

func (r *Requester) refreshClientsLoop(ctx context.Context, getNCookies func(n int) ([]string, error)) {
	r.logger.Debugf("started refresh loop")
	ticker := time.NewTicker(r.Cfg.ClientsRefreshTimeout)
	defer ticker.Stop()

Loop:
	for {
		select {
		case <-ctx.Done():
			break Loop
		case <-ticker.C:
			err := r.refreshClients(ctx, getNCookies)
			if err != nil {
				r.logger.Errorf("refresh clients error: %s", err.Error())
			}
		}
	}
}

func (r *Requester) refreshClients(ctx context.Context, getNCookies func(n int) ([]string, error)) error {
	clientsCount := r.Cfg.DefaultClientsCount

	var proxies []*url.URL
	if r.Cfg.Proxy.Enabled {
		//err := r.proxy.Refresh(ctx)
		//if err != nil {
		//	return fmt.Errorf("%w", err)
		//}
		//proxies = r.proxy.Proxies
		//if len(proxies) == 0 {
		//	return fmt.Errorf("proxy list is empty")
		//}
		//clientsCount = len(proxies)
	}

	// берем на одну куку больше для клиента без прокси
	cookies := make([]string, clientsCount+1)
	if getNCookies != nil {
		var err error
		cookies, err = getNCookies(clientsCount + 1)
		if err != nil {
			return fmt.Errorf("get cookies error")
		}
		if len(cookies) != clientsCount+1 {
			return fmt.Errorf("get cookies length mismatch")
		}
		r.logger.Infof("got %d new cookies", clientsCount+1)
	}

	newClient := func(i int, proxy *url.URL, proxyHost, proxyURL string) (*Client, error) {
		transport, err := r.getRoundTripper(proxy)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		jar, _ := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})

		return &Client{
			Timeout:   r.Cfg.QueryTimeout,
			Transport: transport,
			Jar:       jar,

			WithoutCaptchaCounter: new(int64),
			savedCookiesStr:       cookies[i],
			ID:                    i,
			ProxyHost:             proxyHost,
			ProxyURL:              proxyURL,
		}, nil
	}

	newClients := make([]*Client, clientsCount+1)
	for err := range slices.GoTryEach(newClients, runtime.NumCPU(), func(i int, _ *Client) error {
		var proxy *url.URL
		var proxyHost string
		var proxyURL string

		//последний клиент без прокси
		if i != clientsCount {
			if r.Cfg.Proxy.Enabled {
				proxy = proxies[i]
				proxyHost = proxy.Host
				proxyURL = proxy.String()
			} else if r.Cfg.TorProxy != "" {
				var err error
				proxy, err = url.Parse(r.Cfg.TorProxy)
				if err != nil {
					return err
				}
				proxyHost = proxy.Host
				proxyURL = r.Cfg.TorProxy
			}
		}

		if !r.Cfg.PreserveClientsOnRefresh {
			var err error

			newClients[i], err = newClient(i, proxy, proxyHost, proxyURL)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
		} else {
			if i >= len(r.clients) {
				var err error

				newClients[i], err = newClient(i, proxy, proxyHost, proxyURL)
				if err != nil {
					return fmt.Errorf("%w", err)
				}
			} else {
				newClients[i] = r.clients[i]
				if rt, ok := newClients[i].Transport.(*http.Transport); ok {
					rt.Proxy = http.ProxyURL(proxy)
				} else {
					// newClients[i].Transport.(*cycletls.RoundTripper).Transport.Proxy = http.ProxyURL(proxy)
				}
			}
		}

		return nil
	}) {
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}

	r.clients = newClients[:len(newClients)-1]
	r.clientNoProxy = newClients[len(newClients)-1]
	runtime.GC()

	return nil
}

func (r *Requester) GetClient() (*Client, error) {
	if len(r.clients) == 0 {
		return nil, fmt.Errorf("no clients avaliable")
	}
	return r.clients[atomic.AddUint64(r.queriesCounter, 1)%uint64(len(r.clients))], nil
}

//
//func (r *Requester) GetTrottledClient(parsedUri *url.URL) (*Client, error) {
//	if !r.Cfg.Trottler.Enabled {
//		return r.GetClient()
//	}
//
//	if len(r.clients) == 0 {
//		return nil, fmt.Errorf("no clients avaliable")
//	}
//
//	ctx, cancel := context.WithTimeout(r.ctx, r.Cfg.Trottler.WaitClientTimeout)
//	defer cancel()
//
//	r.clientsMx.Lock()
//	defer r.clientsMx.Unlock()
//
//Loop:
//	for {
//		select {
//		case <-ctx.Done():
//			return nil, fmt.Errorf("no clients avaliable")
//		default:
//			client := r.clients[atomic.AddUint64(r.queriesCounter, 1)%uint64(len(r.clients))]
//			if r.IsQueueBlocked(client, parsedUri) {
//				continue Loop
//			}
//			return client, nil
//		}
//	}
//}

func (r *Requester) GetClientById(id int) (*Client, error) {
	if id >= len(r.clients) {
		return nil, fmt.Errorf("no clients avaliable")
	}
	return r.clients[id], nil
}

//func (r *Requester) GetTrottledClientNoProxy(parsedUri *url.URL) (*Client, error) {
//	client := r.clientNoProxy
//	if r.IsQueueBlocked(client, parsedUri) {
//		return nil, fmt.Errorf("no clients avaliable")
//	}
//
//	return client, nil
//}

func (r *Requester) GetClientNoProxy() *Client {
	return r.clientNoProxy
}

func (r *Requester) GetClientsCount() int {
	return len(r.clients)
}

func (r *Requester) IsProxyEnabled() bool {
	return r.Cfg.Proxy.Enabled
}

func (c *Client) GetHttpClient() *http.Client {
	return &http.Client{
		Transport: c.Transport,
		Timeout:   c.Timeout,
		Jar:       c.Jar,
	}
}

//func (r *Requester) GetUA() (*ApifyUA, error) {
//	if len(r.uas) == 0 {
//		return nil, fmt.Errorf("no uas avaliable")
//	}
//	return r.uas[rand.Intn(len(r.uas))], nil
//}

//func (r *Requester) GetUA4HwType(hwType string) (*ApifyUA, error) {
//	typedUAs := slices.Filter(r.uas, func(_ int, ua *ApifyUA) bool {
//		return ua.HardwareType == hwType
//	})
//
//	if len(typedUAs) == 0 {
//		return nil, fmt.Errorf("no uas avaliable for hw type: %s", hwType)
//	}
//
//	return typedUAs[rand.Intn(len(typedUAs))], nil
//}

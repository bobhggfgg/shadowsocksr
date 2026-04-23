package ssr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	ssrconn "github.com/v2rayA/shadowsocksR"
	"github.com/v2rayA/shadowsocksR/obfs"
	"github.com/v2rayA/shadowsocksR/protocol"
	ssrinfo "github.com/v2rayA/shadowsocksR/ssr"
	"github.com/v2rayA/shadowsocksR/streamCipher"
	"github.com/v2rayA/shadowsocksR/tools/socks"
)

var _ vCore.Core = (*SSR)(nil)

var (
	supportedCiphers = map[string]struct{}{
		"aes-128-cfb": {},
	}
	supportedProtocols = map[string]struct{}{
		"auth_aes128_md5": {},
	}
	supportedObfs = map[string]struct{}{
		"http_simple": {},
	}
)

type SSR struct {
	mu        sync.RWMutex
	statePath string
	enableUDP bool
	nodes     map[string]*NodeState
}

type NodeState struct {
	Info          *panel.NodeInfo         `json:"info"`
	Users         map[int]panel.UserInfo  `json:"users"`
	Traffic       map[int]*TrafficCounter `json:"traffic"`
	ListenIP      string                  `json:"listen_ip"`
	PrimaryUser   int                     `json:"primary_user"`
	listener      net.Listener
	cancel        context.CancelFunc
	protocolParam string
	obfsParam     string
}

type TrafficCounter struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type ssrParam struct {
	Param string `json:"param"`
}

func init() {
	vCore.RegisterCore("ssr", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	cfg := c.SsrConfig
	if cfg == nil {
		cfg = conf.NewSsrConfig()
	}
	return &SSR{
		statePath: cfg.StatePath,
		enableUDP: cfg.EnableUDP,
		nodes:     make(map[string]*NodeState),
	}, nil
}

func (s *SSR) Protocols() []string {
	return []string{"shadowsocksr"}
}

func (s *SSR) Type() string {
	return "ssr"
}

func (s *SSR) Start() error {
	return nil
}

func (s *SSR) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for tag := range s.nodes {
		if err := s.closeNodeLocked(tag); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *SSR) AddNode(tag string, info *panel.NodeInfo, option *conf.Options) error {
	if info == nil || info.ShadowsocksR == nil || info.Common == nil {
		return errors.New("ssr core requires a shadowsocksr node")
	}
	if info.Common.ServerPort <= 0 {
		return errors.New("ssr node server_port is invalid")
	}
	if _, ok := supportedCiphers[info.ShadowsocksR.Cipher]; !ok {
		return fmt.Errorf("unsupported ssr cipher: %s", info.ShadowsocksR.Cipher)
	}
	if _, ok := supportedProtocols[info.ShadowsocksR.Protocol]; !ok {
		return fmt.Errorf("unsupported ssr protocol: %s", info.ShadowsocksR.Protocol)
	}
	if _, ok := supportedObfs[info.ShadowsocksR.Obfs]; !ok {
		return fmt.Errorf("unsupported ssr obfs: %s", info.ShadowsocksR.Obfs)
	}

	listenIP := "0.0.0.0"
	if option != nil && option.ListenIP != "" {
		listenIP = option.ListenIP
	}

	node := &NodeState{
		Info:          info,
		Users:         make(map[int]panel.UserInfo),
		Traffic:       make(map[int]*TrafficCounter),
		ListenIP:      listenIP,
		protocolParam: decodeParam(info.ShadowsocksR.ProtocolSettings),
		obfsParam:     decodeParam(info.ShadowsocksR.ObfsSettings),
	}

	addr := net.JoinHostPort(listenIP, strconv.Itoa(info.Common.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen ssr on %s error: %w", addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	node.listener = ln
	node.cancel = cancel

	s.mu.Lock()
	if old, ok := s.nodes[tag]; ok {
		_ = s.closeNodeLocked(tag)
		_ = old
	}
	s.nodes[tag] = node
	s.mu.Unlock()

	go s.serveNode(ctx, tag, node)
	return nil
}

func (s *SSR) DelNode(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeNodeLocked(tag)
}

func (s *SSR) AddUsers(p *vCore.AddUsersParams) (int, error) {
	if p == nil {
		return 0, errors.New("add users params is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[p.Tag]
	if !ok {
		return 0, errors.New("the node is not have")
	}

	added := 0
	for _, user := range p.Users {
		if _, exists := node.Users[user.Id]; !exists {
			added++
		}
		node.Users[user.Id] = user
		if _, exists := node.Traffic[user.Id]; !exists {
			node.Traffic[user.Id] = &TrafficCounter{}
		}
	}
	node.PrimaryUser = choosePrimaryUser(node.Users, node.PrimaryUser)
	return added, nil
}

func (s *SSR) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[tag]
	if !ok {
		return nil, errors.New("the node is not have")
	}

	traffic := make([]panel.UserTraffic, 0, len(node.Traffic))
	for uid, counter := range node.Traffic {
		if counter == nil || (counter.Upload == 0 && counter.Download == 0) {
			continue
		}
		traffic = append(traffic, panel.UserTraffic{
			UID:      uid,
			Upload:   counter.Upload,
			Download: counter.Download,
		})
		if reset {
			counter.Upload = 0
			counter.Download = 0
		}
	}
	return traffic, nil
}

func (s *SSR) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[tag]
	if !ok {
		return errors.New("the node is not have")
	}
	for _, user := range users {
		delete(node.Users, user.Id)
		delete(node.Traffic, user.Id)
	}
	node.PrimaryUser = choosePrimaryUser(node.Users, node.PrimaryUser)
	return nil
}

func (s *SSR) closeNodeLocked(tag string) error {
	node, ok := s.nodes[tag]
	if !ok {
		return errors.New("the node is not have")
	}
	if node.cancel != nil {
		node.cancel()
	}
	var err error
	if node.listener != nil {
		err = node.listener.Close()
	}
	delete(s.nodes, tag)
	return err
}

func (s *SSR) serveNode(ctx context.Context, tag string, node *NodeState) {
	for {
		conn, err := node.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		go s.handleConn(ctx, tag, node, conn)
	}
}

func (s *SSR) handleConn(ctx context.Context, tag string, node *NodeState, rawConn net.Conn) {
	defer rawConn.Close()

	prefix, err := preloadPrefix(rawConn, 64*1024, 200*time.Millisecond)
	if err != nil {
		return
	}

	userID, password, traffic, targetPreview, err := s.selectUser(node, prefix)
	if err != nil {
		return
	}

	replay := newReplayConn(prefix, rawConn)
	ssrConn, err := s.wrapConn(replay, node, password)
	if err != nil {
		return
	}

	targetAddr, err := socks.ReadAddr(ssrConn)
	if err != nil {
		if targetPreview != nil {
			targetAddr = targetPreview
		} else {
			return
		}
	}

	targetConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", targetAddr.String())
	if err != nil {
		return
	}
	defer targetConn.Close()

	var upBytes int64
	var downBytes int64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(targetConn, ssrConn)
		atomic.AddInt64(&upBytes, n)
		if tcp, ok := targetConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(ssrConn, targetConn)
		atomic.AddInt64(&downBytes, n)
		if tcp, ok := rawConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	if traffic != nil {
		traffic.Upload += atomic.LoadInt64(&upBytes)
		traffic.Download += atomic.LoadInt64(&downBytes)
	}
	_ = userID
	_ = tag
}

func (s *SSR) primaryUser(node *NodeState) (int, string, *TrafficCounter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if node.PrimaryUser == 0 {
		node.PrimaryUser = choosePrimaryUser(node.Users, node.PrimaryUser)
	}
	user, ok := node.Users[node.PrimaryUser]
	if !ok {
		return 0, "", nil, errors.New("no ssr user available")
	}
	if _, ok := node.Traffic[user.Id]; !ok {
		node.Traffic[user.Id] = &TrafficCounter{}
	}
	return user.Id, user.Uuid, node.Traffic[user.Id], nil
}

func (s *SSR) selectUser(node *NodeState, prefix []byte) (int, string, *TrafficCounter, socks.Addr, error) {
	type candidate struct {
		id       int
		password string
		traffic  *TrafficCounter
	}

	s.mu.Lock()
	candidates := make([]candidate, 0, len(node.Users))
	ids := make([]int, 0, len(node.Users))
	for id := range node.Users {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		user := node.Users[id]
		if _, ok := node.Traffic[id]; !ok {
			node.Traffic[id] = &TrafficCounter{}
		}
		candidates = append(candidates, candidate{
			id:       id,
			password: user.Uuid,
			traffic:  node.Traffic[id],
		})
	}
	s.mu.Unlock()

	if len(candidates) == 0 {
		return 0, "", nil, nil, errors.New("no ssr user available")
	}

	for _, item := range candidates {
		addr, err := s.tryUser(node, prefix, item.password)
		if err == nil {
			return item.id, item.password, item.traffic, addr, nil
		}
	}

	id, password, traffic, err := s.primaryUser(node)
	return id, password, traffic, nil, err
}

func (s *SSR) tryUser(node *NodeState, prefix []byte, password string) (socks.Addr, error) {
	mem := newMemoryConn(prefix)
	ssrConn, err := s.wrapConn(mem, node, password)
	if err != nil {
		return nil, err
	}
	return socks.ReadAddr(ssrConn)
}

func (s *SSR) wrapConn(rawConn net.Conn, node *NodeState, password string) (net.Conn, error) {
	cipher, err := streamCipher.NewStreamCipher(node.Info.ShadowsocksR.Cipher, password)
	if err != nil {
		return nil, err
	}

	ob := obfs.NewObfs(node.Info.ShadowsocksR.Obfs)
	proto := protocol.NewProtocol(node.Info.ShadowsocksR.Protocol)
	if ob == nil {
		return nil, fmt.Errorf("unsupported obfs %s", node.Info.ShadowsocksR.Obfs)
	}
	if proto == nil {
		return nil, fmt.Errorf("unsupported protocol %s", node.Info.ShadowsocksR.Protocol)
	}

	serverPort := node.Info.Common.ServerPort
	serverInfo := &ssrinfo.ServerInfo{
		Host:    node.Info.Common.Host,
		Port:    uint16(serverPort),
		Param:   node.obfsParam,
		IVLen:   cipher.InfoIVLen(),
		Key:     cipher.Key(),
		KeyLen:  cipher.InfoKeyLen(),
		TcpMss:  1460,
		HeadLen: 30,
	}
	obInfo := *serverInfo
	obInfo.Param = node.obfsParam
	protoInfo := *serverInfo
	protoInfo.Param = node.protocolParam
	ob.SetServerInfo(&obInfo)
	proto.SetServerInfo(&protoInfo)

	conn := ssrconn.NewSSTCPConn(rawConn, cipher)
	conn.IObfs = ob
	conn.IProtocol = proto
	return conn, nil
}

func decodeParam(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var p ssrParam
	if err := json.Unmarshal(raw, &p); err == nil && p.Param != "" {
		return p.Param
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

func choosePrimaryUser(users map[int]panel.UserInfo, current int) int {
	if current != 0 {
		if _, ok := users[current]; ok {
			return current
		}
	}
	if len(users) == 0 {
		return 0
	}
	ids := make([]int, 0, len(users))
	for id := range users {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids[0]
}

func preloadPrefix(conn net.Conn, maxBytes int, idle time.Duration) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	buf := make([]byte, 0, maxBytes)
	tmp := make([]byte, 4096)
	for len(buf) < maxBytes {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return nil, err
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if n < len(tmp) {
				break
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			if errors.Is(err, io.EOF) {
				break
			}
			_ = conn.SetReadDeadline(time.Time{})
			return nil, err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return buf, nil
}

type memoryConn struct {
	reader *bytes.Reader
}

func newMemoryConn(data []byte) net.Conn {
	copied := append([]byte(nil), data...)
	return &memoryConn{reader: bytes.NewReader(copied)}
}

func (m *memoryConn) Read(b []byte) (int, error)       { return m.reader.Read(b) }
func (m *memoryConn) Write(_ []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (m *memoryConn) Close() error                     { return nil }
func (m *memoryConn) LocalAddr() net.Addr              { return dummyAddr("memory-local") }
func (m *memoryConn) RemoteAddr() net.Addr             { return dummyAddr("memory-remote") }
func (m *memoryConn) SetDeadline(time.Time) error      { return nil }
func (m *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type replayConn struct {
	net.Conn
	reader *bytes.Reader
}

func newReplayConn(prefix []byte, raw net.Conn) net.Conn {
	copied := append([]byte(nil), prefix...)
	return &replayConn{
		Conn:   raw,
		reader: bytes.NewReader(copied),
	}
}

func (r *replayConn) Read(b []byte) (int, error) {
	if r.reader != nil && r.reader.Len() > 0 {
		return r.reader.Read(b)
	}
	return r.Conn.Read(b)
}

type dummyAddr string

func (d dummyAddr) Network() string { return "memory" }
func (d dummyAddr) String() string  { return string(d) }

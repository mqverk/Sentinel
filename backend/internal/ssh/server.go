package ssh

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/domain"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/store"
)

type directTCPIPRequest struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type Server struct {
	log      *slog.Logger
	store    store.Store
	auth     *auth.Service
	policy   *policy.Engine
	sessions *session.Service
	audit    *audit.Service
}

func NewServer(
	log *slog.Logger,
	st store.Store,
	authService *auth.Service,
	policyEngine *policy.Engine,
	sessionService *session.Service,
	auditService *audit.Service,
) *Server {
	return &Server{
		log:      log,
		store:    st,
		auth:     authService,
		policy:   policyEngine,
		sessions: sessionService,
		audit:    auditService,
	}
}

func (s *Server) Start(ctx context.Context, addr string) error {
	signer, err := generateHostSigner()
	if err != nil {
		return err
	}

	sshConfig := &ssh.ServerConfig{
		ServerVersion:    "SSH-2.0-Sentinel",
		PasswordCallback: s.passwordCallback,
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	s.log.Info("ssh bastion started", slog.String("address", addr))

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.log.Warn("ssh accept failed", slog.Any("error", err))
			continue
		}

		go s.handleConnection(rawConn, sshConfig)
	}
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	user, roles, err := s.auth.AuthenticatePassword(context.Background(), conn.User(), string(password))
	if err != nil {
		_ = s.audit.Record(context.Background(), audit.NewEntry(
			"",
			conn.User(),
			"ssh.auth",
			"bastion",
			"denied",
			remoteIP(conn.RemoteAddr().String()),
			map[string]any{"reason": err.Error()},
		))
		return nil, errors.New("authentication failed")
	}

	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}

	_ = s.audit.Record(context.Background(), audit.NewEntry(
		user.ID,
		user.Username,
		"ssh.auth",
		"bastion",
		"success",
		remoteIP(conn.RemoteAddr().String()),
		map[string]any{"roles": roleNames},
	))

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user_id":    user.ID,
			"username":   user.Username,
			"role_names": strings.Join(roleNames, ","),
		},
	}, nil
}

func (s *Server) handleConnection(rawConn net.Conn, cfg *ssh.ServerConfig) {
	defer rawConn.Close()

	conn, channels, requests, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		s.log.Warn("ssh handshake failed", slog.Any("error", err), slog.String("remote", rawConn.RemoteAddr().String()))
		return
	}
	defer conn.Close()

	userID, username := connectionIdentity(conn)
	remote := remoteIP(conn.RemoteAddr().String())

	_ = s.audit.Record(context.Background(), audit.NewEntry(
		userID,
		username,
		"ssh.connect",
		"bastion",
		"success",
		remote,
		nil,
	))

	go ssh.DiscardRequests(requests)

	for channel := range channels {
		switch channel.ChannelType() {
		case "direct-tcpip":
			go s.handleDirectTCPIP(conn, channel)
		case "session":
			go s.handleSessionShell(conn, channel)
		default:
			_ = channel.Reject(ssh.UnknownChannelType, "channel type is not supported")
		}
	}

	_ = s.audit.Record(context.Background(), audit.NewEntry(
		userID,
		username,
		"ssh.disconnect",
		"bastion",
		"success",
		remote,
		nil,
	))
}

func (s *Server) handleDirectTCPIP(conn *ssh.ServerConn, newChannel ssh.NewChannel) {
	var req directTCPIPRequest
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		_ = newChannel.Reject(ssh.Prohibited, "invalid direct-tcpip payload")
		return
	}

	userID, username := connectionIdentity(conn)
	remote := remoteIP(conn.RemoteAddr().String())

	roles, err := s.store.ListUserRoles(context.Background(), userID)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to resolve roles")
		return
	}

	host, err := s.store.GetHostByAddress(context.Background(), req.DestAddr, int(req.DestPort))
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "destination host is not registered")
		return
	}

	if !s.policy.CanAccessHost(roles, host) {
		_ = s.audit.Record(context.Background(), audit.NewEntry(
			userID,
			username,
			"ssh.tunnel",
			host.Name,
			"denied",
			remote,
			map[string]any{"destination": fmt.Sprintf("%s:%d", req.DestAddr, req.DestPort)},
		))
		_ = newChannel.Reject(ssh.Prohibited, "host access denied")
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(req.DestAddr, strconv.Itoa(int(req.DestPort))), 8*time.Second)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to connect destination")
		return
	}
	defer upstream.Close()

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	sessionEntry, sessionErr := s.sessions.Start(context.Background(), session.StartInput{
		UserID:   userID,
		Username: username,
		HostID:   host.ID,
		HostName: host.Name,
		SourceIP: remote,
		Protocol: domain.SessionProtocolSSHTunnel,
		Status:   domain.SessionStatusActive,
	})
	if sessionErr != nil {
		s.log.Warn("failed to create tunnel session record", slog.Any("error", sessionErr))
	}

	uplinkBytes, downlinkBytes, proxyErr := proxyBidirectional(channel, upstream)
	status := domain.SessionStatusClosed
	if proxyErr != nil {
		status = domain.SessionStatusFailed
	}

	if sessionEntry.ID != "" {
		replay := fmt.Sprintf("destination=%s:%d source=%s:%d uplink_bytes=%d downlink_bytes=%d", req.DestAddr, req.DestPort, req.OriginAddr, req.OriginPort, uplinkBytes, downlinkBytes)
		_ = s.sessions.End(context.Background(), sessionEntry.ID, status, replay)
	}
}

func (s *Server) handleSessionShell(conn *ssh.ServerConn, newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	ready := make(chan struct{}, 1)
	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
				select {
				case ready <- struct{}{}:
				default:
				}
			default:
				req.Reply(false, nil)
			}
		}
	}()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
	}

	userID, username := connectionIdentity(conn)
	remote := remoteIP(conn.RemoteAddr().String())

	sessionEntry, sessionErr := s.sessions.Start(context.Background(), session.StartInput{
		UserID:   userID,
		Username: username,
		HostID:   "bastion-shell",
		HostName: "bastion-shell",
		SourceIP: remote,
		Protocol: domain.SessionProtocolSSHShell,
		Status:   domain.SessionStatusActive,
	})
	if sessionErr != nil {
		s.log.Warn("failed to create shell session record", slog.Any("error", sessionErr))
	}

	roles, _ := s.store.ListUserRoles(context.Background(), userID)

	transcript := strings.Builder{}
	_, _ = io.WriteString(channel, "\r\nSentinel Bastion Shell\r\n")
	_, _ = io.WriteString(channel, "Type 'help' for available commands.\r\n\r\n")

	scanner := bufio.NewScanner(channel)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for {
		_, _ = io.WriteString(channel, "sentinel> ")
		if !scanner.Scan() {
			break
		}

		command := strings.TrimSpace(scanner.Text())
		transcript.WriteString(time.Now().UTC().Format(time.RFC3339) + " " + command + "\n")

		switch {
		case command == "":
			continue
		case command == "help":
			_, _ = io.WriteString(channel, "commands: help, hosts, connect <host-id>, exit\r\n")
		case command == "hosts":
			hosts, err := s.store.ListHosts(context.Background())
			if err != nil {
				_, _ = io.WriteString(channel, "failed to list hosts\r\n")
				continue
			}
			for _, host := range hosts {
				line := fmt.Sprintf("- %s (%s:%d) env=%s active=%t\r\n", host.ID, host.Address, host.Port, host.Environment, host.Active)
				_, _ = io.WriteString(channel, line)
			}
		case strings.HasPrefix(command, "connect "):
			hostID := strings.TrimSpace(strings.TrimPrefix(command, "connect "))
			host, err := s.store.GetHostByID(context.Background(), hostID)
			if err != nil {
				_, _ = io.WriteString(channel, "host not found\r\n")
				continue
			}

			if !s.policy.CanAccessHost(roles, host) {
				_, _ = io.WriteString(channel, "access denied by policy\r\n")
				_ = s.audit.Record(context.Background(), audit.NewEntry(
					userID,
					username,
					"ssh.shell.connect_hint",
					host.Name,
					"denied",
					remote,
					map[string]any{"hostId": host.ID},
				))
				continue
			}

			message := fmt.Sprintf("connect using: ssh -J %s@<sentinel-host> <target-user>@%s -p %d\r\n", username, host.Address, host.Port)
			_, _ = io.WriteString(channel, message)
			_ = s.audit.Record(context.Background(), audit.NewEntry(
				userID,
				username,
				"ssh.shell.connect_hint",
				host.Name,
				"success",
				remote,
				map[string]any{"hostId": host.ID},
			))
		case command == "exit" || command == "quit":
			_, _ = io.WriteString(channel, "bye\r\n")
			goto done
		default:
			_, _ = io.WriteString(channel, "unknown command\r\n")
		}
	}

done:
	status := domain.SessionStatusClosed
	if err := scanner.Err(); err != nil {
		status = domain.SessionStatusFailed
	}

	if sessionEntry.ID != "" {
		_ = s.sessions.End(context.Background(), sessionEntry.ID, status, transcript.String())
	}
}

func generateHostSigner() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(privateKey)
}

func connectionIdentity(conn *ssh.ServerConn) (userID, username string) {
	username = conn.User()
	if conn.Permissions == nil {
		return "", username
	}

	if storedUser := strings.TrimSpace(conn.Permissions.Extensions["username"]); storedUser != "" {
		username = storedUser
	}

	return strings.TrimSpace(conn.Permissions.Extensions["user_id"]), username
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return strings.TrimSpace(remoteAddr)
	}

	return host
}

func proxyBidirectional(channel ssh.Channel, upstream net.Conn) (int64, int64, error) {
	errCh := make(chan error, 2)
	bytesToUpstream := int64(0)
	bytesToChannel := int64(0)

	go func() {
		n, err := io.Copy(upstream, channel)
		bytesToUpstream = n
		closeWrite(upstream)
		errCh <- err
	}()

	go func() {
		n, err := io.Copy(channel, upstream)
		bytesToChannel = n
		closeWrite(channel)
		errCh <- err
	}()

	err1 := <-errCh
	err2 := <-errCh

	if !isCopyDone(err1) {
		return bytesToUpstream, bytesToChannel, err1
	}

	if !isCopyDone(err2) {
		return bytesToUpstream, bytesToChannel, err2
	}

	return bytesToUpstream, bytesToChannel, nil
}

func closeWrite(value any) {
	if closeWriter, ok := value.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
}

func isCopyDone(err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "closed")
}

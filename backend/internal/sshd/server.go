package sshd

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"sentinel/backend/internal/audit"
	"sentinel/backend/internal/auth"
	"sentinel/backend/internal/config"
	"sentinel/backend/internal/model"
	"sentinel/backend/internal/policy"
	"sentinel/backend/internal/session"
	"sentinel/backend/internal/storage"
)

type Server struct {
	cfg            config.SSHConfig
	logger         *slog.Logger
	authService    *auth.Service
	policyEngine   *policy.Engine
	sessionService *session.Service
	auditService   *audit.Service
	store          storage.Store
	listener       net.Listener
}

func NewServer(
	cfg config.SSHConfig,
	logger *slog.Logger,
	authService *auth.Service,
	policyEngine *policy.Engine,
	sessionService *session.Service,
	auditService *audit.Service,
	store storage.Store,
) *Server {
	return &Server{
		cfg:            cfg,
		logger:         logger,
		authService:    authService,
		policyEngine:   policyEngine,
		sessionService: sessionService,
		auditService:   auditService,
		store:          store,
	}
}

func (s *Server) Start() error {
	signer, err := loadOrCreateHostSigner(s.cfg.HostKeyPath)
	if err != nil {
		return fmt.Errorf("load host key: %w", err)
	}

	sshConfig := &ssh.ServerConfig{
		PasswordCallback: s.passwordCallback,
		ServerVersion:    "SSH-2.0-SentinelBastion",
		BannerCallback: func(_ ssh.ConnMetadata) string {
			return s.cfg.Banner + "\n"
		},
		MaxAuthTries: s.cfg.MaxAuthTries,
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen ssh: %w", err)
	}
	s.listener = listener
	s.logger.Info("starting ssh bastion", "addr", s.cfg.ListenAddr)

	for {
		netConn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Error("accept ssh connection failed", "error", err.Error())
			continue
		}
		go s.handleConnection(netConn, sshConfig)
	}
}

func (s *Server) Shutdown() error {
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	principal, err := s.authService.AuthenticatePassword(context.Background(), conn.User(), string(password))
	if err != nil {
		s.auditService.Log(context.Background(), audit.Event{
			ActorID:       "anonymous",
			ActorUsername: conn.User(),
			Action:        "ssh.login",
			Resource:      "ssh",
			Outcome:       "deny",
			SourceIP:      conn.RemoteAddr().String(),
			Details:       map[string]any{"reason": err.Error()},
		})
		return nil, errors.New("authentication failed")
	}

	s.auditService.Log(context.Background(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "ssh.login",
		Resource:      "ssh",
		Outcome:       "allow",
		SourceIP:      conn.RemoteAddr().String(),
		Details:       map[string]any{"roles": principal.Roles},
	})

	return &ssh.Permissions{Extensions: map[string]string{
		"user_id":     principal.UserID,
		"username":    principal.Username,
		"roles":       strings.Join(principal.Roles, ","),
		"permissions": strings.Join(principal.Permissions, ","),
	}}, nil
}

func (s *Server) handleConnection(netConn net.Conn, cfg *ssh.ServerConfig) {
	if s.cfg.IdleTimeout > 0 {
		_ = netConn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout))
	}

	serverConn, chans, requests, err := ssh.NewServerConn(netConn, cfg)
	if err != nil {
		s.logger.Warn("ssh handshake failed", "error", err.Error())
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)

	principal := principalFromExtensions(serverConn.Permissions)
	for channelRequest := range chans {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			s.logger.Error("accept channel failed", "error", err.Error())
			continue
		}
		go s.handleSessionChannel(channel, channelRequests, principal, serverConn.RemoteAddr().String())
	}
}

func (s *Server) handleSessionChannel(channel ssh.Channel, requests <-chan *ssh.Request, principal auth.Principal, remoteAddr string) {
	defer channel.Close()

	metadataJSON, _ := json.Marshal(map[string]any{"remoteAddr": remoteAddr, "username": principal.Username})
	sessionEntry, err := s.sessionService.StartSession(context.Background(), principal.UserID, "host-bastion", string(metadataJSON))
	if err != nil {
		io.WriteString(channel, "Failed to start sentinel session\n")
		s.logger.Error("start ssh session failed", "error", err.Error())
		return
	}
	start := time.Now()
	defer func() {
		_ = s.sessionService.EndSession(context.Background(), sessionEntry.ID)
		s.auditService.Log(context.Background(), audit.Event{
			ActorID:       principal.UserID,
			ActorUsername: principal.Username,
			Action:        "ssh.session.end",
			Resource:      "ssh",
			Outcome:       "allow",
			SourceIP:      remoteAddr,
			Details:       map[string]any{"sessionID": sessionEntry.ID},
		})
	}()

	s.auditService.Log(context.Background(), audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "ssh.session.start",
		Resource:      "ssh",
		Outcome:       "allow",
		SourceIP:      remoteAddr,
		Details:       map[string]any{"sessionID": sessionEntry.ID},
	})

	for req := range requests {
		switch req.Type {
		case "pty-req":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			s.runShell(channel, principal, sessionEntry, start)
			return
		case "exec":
			req.Reply(true, nil)
			command := parseExecCommand(req.Payload)
			s.runCommand(channel, principal, sessionEntry, start, command)
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) runShell(channel ssh.Channel, principal auth.Principal, sessionEntry *model.Session, start time.Time) {
	banner := "Sentinel Bastion Shell\nType 'help' for commands.\n"
	_, _ = io.WriteString(channel, banner)
	_ = s.sessionService.RecordFrame(sessionEntry.RecordingPath, start, "stdout", []byte(banner))

	scanner := bufio.NewScanner(channel)
	for {
		_, _ = io.WriteString(channel, "sentinel> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		_ = s.sessionService.RecordFrame(sessionEntry.RecordingPath, start, "stdin", []byte(line+"\n"))
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			_, _ = io.WriteString(channel, "Bye.\n")
			_ = s.sessionService.RecordFrame(sessionEntry.RecordingPath, start, "stdout", []byte("Bye.\n"))
			return
		}

		output := s.executeCommand(context.Background(), principal, line)
		_, _ = io.WriteString(channel, output)
		_ = s.sessionService.RecordFrame(sessionEntry.RecordingPath, start, "stdout", []byte(output))
	}
}

func (s *Server) runCommand(channel ssh.Channel, principal auth.Principal, sessionEntry *model.Session, start time.Time, command string) {
	_ = s.sessionService.RecordFrame(sessionEntry.RecordingPath, start, "stdin", []byte(command+"\n"))
	output := s.executeCommand(context.Background(), principal, strings.TrimSpace(command))
	_, _ = io.WriteString(channel, output)
	_ = s.sessionService.RecordFrame(sessionEntry.RecordingPath, start, "stdout", []byte(output))
}

func (s *Server) executeCommand(ctx context.Context, principal auth.Principal, command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}

	s.auditService.Log(ctx, audit.Event{
		ActorID:       principal.UserID,
		ActorUsername: principal.Username,
		Action:        "ssh.command",
		Resource:      "ssh",
		Outcome:       "allow",
		SourceIP:      "",
		Details:       map[string]any{"command": command},
	})

	switch parts[0] {
	case "help":
		return "Available commands: help, whoami, hosts, connect <hostID>, exit\n"
	case "whoami":
		return fmt.Sprintf("%s roles=%s\n", principal.Username, strings.Join(principal.Roles, ","))
	case "hosts":
		hosts, err := s.store.ListHosts(ctx)
		if err != nil {
			return "failed to list hosts\n"
		}
		if len(hosts) == 0 {
			return "no hosts configured\n"
		}
		builder := strings.Builder{}
		for _, host := range hosts {
			builder.WriteString(fmt.Sprintf("- %s (%s:%d) env=%s criticality=%s\n", host.ID, host.Address, host.Port, host.Environment, host.Criticality))
		}
		return builder.String()
	case "connect":
		if len(parts) < 2 {
			return "usage: connect <hostID>\n"
		}
		hostID := parts[1]
		decision, err := s.policyEngine.CanConnect(ctx, principal, hostID)
		if err != nil {
			return "policy evaluation failed\n"
		}
		if !decision.Allowed {
			return "access denied by policy\n"
		}
		return fmt.Sprintf("access granted to %s. Use API session start for full proxy workflow.\n", hostID)
	default:
		return "unknown command\n"
	}
}

func parseExecCommand(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	length := binary.BigEndian.Uint32(payload[:4])
	if int(length)+4 > len(payload) {
		return ""
	}
	return string(payload[4 : 4+length])
}

func principalFromExtensions(perms *ssh.Permissions) auth.Principal {
	if perms == nil {
		return auth.Principal{Authenticated: false}
	}
	roles := splitCSV(perms.Extensions["roles"])
	permissions := splitCSV(perms.Extensions["permissions"])
	return auth.Principal{
		UserID:        perms.Extensions["user_id"],
		Username:      perms.Extensions["username"],
		Roles:         roles,
		Permissions:   permissions,
		Authenticated: true,
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func loadOrCreateHostSigner(path string) (ssh.Signer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create host key directory: %w", err)
	}

	if keyBytes, err := os.ReadFile(path); err == nil {
		signer, parseErr := ssh.ParsePrivateKey(keyBytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse host key: %w", parseErr)
		}
		return signer, nil
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER}
	pemBytes := pem.EncodeToMemory(privateBlock)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse generated host key: %w", err)
	}
	return signer, nil
}

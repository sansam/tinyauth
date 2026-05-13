package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	ldapgo "github.com/go-ldap/ldap/v3"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type LdapService struct {
	log     *logger.Logger
	config  model.Config
	context context.Context

	conn  *ldapgo.Conn
	mutex sync.Mutex // 改为 Mutex，不需要 RWMutex，因为所有操作都需要独占访问
	cert  *tls.Certificate
}

func NewLdapService(
	log *logger.Logger,
	config model.Config,
	ctx context.Context,
	wg *sync.WaitGroup,
) (*LdapService, error) {
	if config.LDAP.Address == "" {
		return nil, nil
	}

	ldap := &LdapService{
		log:     log,
		config:  config,
		context: ctx,
	}


	if config.LDAP.AuthCert != "" && config.LDAP.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(config.LDAP.AuthCert, config.LDAP.AuthKey)

		if err != nil {
			return nil, fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}

		log.App.Info().Msg("LDAP mTLS authentication configured successfully")

		ldap.cert = &cert









	}



	if err := ldap.connectLocked(); err != nil {


		return nil, fmt.Errorf("failed to connect to ldap server: %w", err)
	}

	wg.Go(func() {
		ldap.log.App.Debug().Msg("Starting LDAP connection heartbeat routine")

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ldap.mutex.Lock()
				err := ldap.heartbeatLocked()
				if err != nil {
					ldap.log.App.Warn().Err(err).Msg("LDAP connection heartbeat failed, attempting to reconnect")
					if reconnectErr := ldap.reconnectLocked(); reconnectErr != nil {
						ldap.log.App.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
						ldap.mutex.Unlock()
						continue
					}
					ldap.log.App.Info().Msg("Successfully reconnected to LDAP server")
				}
				ldap.mutex.Unlock()
			case <-ldap.context.Done():
				ldap.log.App.Debug().Msg("LDAP service context cancelled, stopping heartbeat")
				return
			}
		}
	})

	return ldap, nil
}

// connectLocked 建立连接并绑定服务账号，调用者必须未持有锁
func (ldap *LdapService) connectLocked() error {




	var conn *ldapgo.Conn
	var err error







	if ldap.cert != nil {
		conn, err = ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*ldap.cert},
		}))
	} else {
		conn, err = ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: ldap.config.LDAP.Insecure,
			MinVersion:         tls.VersionTLS12,
		}))
	}
	if err != nil {
		return fmt.Errorf("failed to dial LDAP: %w", err)
	}

	ldap.conn = conn

	if err := ldap.bindServiceLocked(); err != nil {


		conn.Close()
		ldap.conn = nil
		return fmt.Errorf("failed to bind service account: %w", err)
	}

	return nil
}

// bindServiceLocked 使用服务账号绑定，调用者必须保证对 conn 的独占访问
func (ldap *LdapService) bindServiceLocked() error {
	if ldap.cert != nil {
		return ldap.conn.ExternalBind()
	}
	return ldap.conn.Bind(ldap.config.LDAP.BindDN, ldap.config.LDAP.BindPassword)
}

// dialNewConn 创建一个独立的新连接（不影响共享连接）
func (ldap *LdapService) dialNewConn() (*ldapgo.Conn, error) {
	if ldap.cert != nil {
		return ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*ldap.cert},
		}))
	}
	return ldapgo.DialURL(ldap.config.LDAP.Address, ldapgo.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: ldap.config.LDAP.Insecure,
		MinVersion:         tls.VersionTLS12,
	}))
}

// withRetry 在共享连接上执行操作，如果连接断开则自动重连重试
func (ldap *LdapService) withRetry(operation func() error) error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	err := operation()
	if err == nil {
		return nil
	}

	// 判断是否为连接级别的错误，如果是则尝试重连
	if !ldapgo.IsErrorAnyOf(err,
		ldapgo.LDAPResultServerDown,
		ldapgo.LDAPResultBusy,
		ldapgo.LDAPResultUnavailable,
		ldapgo.LDAPResultOperationsError,
	) && !isConnectionClosed(err) {
		return err
	}

	ldap.log.App.Warn().Err(err).Msg("LDAP operation failed, attempting reconnect")

	if reconnErr := ldap.reconnectLocked(); reconnErr != nil {
		return fmt.Errorf("operation failed and reconnect also failed: original=%w, reconnect=%v", err, reconnErr)
	}

	// 重连成功后重试一次
	return operation()
}

// isConnectionClosed 检查是否为连接关闭类错误
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	// go-ldap 在连接关闭时可能返回的错误信息
	msg := err.Error()
	for _, substr := range []string{
		"connection is closed",
		"use of closed network connection",
		"broken pipe",
		"connection reset",
	} {
		if containsSubstring(msg, substr) {
			return true
		}
	}
	return false
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (ldap *LdapService) GetUserInfo(username string) (dn string, email string, err error) {
	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(ldap.config.LDAP.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn", "mail"},
		nil,
	)





	var searchResult *ldapgo.SearchResult

	err = ldap.withRetry(func() error {
		var searchErr error
		searchResult, searchErr = ldap.conn.Search(searchRequest)
		return searchErr
	})
	if err != nil {
		return "", "", fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(searchResult.Entries) != 1 {
		return "", "", fmt.Errorf("multiple or no entries found for user %s", username)
	}

	entry := searchResult.Entries[0]
	return entry.DN, entry.GetAttributeValue("mail"), nil
}

func (ldap *LdapService) GetUserGroups(userDN string) ([]string, error) {
	escapedUserDN := ldapgo.EscapeFilter(userDN)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectclass=groupOfUniqueNames)(uniquemember=%s))", escapedUserDN),
		[]string{"dn"},
		nil,
	)





	var searchResult *ldapgo.SearchResult

	err := ldap.withRetry(func() error {
		var searchErr error
		searchResult, searchErr = ldap.conn.Search(searchRequest)
		return searchErr
	})
	if err != nil {
		return nil, fmt.Errorf("LDAP group search failed: %w", err)
	}

	groups := make([]string, 0, len(searchResult.Entries))


	for _, entry := range searchResult.Entries {
		rdnParts, err := ldapgo.ParseDN(entry.DN)







		if err != nil {
			return nil, fmt.Errorf("failed to parse DN %s: %w", entry.DN, err)
		}
		if len(rdnParts.RDNs) == 0 || len(rdnParts.RDNs[0].Attributes) == 0 {
			return nil, fmt.Errorf("invalid DN format: %s", entry.DN)
		}
		groups = append(groups, rdnParts.RDNs[0].Attributes[0].Value)
	}

	return groups, nil
}

// Bind 验证用户凭证 —— 使用独立连接，不影响共享的服务连接
func (ldap *LdapService) Bind(userDN string, password string) error {




	// 创建独立连接来验证用户密码
	conn, err := ldap.dialNewConn()
	if err != nil {
		return fmt.Errorf("failed to create connection for user bind: %w", err)
	}
	defer conn.Close()

	err = conn.Bind(userDN, password)
	if err != nil {

		return fmt.Errorf("user bind failed: %w", err)
	}


	return nil
}

// BindService 重新绑定服务账号（公开方法，外部调用时加锁）
func (ldap *LdapService) BindService() error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()
	return ldap.bindServiceLocked()



}



// heartbeatLocked 执行心跳检测，调用者必须持有锁
func (ldap *LdapService) heartbeatLocked() error {

	ldap.log.App.Debug().Msg("Performing LDAP connection heartbeat")

	searchRequest := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	)



	_, err := ldap.conn.Search(searchRequest)

	return err
}

// reconnectLocked 重连，调用者必须持有锁




func (ldap *LdapService) reconnectLocked() error {
	ldap.log.App.Info().Msg("Attempting to reconnect to LDAP server")

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 500 * time.Millisecond
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	operation := func() (struct{}, error) {
		if ldap.conn != nil {
			ldap.conn.Close()
			ldap.conn = nil
		}
		err := ldap.connectLocked()
		if err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	}

	_, err := backoff.Retry(ldap.context, operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))


	return err
}




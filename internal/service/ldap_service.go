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
	mutex sync.Mutex
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

	if err := ldap.dialAndBind(); err != nil {
		return nil, fmt.Errorf("failed to connect to ldap server: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ldap.log.App.Debug().Msg("Starting LDAP connection heartbeat routine")

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := ldap.heartbeat(); err != nil {
					ldap.log.App.Warn().Err(err).Msg("LDAP connection heartbeat failed, attempting to reconnect")
					if reconnectErr := ldap.reconnect(); reconnectErr != nil {
						ldap.log.App.Error().Err(reconnectErr).Msg("Failed to reconnect to LDAP server")
						continue
					}
					ldap.log.App.Info().Msg("Successfully reconnected to LDAP server")
				}
			case <-ldap.context.Done():
				ldap.log.App.Debug().Msg("LDAP service context cancelled, stopping heartbeat")
				return
			}
		}
	}()

	return ldap, nil
}

// dialAndBind establishes a new connection and binds the service account.
// Caller must NOT hold the mutex.
func (ldap *LdapService) dialAndBind() error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	return ldap.dialAndBindLocked()
}

// dialAndBindLocked establishes a new connection and binds.
// Caller MUST already hold the mutex.
func (ldap *LdapService) dialAndBindLocked() error {
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
		ldap.conn.Close()
		ldap.conn = nil
		return err
	}

	return nil
}

// bindServiceLocked binds using the service account credentials.
// Caller MUST already hold the mutex.
func (ldap *LdapService) bindServiceLocked() error {
	var err error
	if ldap.cert != nil {
		err = ldap.conn.ExternalBind()
	} else {
		err = ldap.conn.Bind(ldap.config.LDAP.BindDN, ldap.config.LDAP.BindPassword)
	}
	if err != nil {
		return fmt.Errorf("LDAP service bind failed: %w", err)
	}
	ldap.log.App.Debug().Msg("LDAP service account bound successfully")
	return nil
}

// ensureBound verifies the connection is alive and rebinds the service account.
// If the connection is dead it attempts a full reconnect.
// Caller must NOT hold the mutex.
func (ldap *LdapService) ensureBound() error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	// Quick connectivity test via root DSE query
	testReq := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 1, 1, false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	)

	_, err := ldap.conn.Search(testReq)
	if err != nil {
		ldap.log.App.Warn().Err(err).Msg("LDAP connection test failed, attempting full reconnect")

		if ldap.conn != nil {
			ldap.conn.Close()
		}

		if dialErr := ldap.dialAndBindLocked(); dialErr != nil {
			return fmt.Errorf("LDAP reconnect failed: %w", dialErr)
		}

		ldap.log.App.Info().Msg("LDAP reconnected and rebound successfully")
		return nil
	}

	// Connection is alive, rebind service account to ensure a clean state
	if bindErr := ldap.bindServiceLocked(); bindErr != nil {
		return fmt.Errorf("LDAP rebind failed: %w", bindErr)
	}

	return nil
}

// searchWithBind ensures the service account is bound, then executes the search.
// Caller must NOT hold the mutex.
func (ldap *LdapService) searchWithBind(request *ldapgo.SearchRequest) (*ldapgo.SearchResult, error) {
	if err := ldap.ensureBound(); err != nil {
		return nil, err
	}

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	return ldap.conn.Search(request)
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

	searchResult, err := ldap.searchWithBind(searchRequest)
	if err != nil {
		return "", "", err
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

	searchResult, err := ldap.searchWithBind(searchRequest)
	if err != nil {
		return nil, err
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

// BindService binds the service account. Safe to call without holding the mutex.
func (ldap *LdapService) BindService() error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	return ldap.bindServiceLocked()
}

// Bind authenticates a user and then rebinds the service account.
func (ldap *LdapService) Bind(userDN string, password string) error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	if err := ldap.conn.Bind(userDN, password); err != nil {
		// Rebind service account even on failure to keep connection usable
		_ = ldap.bindServiceLocked()
		return err
	}

	// Rebind service account after successful user authentication
	return ldap.bindServiceLocked()
}

func (ldap *LdapService) heartbeat() error {
	ldap.log.App.Debug().Msg("Performing LDAP connection heartbeat")
	return ldap.ensureBound()
}

func (ldap *LdapService) reconnect() error {
	ldap.log.App.Info().Msg("Attempting to reconnect to LDAP server")

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 500 * time.Millisecond
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	operation := func() (struct{}, error) {
		ldap.mutex.Lock()
		defer ldap.mutex.Unlock()

		if ldap.conn != nil {
			ldap.conn.Close()
		}

		if err := ldap.dialAndBindLocked(); err != nil {
			return struct{}{}, err
		}

		return struct{}{}, nil
	}

	_, err := backoff.Retry(ldap.context, operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))
	return err
}

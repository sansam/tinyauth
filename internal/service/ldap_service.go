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
	mutex sync.RWMutex
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

	// Check whether authentication with client certificate is possible
	if config.LDAP.AuthCert != "" && config.LDAP.AuthKey != "" {
		cert, err := tls.LoadX509KeyPair(config.LDAP.AuthCert, config.LDAP.AuthKey)

		if err != nil {
			return nil, fmt.Errorf("failed to initialize LDAP with mTLS authentication: %w", err)
		}

		log.App.Info().Msg("LDAP mTLS authentication configured successfully")

		ldap.cert = &cert
	}

	_, err := ldap.connect()

	if err != nil {
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
				err := ldap.heartbeat()
				if err != nil {
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

func (ldap *LdapService) connect() (*ldapgo.Conn, error) {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

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
		return nil, err
	}

	ldap.conn = conn

	err = ldap.BindService(false)
	if err != nil {
		return nil, err
	}
	return ldap.conn, nil
}

// ensureBound verifies the connection is alive and rebinds if necessary
func (ldap *LdapService) ensureBound() error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	// Test connection with root DSE query
	testReq := ldapgo.NewSearchRequest(
		"",
		ldapgo.ScopeBaseObject, ldapgo.NeverDerefAliases, 1, 1, false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	)
	if _, err := ldap.conn.Search(testReq); err != nil {
		ldap.log.App.Warn().Err(err).Msg("LDAP connection test failed, rebinding")
		if bindErr := ldap.BindService(true); bindErr != nil {
			return fmt.Errorf("failed to rebind LDAP: %w", bindErr)
		}
		ldap.log.App.Debug().Msg("Successfully rebound LDAP connection")
	}
	return nil
}

func (ldap *LdapService) GetUserInfo(username string) (dn string, email string, err error) {
	if err := ldap.ensureBound(); err != nil {
		return "", "", err
	}

	escapedUsername := ldapgo.EscapeFilter(username)
	filter := fmt.Sprintf(ldap.config.LDAP.SearchFilter, escapedUsername)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn", "mail"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
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
	if err := ldap.ensureBound(); err != nil {
		return nil, err
	}

	escapedUserDN := ldapgo.EscapeFilter(userDN)

	searchRequest := ldapgo.NewSearchRequest(
		ldap.config.LDAP.BaseDN,
		ldapgo.ScopeWholeSubtree, ldapgo.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectclass=groupOfUniqueNames)(uniquemember=%s))", escapedUserDN),
		[]string{"dn"},
		nil,
	)

	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()

	searchResult, err := ldap.conn.Search(searchRequest)
	if err != nil {
		return []string{}, err
	}

	groupDNs := []string{}

	for _, entry := range searchResult.Entries {
		groupDNs = append(groupDNs, entry.DN)
	}

	groups := []string{}

	for _, dn := range groupDNs {
		rdnParts, err := ldapgo.ParseDN(dn)
		if err != nil {
			return []string{}, err
		}
		if len(rdnParts.RDNs) == 0 || len(rdnParts.RDNs[0].Attributes) == 0 {
			return []string{}, fmt.Errorf("invalid DN format: %s", dn)
		}
		groups = append(groups, rdnParts.RDNs[0].Attributes[0].Value)
	}

	return groups, nil
}

func (ldap *LdapService) BindService(rebind bool) error {
	if rebind {
		ldap.mutex.Lock()
		defer ldap.mutex.Unlock()
	}

	var err error
	if ldap.cert != nil {
		err = ldap.conn.ExternalBind()
	} else {
		err = ldap.conn.Bind(ldap.config.LDAP.BindDN, ldap.config.LDAP.BindPassword)
	}
	if err != nil {
		return fmt.Errorf("LDAP bind failed: %w", err)
	}
	return nil
}

func (ldap *LdapService) Bind(userDN string, password string) error {
	ldap.mutex.Lock()
	defer ldap.mutex.Unlock()
	err := ldap.conn.Bind(userDN, password)
	if err != nil {
		return err
	}
	return nil
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

	operation := func() error {
		ldap.mutex.Lock()
		defer ldap.mutex.Unlock()

		if ldap.conn != nil {
			ldap.conn.Close()
		}
		conn, err := ldap.connect()
		if err != nil {
			return err
		}
		ldap.conn = conn
		return nil
	}

	return backoff.Retry(ldap.context, operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))
}

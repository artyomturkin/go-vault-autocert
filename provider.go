package vac

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// Provider configures tls.Config with certificate
type Provider interface {
	BindTLSConfig(*tls.Config)
}

type pki struct {
	sync.RWMutex

	cert      *tls.Certificate
	client    *api.Client
	timer     *time.Timer
	ctx       context.Context
	expiresAt time.Time

	//config
	path          string
	data          map[string]interface{}
	renewModifier float32
	retryDelay    time.Duration
}

func (p *pki) BindTLSConfig(c *tls.Config) {
	c.GetCertificate = p.getCertificate
}

// VaultPKIConfig config for Vault PKI provider
type VaultPKIConfig struct {
	Address string
	Token   string

	Path          string
	Role          string
	CN            string
	AdvertisedIPs []string

	RenewModifier float32
	RetryDelay    time.Duration
}

// NewVaultPKIProvider setup new certificate provider with Vault PKI Backend
func NewVaultPKIProvider(ctx context.Context, c VaultPKIConfig) (Provider, error) {
	if c.Address == "" {
		c.Address = "http://localhost:8200"
	}
	if c.Path == "" {
		c.CN = "pki"
	}
	if c.RenewModifier == 0 {
		c.RenewModifier = 0.95
	}
	if c.RetryDelay == 0 {
		c.RetryDelay = time.Second * 30
	}

	p := &pki{}
	p.ctx = ctx

	ac := api.DefaultConfig()
	ac.Address = c.Address
	cl, err := api.NewClient(ac)
	if err != nil {
		return nil, err
	}
	cl.SetToken(c.Token)
	p.client = cl

	p.path = fmt.Sprintf("%s/issue/%s", c.Path, c.Role)
	p.data = map[string]interface{}{
		"common_name": c.CN,
		"ip_sans":     strings.Join(c.AdvertisedIPs, ","),
	}

	p.renewModifier = c.RenewModifier
	p.retryDelay = c.RetryDelay

	expiresIn, err := p.updateCert()
	if err != nil {
		return nil, err
	}

	p.timer = time.NewTimer(expiresIn)
	go p.renewCertificate()
	return p, nil
}

func (p *pki) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.RLock()
	if p.cert == nil {
		p.RUnlock()
		return nil, errors.New("certificate not loaded")
	}
	p.RUnlock()
	return p.cert, nil
}

func (p *pki) updateCert() (time.Duration, error) {
	s, err := p.client.Logical().Write(p.path, p.data)
	if err != nil {
		return 0, err
	}
	if s == nil {
		return 0, errors.New("got empty response fro vault")
	}

	ca := s.Data["issuing_ca"].(string)
	crt := s.Data["certificate"].(string)
	chain := []byte(crt + "\n" + ca)
	key := []byte(s.Data["private_key"].(string))
	c, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return 0, err
	}

	p.Lock()
	defer p.Unlock()
	p.cert = &c
	p.expiresAt = time.Now().Add(time.Second * time.Duration(s.LeaseDuration))

	e := int(float32(s.LeaseDuration) * p.renewModifier)

	return time.Second * time.Duration(e), nil
}

func (p *pki) renewCertificate() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.timer.C:
			d, err := p.updateCert()
			if err != nil {
				if time.Now().Before(p.expiresAt) {
					p.timer.Reset(p.retryDelay)
					continue
				} else {
					panic("get certificate retries exceeded")
				}
			}
			p.timer.Reset(d)
		}
	}
}

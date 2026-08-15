package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	certFileName = "ca-cert.pem"
	keyFileName  = "ca-key.pem"

	rootValidity = 10 * 365 * 24 * time.Hour
	leafValidity = 397 * 24 * time.Hour // under the ~398 day limit most trust stores enforce
)

type CA struct {
	certDER []byte
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func LoadOrCreate(dir string) (*CA, error) {
	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return load(certPEM, keyPEM)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ca: creating %s: %w", dir, err)
	}
	c, certPEM, keyPEM, err := generate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("ca: writing %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("ca: writing %s: %w", keyPath, err)
	}
	return c, nil
}

func generate() (*CA, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: generating root key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: generating serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"labnet"}, CommonName: "labnet local root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: creating root certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: parsing generated root certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca: marshaling root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CA{certDER: der, certPEM: certPEM, cert: cert, key: key, leafs: map[string]*tls.Certificate{}}, certPEM, keyPEM, nil
}

func load(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca: no PEM block found in root certificate file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing root certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca: no PEM block found in root key file")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing root key: %w", err)
	}
	return &CA{certDER: certBlock.Bytes, certPEM: certPEM, cert: cert, key: key, leafs: map[string]*tls.Certificate{}}, nil
}

func (c *CA) RootPEM() []byte { return c.certPEM }

func (c *CA) RootCert() *x509.Certificate { return c.cert }

func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(hello.ServerName)
	if name == "" {
		return nil, fmt.Errorf("ca: no SNI server name in TLS handshake — connect by hostname, not bare IP")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leafs[name]; ok && leaf.Leaf.NotAfter.After(time.Now()) {
		return leaf, nil
	}

	leaf, err := c.mintLeaf(name)
	if err != nil {
		return nil, err
	}
	c.leafs[name] = leaf
	return leaf, nil
}

func (c *CA) mintLeaf(name string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generating leaf key for %s: %w", name, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generating serial for %s: %w", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"labnet"}, CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: signing leaf certificate for %s: %w", name, err)
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing minted leaf certificate for %s: %w", name, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.certDER},
		PrivateKey:  key,
		Leaf:        leafCert,
	}, nil
}

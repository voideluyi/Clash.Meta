package http

import (
	"context"
	basetls "crypto/tls"
	"encoding/pem"
	"github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/listener/inner"
	"golang.org/x/crypto/pkcs12"
	"io"
	"net"
	"net/http"
	URL "net/url"
	"os"
	"strings"
	"time"
)

const (
	UA = "clash.meta"
)

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader) (*http.Response, error) {
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if _, ok := header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", UA)
	}

	if err != nil {
		return nil, err
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	transport := &http.Transport{
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if conn, err := inner.HandleTcp(address); err == nil {
				return conn, nil
			} else {
				d := net.Dialer{}
				return d.DialContext(ctx, network, address)
			}
		},
		TLSClientConfig: tls.GetDefaultTLSConfig(),
	}

	client := http.Client{Transport: transport}
	return client.Do(req)

}

func HttpRequestV2(ctx context.Context, url, method string, header map[string][]string, p12kFile string, p12kPass string, clientCert string, clientKey string, body io.Reader) (*http.Response, error) {
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if _, ok := header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", UA)
	}

	if err != nil {
		return nil, err
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)
	tlsConfig := tls.GetDefaultTLSConfig()

	// Load client cert and key from PKCS#12 file if provided
	if p12kFile != "" {
		p12Data, err := os.ReadFile(p12kFile)
		if err != nil {
			return nil, err
		}
		blocks, err := pkcs12.ToPEM(p12Data, p12kPass)
		if err != nil {
			return nil, err
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		cert, err := basetls.X509KeyPair(pemData, pemData)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []basetls.Certificate{cert}
	}
	if clientCert != "" && clientKey != "" {
		cert, err := basetls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []basetls.Certificate{cert}
	}
	transport := &http.Transport{
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if conn, err := inner.HandleTcp(address); err == nil {
				return conn, nil
			} else {
				d := net.Dialer{}
				return d.DialContext(ctx, network, address)
			}
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{Transport: transport}
	return client.Do(req)

}

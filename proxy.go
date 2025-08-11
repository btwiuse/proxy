package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/btwiuse/connect"
	"github.com/btwiuse/dispatcher"
	"github.com/btwiuse/forward"
)

func ProxyBasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	return parseProxyBasicAuth(auth)
}

func parseProxyBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// h1/h2/h3 connect requests or forward requests
func IsProxy(r *http.Request) bool {
	if r.Header.Get("Proxy-Connection") != "" {
		return true
	}
	if r.Method == http.MethodConnect && r.URL.Path == "" {
		return true
	}
	return false
}

func IsProxyAuthenticated(r *http.Request) bool {
	user, pass, ok := ProxyBasicAuth(r)
	return ok && CheckProxyAuth(user, pass)
}

func ProxyAuthenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsProxyAuthenticated(r) {
			w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%s"`, r.Host))
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CheckProxyAuth(user, pass string) bool {
	if user == "" || pass == "" {
		return false
	}
	return true
}

var AuthenticatedProxyHandler = ConnectVerbose(ProxyAuthenticate(NewProxyHandler()))

func ProxyDispatcher(r *http.Request) http.Handler {
	switch {
	// HTTPS or WS/WSS target
	case r.Method == http.MethodConnect:
		return connect.Handler
	// Plain HTTP target
	default:
		return forward.Handler
	}
}

func NewProxyHandler() http.Handler {
	return dispatcher.DispatcherFunc(ProxyDispatcher)
}

// ConnectVerbose is a misnomer
// It also logs plain HTTP proxy requests, which do not have CONNECT method
func ConnectVerbose(next http.Handler) http.Handler {
	if os.Getenv("CONNECT_VERBOSE") == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		println(r.Method, r.Proto, r.Host, r.Header)
		next.ServeHTTP(w, r)
	})
}

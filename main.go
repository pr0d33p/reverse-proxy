package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"github.com/sirupsen/logrus"
	"strconv"
	"sync"
	"time"
	"crypto/tls"
)

type ProxyConfig struct {
	Servers      []string          `json:"servers"`
	DefaultHTTPPort int             `json:"default_http_port"`
	DefaultHTTPSPort int            `json:"default_https_port"`
	ProxyHeaders map[string]string `json:"proxy_headers"`
	HealthCheckInterval int               `json:"health_check_interval"`
	SSL          struct {
		Enabled bool   `json:"enabled"`
		Key     string `json:"key"`
		Cert    string `json:"cert"`
	} `json:"ssl"`
}

type ServerStatus struct {
	URL     *url.URL
	Healthy bool
}

var proxyConfig ProxyConfig
var randSource = rand.NewSource(time.Now().UnixNano())
var randMutex sync.Mutex
var healthyProxiesMutex sync.Mutex
var healthyProxies []*httputil.ReverseProxy

var httpLogger = logrus.New()

func main() {
	loadConfig()

	httpLogger.SetFormatter(&logrus.JSONFormatter{})

	serverStatuses := make([]*ServerStatus, len(proxyConfig.Servers))
	for i, server := range proxyConfig.Servers {
		serverStatuses[i] = &ServerStatus{
			URL:     parseServerURL(server),
			Healthy: checkServerHealth(parseServerURL(server)),
		}
	}
	
	healthyProxies = createHealthyProxies(serverStatuses)

	go func() {
		for {
			time.Sleep(time.Duration(proxyConfig.HealthCheckInterval) * time.Second)
			for _, serverStatus := range serverStatuses {
				serverStatus.Healthy = checkServerHealth(serverStatus.URL)
			}
			updateHealthyProxies(serverStatuses)
			log.Printf("Healthy proxies: %d\n", len(healthyProxies))
		}
	}()

	handler := func() func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			healthyProxiesMutex.Lock()
			defer healthyProxiesMutex.Unlock()

			if len(healthyProxies) == 0 {
				httpLogger.WithFields(logrus.Fields{
					"method": r.Method,
					"uri": r.RequestURI,
					"host": r.Host,
					"remote_addr": r.RemoteAddr,
					"proto": r.Proto,
					"referer": r.Referer(),
					"user_agent": r.UserAgent(),
				}).Error("No healthy servers available")

				http.Error(w, "{\"error\": \"No healthy servers available\"}", http.StatusServiceUnavailable)
				return
			}

			index := getRandomHealthyServerIndex(healthyProxies)
			proxy := healthyProxies[index]

			r.Host = r.URL.Host

			httpLogger.WithFields(logrus.Fields{
				"method": r.Method,
				"uri": r.RequestURI,
				"host": r.Host,
				"remote_addr": r.RemoteAddr,
				"proto": r.Proto,
				"referer": r.Referer(),
				"user_agent": r.UserAgent(),
			}).Info("Access")
			
			for k, v := range proxyConfig.ProxyHeaders {
				w.Header().Set(k, v)
			}

			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}

			proxy.ServeHTTP(w, r)
		}
	}

	http.HandleFunc("/", handler())
	HTTPport := proxyConfig.DefaultHTTPPort
	HTTPSport := proxyConfig.DefaultHTTPSPort
	
	if proxyConfig.SSL.Enabled {
		log.Printf("Starting server on :%d...\n", HTTPSport)
		log.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(HTTPSport), proxyConfig.SSL.Cert, proxyConfig.SSL.Key, nil))
	} else {
		log.Printf("Starting server on :%d...\n", HTTPport)
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(HTTPport), nil))
	}
}

func createHealthyProxies(serverStatuses []*ServerStatus) []*httputil.ReverseProxy {
	var proxies []*httputil.ReverseProxy

	for _, status := range serverStatuses {
		if status.Healthy {
			proxies = append(proxies, httputil.NewSingleHostReverseProxy(status.URL))
		}
	}
	return proxies
}

func updateHealthyProxies(serverStatuses []*ServerStatus) {
	healthyProxiesMutex.Lock()
	defer healthyProxiesMutex.Unlock()
	healthyProxies = createHealthyProxies(serverStatuses)
}

func getRandomHealthyServerIndex(proxies []*httputil.ReverseProxy) int {
	if len(proxies) == 0 {
		return -1
	}

	randMutex.Lock()
	defer randMutex.Unlock()
	rand.Seed(randSource.Int63())
	return rand.Intn(len(proxies))
}

func checkServerHealth(serverURL *url.URL) bool {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Get(serverURL.String())
	
	if err != nil || resp == nil {
		log.Printf("Server %s is unhealthy\n", serverURL.String())
		return false
	}
	log.Printf("Server %s is healthy\n", serverURL.String())
	return true
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal("Error opening config file: ", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&proxyConfig)
	if err != nil {
		log.Fatal("Error decoding config file: ", err)
	}
}

func parseServerURL(server string) *url.URL {
	u, err := url.Parse(server)
	if err != nil {
		log.Fatal("Error parsing server URL: ", err)
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}

	return u
}
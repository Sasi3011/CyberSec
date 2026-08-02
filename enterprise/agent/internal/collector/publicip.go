package collector

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	publicIPCache     string
	publicIPCacheTime time.Time
	publicIPMu        sync.Mutex
)

func cachedPublicIP() string {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	if publicIPCache != "" && time.Since(publicIPCacheTime) < 5*time.Minute {
		return publicIPCache
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/?fields=status,query,country,city,lat,lon")
	if err != nil {
		return publicIPCache
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// minimal parse without json import overhead in hot path - use simple scan
	s := string(body)
	if !strings.Contains(s, `"success"`) {
		return publicIPCache
	}
	ip := extractJSONField(s, "query")
	if ip != "" {
		publicIPCache = ip
		publicIPCacheTime = time.Now()
	}
	return publicIPCache
}

func publicGeo() *GeoHint {
	publicIPMu.Lock()
	cached := publicIPCacheTime
	publicIPMu.Unlock()
	if time.Since(cached) > 5*time.Minute {
		cachedPublicIP()
	}
	publicIPMu.Lock()
	ip := publicIPCache
	publicIPMu.Unlock()
	if ip == "" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=status,country,city,lat,lon")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, `"success"`) {
		return nil
	}
	return &GeoHint{
		Country: extractJSONField(s, "country"),
		City:    extractJSONField(s, "city"),
		Lat:     parseJSONFloat(s, "lat"),
		Lon:     parseJSONFloat(s, "lon"),
	}
}

type GeoHint struct {
	Country string
	City    string
	Lat     float64
	Lon     float64
}

func extractJSONField(json, key string) string {
	needle := `"` + key + `":"`
	i := strings.Index(json, needle)
	if i < 0 {
		return ""
	}
	rest := json[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func parseJSONFloat(json, key string) float64 {
	needle := `"` + key + ":"
	i := strings.Index(json, needle)
	if i < 0 {
		return 0
	}
	rest := json[i+len(needle):]
	rest = strings.TrimLeft(rest, " ")
	var num []byte
	for _, c := range rest {
		if (c >= '0' && c <= '9') || c == '.' || c == '-' {
			num = append(num, byte(c))
		} else {
			break
		}
	}
	v, _ := strconv.ParseFloat(string(num), 64)
	return v
}

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type kv struct{ K, V string }

type section struct {
	Title string
	Rows  []kv
}

// Info is what the JSON endpoint returns.
type Info struct {
	Time       string              `json:"time"`
	Container  string              `json:"container_hostname"`
	PeerIP     string              `json:"peer_ip"`
	PeerPort   string              `json:"peer_port"`
	ClaimedIP  string              `json:"claimed_client_ip"`
	ClaimedVia string              `json:"claimed_client_ip_source"`
	XFFChain   []string            `json:"x_forwarded_for_chain"`
	Forwarded  map[string]string   `json:"proxy_headers"`
	Method     string              `json:"method"`
	Proto      string              `json:"protocol"`
	Host       string              `json:"host"`
	URI        string              `json:"request_uri"`
	Scheme     string              `json:"scheme"`
	TLS        map[string]string   `json:"tls,omitempty"`
	UserAgent  string              `json:"user_agent"`
	Query      map[string][]string `json:"query"`
	Cookies    map[string]string   `json:"cookies"`
	Headers    map[string][]string `json:"headers"`
	ContentLen int64               `json:"content_length"`
}

var proxyHeaders = []string{
	"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
	"X-Real-Ip", "Forwarded", "Via", "Cf-Connecting-Ip", "True-Client-Ip",
	"X-Client-Ip", "Cf-Ipcountry", "Cf-Ray", "X-Request-Id",
}

func gather(r *http.Request) Info {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host, port = r.RemoteAddr, ""
	}
	hn, _ := os.Hostname()

	info := Info{
		Time:       time.Now().Format(time.RFC3339),
		Container:  hn,
		PeerIP:     host,
		PeerPort:   port,
		Forwarded:  map[string]string{},
		Method:     r.Method,
		Proto:      r.Proto,
		Host:       r.Host,
		URI:        r.RequestURI,
		Scheme:     "http",
		UserAgent:  r.UserAgent(),
		Query:      r.URL.Query(),
		Cookies:    map[string]string{},
		Headers:    map[string][]string{"Host": {r.Host}},
		ContentLen: r.ContentLength,
	}

	for k, v := range r.Header {
		info.Headers[k] = v
	}
	for _, c := range r.Cookies() {
		info.Cookies[c.Name] = c.Value
	}

	for _, h := range proxyHeaders {
		if v := r.Header.Get(h); v != "" {
			info.Forwarded[h] = v
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, p := range strings.Split(xff, ",") {
			info.XFFChain = append(info.XFFChain, strings.TrimSpace(p))
		}
	}

	// Best-effort "original client" guess. All of these are client-controllable
	// unless a proxy you trust sets/overwrites them.
	switch {
	case r.Header.Get("Cf-Connecting-Ip") != "":
		info.ClaimedIP, info.ClaimedVia = r.Header.Get("Cf-Connecting-Ip"), "CF-Connecting-IP"
	case len(info.XFFChain) > 0:
		info.ClaimedIP, info.ClaimedVia = info.XFFChain[0], "X-Forwarded-For (first)"
	case r.Header.Get("X-Real-Ip") != "":
		info.ClaimedIP, info.ClaimedVia = r.Header.Get("X-Real-Ip"), "X-Real-IP"
	default:
		info.ClaimedIP, info.ClaimedVia = host, "TCP peer (no proxy headers)"
	}

	if r.TLS != nil {
		info.Scheme = "https"
		info.TLS = map[string]string{
			"version":     tlsVersion(r.TLS.Version),
			"server_name": r.TLS.ServerName,
			"alpn":        r.TLS.NegotiatedProtocol,
		}
	} else if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		info.Scheme = p + " (via X-Forwarded-Proto)"
	}
	return info
}

func tlsVersion(v uint16) string {
	switch v {
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sections(i Info) []section {
	s := []section{
		{"Origin", []kv{
			{"TCP peer IP (direct connection)", i.PeerIP},
			{"TCP peer port", i.PeerPort},
			{"Claimed client IP", i.ClaimedIP},
			{"Claimed via", i.ClaimedVia},
			{"X-Forwarded-For chain", strings.Join(i.XFFChain, " -> ")},
		}},
		{"Request", []kv{
			{"Method", i.Method}, {"Protocol", i.Proto}, {"Scheme", i.Scheme},
			{"Host", i.Host}, {"URI", i.URI}, {"User-Agent", i.UserAgent},
			{"Content-Length", fmt.Sprint(i.ContentLen)},
		}},
	}
	if len(i.TLS) > 0 {
		var rows []kv
		for _, k := range sortedKeys(i.TLS) {
			rows = append(rows, kv{k, i.TLS[k]})
		}
		s = append(s, section{"TLS", rows})
	}
	if len(i.Forwarded) > 0 {
		var rows []kv
		for _, k := range sortedKeys(i.Forwarded) {
			rows = append(rows, kv{k, i.Forwarded[k]})
		}
		s = append(s, section{"Proxy headers", rows})
	}
	var hdr []kv
	for _, k := range sortedKeys(i.Headers) {
		hdr = append(hdr, kv{k, strings.Join(i.Headers[k], ", ")})
	}
	s = append(s, section{"All headers (alphabetical; Go does not keep wire order)", hdr})
	if len(i.Query) > 0 {
		var rows []kv
		for _, k := range sortedKeys(i.Query) {
			rows = append(rows, kv{k, strings.Join(i.Query[k], ", ")})
		}
		s = append(s, section{"Query parameters", rows})
	}
	if len(i.Cookies) > 0 {
		var rows []kv
		for _, k := range sortedKeys(i.Cookies) {
			rows = append(rows, kv{k, i.Cookies[k]})
		}
		s = append(s, section{"Cookies", rows})
	}
	s = append(s, section{"Server", []kv{
		{"Container hostname", i.Container}, {"Time", i.Time},
	}})
	return s
}

func renderText(i Info) string {
	var b strings.Builder
	for _, sec := range sections(i) {
		fmt.Fprintf(&b, "== %s ==\n", sec.Title)
		for _, r := range sec.Rows {
			fmt.Fprintf(&b, "%-34s %s\n", r.K+":", r.V)
		}
		b.WriteString("\n")
	}
	return b.String()
}

const page = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>whoami</title><style>
:root{color-scheme:light dark;--b:#ccc8}
body{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.3rem} h2{font-size:1rem;margin:1.5rem 0 .3rem;border-bottom:1px solid var(--b)}
table{border-collapse:collapse;width:100%} td{padding:3px 8px;border-bottom:1px solid var(--b);vertical-align:top;word-break:break-all}
td:first-child{white-space:nowrap;width:1%;opacity:.7} .hi td{font-weight:bold}
small{opacity:.6}
</style></head><body><h1>whoami</h1>
<small>Forwarded-style headers can be spoofed by clients unless set by a proxy you trust. Also: <a href="/json">/json</a> · <a href="/ip">/ip</a></small>`

func renderHTML(i Info) string {
	var b strings.Builder
	b.WriteString(page)
	for n, sec := range sections(i) {
		fmt.Fprintf(&b, "<h2>%s</h2><table", html.EscapeString(sec.Title))
		if n == 0 {
			b.WriteString(` class="hi"`)
		}
		b.WriteString(">")
		for _, r := range sec.Rows {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td></tr>", html.EscapeString(r.K), html.EscapeString(r.V))
		}
		b.WriteString("</table>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	info := gather(r)
	accept := r.Header.Get("Accept")

	switch {
	case r.URL.Path == "/ip":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, info.ClaimedIP)
	case r.URL.Path == "/json" || r.URL.Query().Get("format") == "json" || strings.Contains(accept, "application/json"):
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(info)
	case r.URL.Query().Get("format") == "text" || !strings.Contains(accept, "text/html"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, renderText(info))
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, renderHTML(info))
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// `/whoami -healthcheck` for Docker HEALTHCHECK (scratch image has no curl/sh)
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		c := http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get("http://127.0.0.1:" + port + "/ip")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Println("listening on :" + port)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
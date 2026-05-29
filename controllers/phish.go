package controllers

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/gophish/gophish/config"
	ctx "github.com/gophish/gophish/context"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/util"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jordan-wright/unindexed"
)

// ErrInvalidRequest is thrown when a request with an invalid structure is
// received
var ErrInvalidRequest = errors.New("Invalid request")

// ErrCampaignComplete is thrown when an event is received for a campaign that
// has already been marked as complete.
var ErrCampaignComplete = errors.New("Event received on completed campaign")

// PhishingServerOption is a functional option that is used to configure the
// the phishing server
type PhishingServerOption func(*PhishingServer)

// PhishingServer is an HTTP server that implements the campaign event
// handlers, such as email open tracking, click tracking, and more.
type PhishingServer struct {
	server *http.Server
	config config.PhishServer
}

// NewPhishingServer returns a new instance of the phishing server with
// provided options applied.
func NewPhishingServer(config config.PhishServer, options ...PhishingServerOption) *PhishingServer {
	defaultServer := &http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Addr:         config.ListenURL,
	}
	ps := &PhishingServer{
		server: defaultServer,
		config: config,
	}
	for _, opt := range options {
		opt(ps)
	}
	ps.registerRoutes()
	return ps
}

// Start launches the phishing server, listening on the configured address.
func (ps *PhishingServer) Start() {
	if ps.config.UseTLS {
		// Only support TLS 1.2 and above - ref #1691, #1689
		ps.server.TLSConfig = defaultTLSConfig
		err := util.CheckAndCreateSSL(ps.config.CertPath, ps.config.KeyPath)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("Starting phishing server at https://%s", ps.config.ListenURL)
		log.Fatal(ps.server.ListenAndServeTLS(ps.config.CertPath, ps.config.KeyPath))
	}
	// If TLS isn't configured, just listen on HTTP
	log.Infof("Starting phishing server at http://%s", ps.config.ListenURL)
	log.Fatal(ps.server.ListenAndServe())
}

// Shutdown attempts to gracefully shutdown the server.
func (ps *PhishingServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	return ps.server.Shutdown(ctx)
}

// phishNotFound is the dead-end response handler. If a not_found_redirect_url
// is configured under phish_server, every dead-end request (invalid rid,
// missing rid, burnt rid, completed campaign, unmatched route, failed
// token validation, etc.) is 302-redirected there so a casual visitor or
// scanner sees a benign page instead of a 404 fingerprint. If the config
// field is empty, the original 404 behavior is preserved.
func (ps *PhishingServer) phishNotFound(w http.ResponseWriter, r *http.Request) {
	if ps.config.NotFoundRedirectURL != "" {
		http.Redirect(w, r, ps.config.NotFoundRedirectURL, http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

// tokenValid recomputes the HMAC-SHA256 token for the rid in the request
// and compares it (constant-time) against the ?token= query parameter.
// Returns false on any missing/malformed input or mismatch, including when
// the configured secret is empty (strict-deny by default).
func (ps *PhishingServer) tokenValid(r *http.Request) bool {
	rid := r.URL.Query().Get(models.RecipientParameter)
	provided := r.URL.Query().Get("token")
	if rid == "" || provided == "" {
		return false
	}
	secret, err := hex.DecodeString(ps.config.Redirector.Secret)
	if err != nil || len(secret) == 0 {
		return false
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(rid))
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(provided))
}

// CreatePhishingRouter creates the router that handles phishing connections.
func (ps *PhishingServer) registerRoutes() {
	router := mux.NewRouter()
	fileServer := http.FileServer(unindexed.Dir("./static/endpoint/"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fileServer))
	router.HandleFunc("/hi", ps.TrackHandler)
	router.HandleFunc("/{path:.*}/hi", ps.TrackHandler)
	router.HandleFunc("/beep", ps.BeepHandler)
	router.HandleFunc("/{path:.*}/beep", ps.BeepHandler)
	router.HandleFunc("/robots.txt", ps.RobotsHandler)
	router.HandleFunc("/{path:.*}", ps.PhishHandler)
	router.NotFoundHandler = http.HandlerFunc(ps.phishNotFound)

	// Setup GZIP compression
	gzipWrapper, _ := gziphandler.NewGzipLevelHandler(gzip.BestCompression)
	phishHandler := gzipWrapper(router)

	// Respect X-Forwarded-For and X-Real-IP headers in case we're behind a
	// reverse proxy.
	phishHandler = handlers.ProxyHeaders(phishHandler)

	// Setup logging
	phishHandler = handlers.CombinedLoggingHandler(log.Writer(), phishHandler)
	ps.server.Handler = phishHandler
}

// TrackHandler tracks emails as they are opened, updating the status for the given Result
func (ps *PhishingServer) TrackHandler(w http.ResponseWriter, r *http.Request) {
	if !ps.tokenValid(r) {
		ps.phishNotFound(w, r)
		return
	}
	r, err := setupContext(r)
	if err != nil {
		// Log the error if it wasn't something we can safely ignore
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		ps.phishNotFound(w, r)
		return
	}
	rs := ctx.Get(r, "result").(models.Result)

	// Once the landing page has been served (or the form submitted), a
	// subsequent open-tracking request is stale. Treat it like an invalid
	// rid: no event, dead-end response.
	if rs.LandingGetServed || rs.LandingPostServed {
		ps.phishNotFound(w, r)
		return
	}

	d := ctx.Get(r, "details").(models.EventDetails)
	err = rs.HandleEmailOpened(d)
	if err != nil {
		log.Error(err)
	}
	http.ServeFile(w, r, "static/images/pixel.png")
}

// BeepHandler is the upstream redirector's bot-detection signal endpoint.
// Cloudflare Worker (or any redirector) makes a server-side GET to
// /beep?id=<rid>&token=<hmac> when it has decided the visitor is a bot.
// On valid token, gophish appends a "Bot Click" event to the result's
// timeline; it never burns the rid, never renders anything, and returns
// 200 with no body. Once the landing page has been served, further bot
// pings are stale and treated as invalid.
func (ps *PhishingServer) BeepHandler(w http.ResponseWriter, r *http.Request) {
	if !ps.tokenValid(r) {
		ps.phishNotFound(w, r)
		return
	}
	r, err := setupContext(r)
	if err != nil {
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		ps.phishNotFound(w, r)
		return
	}
	rs := ctx.Get(r, "result").(models.Result)

	// Don't log post-burn bot pings; the rid is already past its useful
	// life-cycle stage and any bot probe at this point is just noise.
	if rs.LandingGetServed || rs.LandingPostServed {
		ps.phishNotFound(w, r)
		return
	}

	d := ctx.Get(r, "details").(models.EventDetails)
	if err := rs.HandleBotClick(d); err != nil {
		log.Error(err)
	}
	w.WriteHeader(http.StatusOK)
}

// PhishHandler handles incoming client connections and registers the associated actions performed
// (such as clicked link, etc.)
func (ps *PhishingServer) PhishHandler(w http.ResponseWriter, r *http.Request) {
	if !ps.tokenValid(r) {
		ps.phishNotFound(w, r)
		return
	}
	r, err := setupContext(r)
	if err != nil {
		// Log the error if it wasn't something we can safely ignore
		if err != ErrInvalidRequest && err != ErrCampaignComplete {
			log.Error(err)
		}
		ps.phishNotFound(w, r)
		return
	}
	rs := ctx.Get(r, "result").(models.Result)
	c := ctx.Get(r, "campaign").(models.Campaign)
	d := ctx.Get(r, "details").(models.EventDetails)

	// One-shot guard: at most one GET and one POST per rid. The burn is an
	// atomic conditional UPDATE, so concurrent requests for the same rid can
	// only have one winner per method.
	burned := true
	switch r.Method {
	case "GET":
		burned, err = rs.BurnLandingGet()
	case "POST":
		burned, err = rs.BurnLandingPost()
	}
	if err != nil {
		log.Error(err)
	}
	if !burned {
		ps.phishNotFound(w, r)
		return
	}

	p, err := models.GetPage(c.PageId, c.UserId)
	if err != nil {
		log.Error(err)
		ps.phishNotFound(w, r)
		return
	}
	switch {
	case r.Method == "GET":
		err = rs.HandleClickedLink(d)
		if err != nil {
			log.Error(err)
		}
	case r.Method == "POST":
		err = rs.HandleFormSubmit(d)
		if err != nil {
			log.Error(err)
		}
	}
	ptx, err := models.NewPhishingTemplateContext(&c, rs.BaseRecipient, rs.RId)
	if err != nil {
		log.Error(err)
		ps.phishNotFound(w, r)
		return
	}
	ps.renderPhishResponse(w, r, ptx, p)
}

// renderPhishResponse handles rendering the correct response to the phishing
// connection. This usually involves writing out the page HTML or redirecting
// the user to the correct URL.
func (ps *PhishingServer) renderPhishResponse(w http.ResponseWriter, r *http.Request, ptx models.PhishingTemplateContext, p models.Page) {
	// If the request was a form submit and a redirect URL was specified, we
	// should send the user to that URL
	if r.Method == "POST" {
		if p.RedirectURL != "" {
			redirectURL, err := models.ExecuteTemplate(p.RedirectURL, ptx)
			if err != nil {
				log.Error(err)
				ps.phishNotFound(w, r)
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}
	// Otherwise, we just need to write out the templated HTML
	html, err := models.ExecuteTemplate(p.HTML, ptx)
	if err != nil {
		log.Error(err)
		ps.phishNotFound(w, r)
		return
	}
	w.Write([]byte(html))
}

// RobotsHandler prevents search engines, etc. from indexing phishing materials
func (ps *PhishingServer) RobotsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "User-agent: *\nDisallow: /")
}

// setupContext handles some of the administrative work around receiving a new
// request, such as checking the result ID, the campaign, etc.
func setupContext(r *http.Request) (*http.Request, error) {
	err := r.ParseForm()
	if err != nil {
		log.Error(err)
		return r, err
	}
	rid := r.Form.Get(models.RecipientParameter)
	if rid == "" {
		return r, ErrInvalidRequest
	}
	rs, err := models.GetResult(rid)
	if err != nil {
		return r, err
	}
	c, err := models.GetCampaign(rs.CampaignId, rs.UserId)
	if err != nil {
		log.Error(err)
		return r, err
	}
	// Don't process events for completed campaigns
	if c.Status == models.CampaignComplete {
		return r, ErrCampaignComplete
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	// Handle post processing such as GeoIP
	err = rs.UpdateGeo(ip)
	if err != nil {
		log.Error(err)
	}
	d := models.EventDetails{
		Payload: r.Form,
		Browser: make(map[string]string),
	}
	d.Browser["address"] = ip
	d.Browser["user-agent"] = r.Header.Get("User-Agent")

	r = ctx.Set(r, "result", rs)
	r = ctx.Set(r, "campaign", c)
	r = ctx.Set(r, "details", d)
	return r, nil
}

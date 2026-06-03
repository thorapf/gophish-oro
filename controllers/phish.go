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

// clientIP returns the visitor's IP exactly as Cloudflare presents it in the
// CF-Connecting-IP header. The redirector signs against this same header
// value, and because both the redirector and gophish sit behind Cloudflare,
// gophish receives the identical client IP here.
func clientIP(r *http.Request) string {
	return r.Header.Get("CF-Connecting-IP")
}

// signatureMatches reports whether the ?id and ?sig query parameters carry a
// valid HMAC-SHA256(secret, msg) signature, compared in constant time. An
// empty configured secret means strict-deny (false). There is no expiry: a
// signature is either valid or it is not.
func (ps *PhishingServer) signatureMatches(r *http.Request, msg string) bool {
	q := r.URL.Query()
	rid := q.Get(models.RecipientParameter)
	sig := q.Get("sig")
	if rid == "" || sig == "" {
		return false
	}
	secret, err := hex.DecodeString(ps.config.Redirector.Secret)
	if err != nil || len(secret) == 0 {
		return false
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// validateSignature validates the id-bound signature the redirector appends to
// the server-side-fetched /hi endpoint:
//
//	?id=<rid>&sig=<hex HMAC-SHA256(secret, rid)>
//
// /hi is fetched by the redirector itself (not the visitor's browser), so the
// connecting IP gophish sees is the redirector's, not the target's — hence it
// is bound to the rid alone, not the IP.
func (ps *PhishingServer) validateSignature(r *http.Request) bool {
	rid := r.URL.Query().Get(models.RecipientParameter)
	return ps.signatureMatches(r, rid)
}

// validateClickSignature validates the IP-bound signature used for the landing
// page:
//
//	?id=<rid>&sig=<hex HMAC-SHA256(secret, rid "." CF-Connecting-IP)>
//
// The redirector mints this against the visitor's CF-Connecting-IP after the
// bot checks pass. gophish recomputes it against the IP it sees in the same
// header. A request replayed from any other network — most importantly a Safe
// Browsing verification crawl from Google infrastructure — computes a
// different IP, fails the comparison, and is dead-ended to the configured
// not-found URL. There is no expiry, so a target reloading from the same IP is
// served indefinitely without a round trip back through the redirector.
func (ps *PhishingServer) validateClickSignature(r *http.Request) bool {
	rid := r.URL.Query().Get(models.RecipientParameter)
	return ps.signatureMatches(r, rid+"."+clientIP(r))
}

// CreatePhishingRouter creates the router that handles phishing connections.
func (ps *PhishingServer) registerRoutes() {
	router := mux.NewRouter()
	fileServer := http.FileServer(unindexed.Dir("./static/endpoint/"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fileServer))
	router.HandleFunc("/hi", ps.TrackHandler)
	router.HandleFunc("/{path:.*}/hi", ps.TrackHandler)
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
	// /hi is fetched server-side by the redirector, which signs it against the
	// rid alone (the connecting IP here is the redirector's, not the target's).
	if !ps.validateSignature(r) {
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
	d := ctx.Get(r, "details").(models.EventDetails)
	err = rs.HandleEmailOpened(d)
	if err != nil {
		log.Error(err)
	}
	http.ServeFile(w, r, "static/images/pixel.png")
}

// PhishHandler handles incoming client connections and registers the associated actions performed
// (such as clicked link, etc.)
func (ps *PhishingServer) PhishHandler(w http.ResponseWriter, r *http.Request) {
	if !ps.validateClickSignature(r) {
		// Bad/missing/IP-mismatched signature: dead-end to the configured
		// not-found URL. A signature minted by the redirector for one visitor
		// IP will not validate for any other network, so a replayed or crawled
		// URL lands here.
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

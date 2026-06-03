package controllers

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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

// challengePagePath is the on-disk press-and-hold gate served before the
// landing page. It is read from disk on each request so it can be restyled
// without rebuilding gophish.
const challengePagePath = "templates/challenge.html"

// challengeParameter is the form field the challenge page POSTs back once the
// press-and-hold gesture completes. Its presence on a POST distinguishes a
// challenge completion (serve the landing page) from a landing-page form
// submission (capture credentials).
const challengeParameter = "__challenge"

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
// is configured under phish_server, every dead-end request (invalid or missing
// rid, completed campaign, unmatched route, etc.) is 302-redirected there so a
// casual visitor or scanner sees a benign page instead of a 404 fingerprint. If
// the config field is empty, the original 404 behavior is preserved.
func (ps *PhishingServer) phishNotFound(w http.ResponseWriter, r *http.Request) {
	if ps.config.NotFoundRedirectURL != "" {
		http.Redirect(w, r, ps.config.NotFoundRedirectURL, http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

// CreatePhishingRouter creates the router that handles phishing connections.
func (ps *PhishingServer) registerRoutes() {
	router := mux.NewRouter()
	fileServer := http.FileServer(unindexed.Dir("./static/endpoint/"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fileServer))
	router.HandleFunc("/pix", ps.TrackHandler)
	router.HandleFunc("/{path:.*}/pix", ps.TrackHandler)
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

// PhishHandler handles incoming client connections and registers the associated
// actions performed (such as clicked link, etc.).
//
// The landing page is gated behind a press-and-hold challenge served directly
// by gophish:
//
//   - GET: the click is recorded and the challenge page is served. The landing
//     page HTML is deliberately NOT included in this response, so a scanner that
//     fetches the URL without performing the gesture never receives it.
//   - POST carrying the challenge marker: the gesture completed, so a "Completed
//     Challenge" event is recorded and the landing page HTML is returned in the
//     body for the challenge page to swap in.
//   - POST without the marker: a submission from the landing page's own form,
//     handled exactly as upstream gophish does (capture + optional redirect).
func (ps *PhishingServer) PhishHandler(w http.ResponseWriter, r *http.Request) {
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

	// Initial visit: record the click and serve the challenge gate. No landing
	// page content is exposed until the gesture is completed.
	if r.Method == "GET" {
		if err = rs.HandleClickedLink(d); err != nil {
			log.Error(err)
		}
		ps.serveChallenge(w, r)
		return
	}

	p, err := models.GetPage(c.PageId, c.UserId)
	if err != nil {
		log.Error(err)
		ps.phishNotFound(w, r)
		return
	}
	ptx, err := models.NewPhishingTemplateContext(&c, rs.BaseRecipient, rs.RId)
	if err != nil {
		log.Error(err)
		ps.phishNotFound(w, r)
		return
	}

	// Challenge completion: record the event and hand back the landing page so
	// the gate page can render it in place.
	if r.PostFormValue(challengeParameter) != "" {
		if err = rs.HandleCompletedChallenge(d); err != nil {
			log.Error(err)
		}
		html, err := models.ExecuteTemplate(p.HTML, ptx)
		if err != nil {
			log.Error(err)
			ps.phishNotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// Landing page form submission.
	if err = rs.HandleFormSubmit(d); err != nil {
		log.Error(err)
	}
	ps.renderPhishResponse(w, r, ptx, p)
}

// serveChallenge writes the press-and-hold gate read from challengePagePath.
// The page is static: on a completed gesture its JS POSTs the challenge marker
// back to the same URL and swaps in the landing page returned there.
func (ps *PhishingServer) serveChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := os.ReadFile(challengePagePath)
	if err != nil {
		log.Error(err)
		ps.phishNotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Write(body)
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

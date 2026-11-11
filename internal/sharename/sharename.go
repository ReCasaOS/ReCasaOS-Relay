// Package sharename validates the public names a box claims for sharing (<name>.<share domain>).
package sharename

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalid  = errors.New("sharename: invalid name")
	ErrReserved = errors.New("sharename: reserved name")
)

// 3 to 32 characters of [a-z0-9-], not starting or ending with "-"; "a--b" is a valid DNS label.
var re = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

// reserved is the built-in list of names no box can claim, whatever the operator's own list on
// /admin says: the relay's own labels, the names a mail or web host is expected to carry, the words
// that make a phishing page look official, and the brands most often imitated. Lower case, as names
// are. A name here answers ErrReserved; the operator adds the rest on /admin.
var reserved = []string{
	// the relay and its product
	"www", "www1", "www2", "relay", "relais", "box", "boxes", "fleet", "tunnel", "share", "recasaos", "casaos",
	"headscale", "tailscale", "derp", "derper", "localhost", "local", "internal", "intranet",
	// infrastructure labels of a domain
	"admin", "administrator", "root", "sys", "system", "sysadmin", "ops", "noc",
	"api", "app", "apps", "dashboard", "panel", "console", "portal",
	"mail", "email", "smtp", "imap", "pop", "pop3", "mx1", "mx2", "webmail", "autodiscover", "autoconfig",
	"ns1", "ns2", "ns3", "dns", "ftp", "sftp", "ssh", "vpn", "proxy", "gateway", "cdn", "static", "assets", "media", "img", "images",
	"git", "gitlab", "github", "build", "registry", "docker", "mirror", "repo", "packages", "download", "downloads", "update", "updates",
	"status", "health", "metrics", "monitor", "monitoring", "grafana", "prometheus", "logs",
	"dev", "test", "testing", "staging", "stage", "demo", "beta", "alpha", "preview", "sandbox", "example", "null", "undefined",
	"acme", "letsencrypt", "ssl", "tls", "cert", "certs", "secure", "security",
	// what a phishing page calls itself
	"login", "logon", "signin", "sign-in", "signup", "sign-up", "register", "auth", "oauth", "sso", "authenticate", "authentication",
	"account", "accounts", "my-account", "profile", "user", "users", "password", "passwords", "reset", "recover", "recovery", "verify", "verification", "confirm", "confirmation",
	"pay", "payment", "payments", "billing", "invoice", "invoices", "checkout", "wallet", "bank", "banque", "refund", "prize", "winner", "gift", "lottery",
	"support", "help", "helpdesk", "service", "services", "customer", "client", "clients", "contact", "info", "official", "officiel", "notice", "alert", "alerts", "urgent", "warning",
	"abuse", "postmaster", "hostmaster", "webmaster", "legal", "privacy", "terms", "press", "blog", "news", "docs", "doc", "wiki", "forum", "shop", "store", "boutique",
	// the brands most often imitated
	"google", "gmail", "youtube", "android", "apple", "icloud", "itunes", "microsoft", "outlook", "hotmail", "office", "office365", "onedrive", "windows", "xbox",
	"facebook", "meta", "instagram", "whatsapp", "messenger", "twitter", "tiktok", "snapchat", "linkedin", "discord", "telegram", "signal", "reddit",
	"amazon", "aws", "prime", "ebay", "aliexpress", "alibaba", "leboncoin", "vinted", "zalando", "cdiscount", "fnac",
	"paypal", "stripe", "visa", "mastercard", "revolut", "n26", "lydia", "wise", "coinbase", "binance", "crypto", "bitcoin",
	"netflix", "spotify", "deezer", "disney", "canal", "canalplus", "molotov", "twitch", "steam", "epicgames", "playstation", "nintendo",
	"dropbox", "box-com", "wetransfer", "nextcloud", "synology", "qnap", "plex", "jellyfin", "immich",
	"orange", "sfr", "bouygues", "free", "freebox", "livebox", "ovh", "ovhcloud", "scaleway", "gandi", "ionos", "cloudflare",
	"laposte", "chronopost", "colissimo", "dhl", "ups", "fedex", "mondialrelay", "amazon-livraison",
	"ameli", "impots", "impots-gouv", "gouv", "service-public", "caf", "urssaf", "pole-emploi", "francetravail", "ants", "antai", "edf", "engie", "total", "totalenergies",
	"bnp", "bnpparibas", "creditagricole", "credit-agricole", "societegenerale", "societe-generale", "lcl", "boursorama", "caissedepargne", "banquepopulaire", "cic", "creditmutuel", "credit-mutuel", "labanquepostale", "fortuneo", "hellobank", "ing", "axa", "maif", "macif",
}

// ValidLabel checks the syntax only (a reserved word passes): the operator may forbid one.
func ValidLabel(name string) error {
	if !re.MatchString(name) {
		return ErrInvalid
	}
	return nil
}

// Valid returns ErrInvalid when name is not an acceptable label and ErrReserved when it is on the built-in list.
func Valid(name string) error {
	if err := ValidLabel(name); err != nil {
		return err
	}
	if slices.Contains(reserved, name) {
		return ErrReserved
	}
	return nil
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHost checks an operator-given host name (SHARE_DOMAIN, RELAY_HOST): lowercase DNS labels
// joined by dots, no scheme, port, trailing dot or space.
func ValidHost(h string) error {
	if h == "" || len(h) > 253 {
		return ErrInvalid
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabel.MatchString(l) {
			return ErrInvalid
		}
	}
	return nil
}

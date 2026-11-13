package feeds

// Preset is a list the operator can add in /admin (always added disabled). Only https URLs.
type Preset struct {
	Key, Name, URL, Format, AuthName, Note string
	Column, EverySec                       int
	NeedsKey                               bool
}

var Presets = []Preset{
	{Key: "firehol1", Name: "FireHOL level 1", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", Format: "text", EverySec: 3600,
		Note: "Aggregate (DShield, Feodo, full bogons, Spamhaus DROP); see each source's license"},
	{Key: "spamhaus-drop", Name: "Spamhaus DROP", URL: "https://www.spamhaus.org/drop/drop.txt", Format: "text", EverySec: 86400,
		Note: "Spamhaus asks for at most one download a day; free for non-commercial use; the text file is being replaced by JSON"},
	{Key: "blocklistde", Name: "blocklist.de (all)", URL: "https://lists.blocklist.de/lists/all.txt", Format: "text", EverySec: 3600,
		Note: "Regenerated every 30 minutes"},
	{Key: "et-compromised", Name: "Emerging Threats compromised", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", Format: "text", EverySec: 86400,
		Note: "The builder checks it answers over https; if not, this preset is dropped"},
	{Key: "tor-exits", Name: "Tor exit nodes", URL: "https://check.torproject.org/torbulkexitlist", Format: "text", EverySec: 3600,
		Note: "Blocking cuts every Tor visitor, including people who only want privacy"},
	{Key: "abuseipdb", Name: "AbuseIPDB (subscription)", URL: "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100000", Format: "text", AuthName: "Key", EverySec: 3600, NeedsKey: true,
		Note: "confidenceMinimum needs a paid plan; check your plan's daily download limit"},
	{Key: "abuseipdb-free", Name: "AbuseIPDB (free)", URL: "https://api.abuseipdb.com/api/v2/blacklist", Format: "text", AuthName: "Key", EverySec: 21600, NeedsKey: true,
		Note: "Free plan: 10 000 addresses at 100 % confidence, 5 downloads a day"},
	{Key: "crowdsec", Name: "CrowdSec blocklist", URL: "https://admin.api.crowdsec.net/v1/integrations/<integration id>/content", Format: "text", AuthName: "Authorization-Basic", EverySec: 3600, NeedsKey: true,
		Note: "Raw IP list integration from the CrowdSec console; credentials shown once there"},
}

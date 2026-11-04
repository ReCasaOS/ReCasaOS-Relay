package admin

import "strconv"

// humanBytes formats n in decimal units: whole bytes below 1 kB, then one decimal place.
func humanBytes(n float64) string {
	if n < 1000 {
		return strconv.FormatFloat(n, 'f', 0, 64) + " B"
	}
	units := []string{"kB", "MB", "GB", "TB", "PB"}
	i := 0
	// 999.95 rounds to 1000.0: show it as the next unit.
	for n /= 1000; n >= 999.95 && i < len(units)-1; i++ {
		n /= 1000
	}
	return strconv.FormatFloat(n, 'f', 1, 64) + " " + units[i]
}

func humanRate(bps float64) string { return humanBytes(bps) + "/s" }

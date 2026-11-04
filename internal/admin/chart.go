package admin

import (
	"html/template"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

type chartSeries struct {
	Name   string
	Values []float64 // bytes/s per bucket
}

// chartRange is one choice of the range links: n buckets of step, read from res rows.
type chartRange struct {
	res  store.Resolution
	step time.Duration
	n    int
}

var chartRanges = map[string]chartRange{
	"1h":  {store.PerMinute, time.Minute, 60},
	"24h": {store.PerMinute, 15 * time.Minute, 96},
	"30d": {store.PerHour, 6 * time.Hour, 120},
}

// start is the first bucket's start. The last bucket is the last complete one: the one still filling
// would read as a drop. Truncate aligns 6 h buckets on UTC.
func (c chartRange) start(now time.Time) time.Time {
	return now.Truncate(c.step).Add(-time.Duration(c.n) * c.step)
}

// topNodes is how many nodes get their own series; the rest are summed as "others".
const topNodes = 5

// fleetSeries buckets one fleet's points (Rx: what each node sends to the relay) into bytes/s and
// keeps the topNodes nodes by volume in the range, the rest summed as "others". names maps node ID
// to hostname.
func fleetSeries(points []store.UsagePoint, names map[string]string, c chartRange, start time.Time) []chartSeries {
	byNode := map[string][]float64{}
	vol := map[string]int64{}
	for _, p := range points {
		i := int(p.At.Sub(start) / c.step)
		if p.At.Before(start) || i >= c.n {
			continue
		}
		if byNode[p.NodeID] == nil {
			byNode[p.NodeID] = make([]float64, c.n)
		}
		byNode[p.NodeID][i] += float64(p.Rx) / c.step.Seconds()
		vol[p.NodeID] += p.Rx
	}
	ids := make([]string, 0, len(byNode))
	for id := range byNode {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if vol[ids[i]] != vol[ids[j]] {
			return vol[ids[i]] > vol[ids[j]]
		}
		return ids[i] < ids[j]
	})
	var out []chartSeries
	for k, id := range ids {
		if k < topNodes {
			name := names[id]
			if name == "" {
				name = "node " + id // no longer in Headscale
			}
			out = append(out, chartSeries{name, byNode[id]})
			continue
		}
		if k == topNodes {
			out = append(out, chartSeries{"others", make([]float64, c.n)})
		}
		for i, v := range byNode[id] {
			out[topNodes].Values[i] += v
		}
	}
	return out
}

const chartW, chartBase, chartTop = 600.0, 110.0, 16.0

// stackedChart draws the series stacked, the first at the bottom, as one band polygon each (class
// c0..c5, c5 being "others"). The SVG holds only numbers and fixed attributes: names go in the
// page's legend, through the template.
func stackedChart(series []chartSeries, buckets int) template.HTML {
	buckets = max(buckets, 2)
	cum := make([][]float64, len(series)+1) // cum[s+1][k]: top of series s; cum[0]: the baseline
	cum[0] = make([]float64, buckets)
	top := 0.0
	for s, ser := range series {
		cum[s+1] = make([]float64, buckets)
		for k := range buckets {
			cum[s+1][k] = cum[s][k]
			if k < len(ser.Values) && ser.Values[k] > 0 && !math.IsInf(ser.Values[k], 1) {
				cum[s+1][k] += ser.Values[k]
			}
			top = max(top, cum[s+1][k])
		}
	}
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
	x := func(k int) string { return num(float64(k) * chartW / float64(buckets-1)) }
	y := func(v float64) string {
		if top <= 0 {
			return num(chartBase)
		}
		return num(chartBase - v/top*(chartBase-chartTop))
	}
	var b strings.Builder
	b.WriteString(`<svg viewBox="0 0 600 120" width="100%" role="img" aria-label="relayed rate per node" data-buckets="` + strconv.Itoa(buckets) + `">`)
	b.WriteString(`<line x1="0" y1="110" x2="600" y2="110" class="axis"/>`)
	if top > 0 {
		b.WriteString(`<line x1="0" y1="16" x2="600" y2="16" class="axis grid"/><text x="2" y="12" class="lbl">` + humanRate(top) + `</text>`)
	}
	for s := range series {
		b.WriteString(`<polygon class="c` + strconv.Itoa(min(s, topNodes)) + `" points="`)
		for k := range buckets {
			b.WriteString(x(k) + "," + y(cum[s+1][k]) + " ")
		}
		for k := buckets - 1; k >= 0; k-- {
			b.WriteString(x(k) + "," + y(cum[s][k]))
			if k > 0 {
				b.WriteString(" ")
			}
		}
		b.WriteString(`"/>`)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

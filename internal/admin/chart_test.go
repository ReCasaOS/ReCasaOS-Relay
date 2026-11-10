package admin

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

func TestHumanBytes(t *testing.T) {
	for n, want := range map[float64]string{0: "0 B", 999: "999 B", 1500: "1.5 kB", 37.4e9: "37.4 GB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%v) = %q, want %q", n, got, want)
		}
	}
	if got := humanRate(2.5e6); got != "2.5 MB/s" {
		t.Errorf("humanRate(2.5e6) = %q", got)
	}
}

func TestChartAllZero(t *testing.T) {
	svg := string(stackedChart([]chartSeries{{"a", make([]float64, 60)}, {"b", make([]float64, 60)}}, 60, "relayed"))
	if !strings.HasPrefix(svg, "<svg") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("not an svg: %s", svg)
	}
	if strings.Contains(svg, "NaN") || strings.Contains(svg, "Inf") {
		t.Fatalf("NaN or Inf in %s", svg)
	}
	if svg := string(stackedChart(nil, 60, "relayed")); strings.Contains(svg, "NaN") || !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("no series: %s", svg)
	}
}

func TestFleetSeries(t *testing.T) {
	c := chartRanges["24h"]
	now := time.Date(2026, 11, 4, 12, 7, 0, 0, time.UTC)
	start := c.start(now)
	if want := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC); !start.Equal(want) {
		t.Fatalf("start %v, want %v", start, want)
	}
	var pts []store.UsagePoint
	for i := 1; i <= 7; i++ { // node i sends i MB in the last complete bucket
		pts = append(pts, store.UsagePoint{NodeID: strconv.Itoa(i), At: now.Add(-10 * time.Minute), Rx: int64(i) * 1e6})
	}
	pts = append(pts, store.UsagePoint{NodeID: "7", At: now, Rx: 1e9}) // the bucket still filling: left out
	s := fleetSeries(pts, map[string]string{"7": "seven"}, c, start)
	if len(s) != 6 || s[0].Name != "seven" || s[1].Name != "node 6" || s[5].Name != "others" {
		t.Fatalf("series %+v", s)
	}
	if got, want := s[0].Values[95], 7e6/900; got != want {
		t.Errorf("top node rate %v, want %v", got, want)
	}
	if got, want := s[5].Values[95], 3e6/900; math.Abs(got-want) > 1e-9 { // nodes 1 and 2
		t.Errorf("others %v, want %v", got, want)
	}
}

var pointsRE = regexp.MustCompile(`points="([^"]*)"`)

// topEdge returns the y of the first n points of each polygon: the top edge, left to right.
func topEdges(t *testing.T, svg string, n int) [][]float64 {
	t.Helper()
	var out [][]float64
	for _, m := range pointsRE.FindAllStringSubmatch(svg, -1) {
		pts := strings.Fields(m[1])
		ys := make([]float64, n)
		for k := 0; k < n; k++ {
			y, err := strconv.ParseFloat(strings.Split(pts[k], ",")[1], 64)
			if err != nil {
				t.Fatal(err)
			}
			ys[k] = y
		}
		out = append(out, ys)
	}
	return out
}

func TestChartStacksInOrder(t *testing.T) {
	series := []chartSeries{
		{"big", []float64{5, 9, 2, 0, 7}},
		{"mid", []float64{1, 0, 4, 3, 2}},
		{"small", []float64{0, 1, 1, 0, 5}},
	}
	edges := topEdges(t, string(stackedChart(series, 5, "relayed")), 5)
	if len(edges) != 3 {
		t.Fatalf("%d polygons, want 3", len(edges))
	}
	for s := 1; s < len(edges); s++ {
		for k := range edges[s] {
			if edges[s][k] > edges[s-1][k] {
				t.Errorf("series %d point %d: y %v below the series under it (%v)", s, k, edges[s][k], edges[s-1][k])
			}
		}
	}
}

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// deleteCall sends DELETE to the public front with the fleet secret and returns the status.
func (r *rig) deleteCall(path, secret string) int {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, r.frontURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (r *rig) nodeNames(user string) []string {
	r.t.Helper()
	ns, err := r.hs.ListNodes(context.Background(), user)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, n := range ns {
		out = append(out, n.Hostname)
	}
	return out
}

func (r *rig) userExists(name string) bool {
	r.t.Helper()
	var res struct{ Users []struct{ Name string } }
	if err := json.Unmarshal(r.hsDo("GET", "/api/v1/user?name="+name, nil), &res); err != nil {
		r.t.Fatal(err)
	}
	for _, u := range res.Users {
		if u.Name == name {
			return true
		}
	}
	return false
}

// TestFleetDeletionAndCleanup runs the DELETE endpoints and the janitor against a real Headscale and
// real tailscaled nodes:
//
//	go test -tags e2e ./e2e -run TestFleetDeletionAndCleanup -v -timeout 15m
//
// The janitor runs every 5 s and treats a fleet as idle after 120 s.
func TestFleetDeletionAndCleanup(t *testing.T) {
	r := newRig(t)
	r.env = []string{"GC_INTERVAL=5s", "IDLE_AFTER=120s"}
	r.up()

	idA, secA := r.createFleet("A")
	userA := r.fleetUser["A"]
	a1 := r.startNode("A", "a1", r.joinKey(idA, secA))
	a2 := r.startNode("A", "a2", r.joinKey(idA, secA))
	spare := r.joinKey(idA, secA) // stays unused and unexpired: the janitor must keep it

	// The janitor deletes the USED keys of A (their nodes registered long ago) and keeps the spare,
	// and A's nodes must not notice: deleting a used key must not drop the node it registered.
	eventually(t, "used keys are pruned", 60*time.Second, func() error {
		used, unused := r.usedKeys(userA)
		if used != 0 || unused != 1 {
			return fmt.Errorf("used=%d unused=%d, want 0 and 1", used, unused)
		}
		return nil
	})
	if got := strings.Join(r.nodeNames(userA), ","); got != "a1,a2" && got != "a2,a1" {
		t.Fatalf("nodes of A after key pruning = %q", got)
	}
	r.mustReach(a1, a2)
	r.mustReach(a2, a1)
	_ = spare

	// DELETE one node: unknown hostnames are a success, a real one disappears.
	if code := r.deleteCall("/v1/fleets/"+idA+"/nodes/ghost", secA); code != http.StatusNoContent {
		t.Fatalf("unknown node = %d, want 204", code)
	}
	if code := r.deleteCall("/v1/fleets/"+idA+"/nodes/a2", secA); code != http.StatusNoContent {
		t.Fatalf("remove a2 = %d, want 204", code)
	}
	if got := r.nodeNames(userA); len(got) != 1 || got[0] != "a1" {
		t.Fatalf("nodes of A after removing a2 = %v", got)
	}
	if code := r.deleteCall("/v1/fleets/"+idA+"/nodes/a2", secA); code != http.StatusNoContent {
		t.Fatalf("remove a2 again = %d, want 204", code)
	}
	if code := r.deleteCall("/v1/fleets/"+idA+"/nodes/a!", secA); code != http.StatusBadRequest {
		t.Fatalf("bad hostname = %d, want 400", code)
	}
	if code := r.deleteCall("/v1/fleets/"+idA+"/nodes/a1", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d, want 401", code)
	}

	// Hostnames are not unique in Headscale: two nodes of one fleet registered as "dup" are two
	// nodes (ids differ), and the node endpoint removes both.
	r.startNodeAs("A", "dup", "dupA1", r.joinKey(idA, secA))
	r.startNodeAs("A", "dup", "dupA2", r.joinKey(idA, secA))
	if got := strings.Join(r.nodeNames(userA), ","); strings.Count(got, "dup") != 2 {
		t.Fatalf("nodes of A with two dups = %q", got)
	}
	if code := r.deleteCall("/v1/fleets/"+idA+"/nodes/dup", secA); code != http.StatusNoContent {
		t.Fatalf("remove dup = %d, want 204", code)
	}
	if got := r.nodeNames(userA); len(got) != 1 || got[0] != "a1" {
		t.Fatalf("nodes of A after removing both dups = %v", got)
	}
	// An unknown node id is a success for the client too (a 404 from Headscale is swallowed).
	if err := r.hs.DeleteNodeByID(context.Background(), "99999"); err != nil {
		t.Fatalf("DeleteNodeByID of an unknown id: %v", err)
	}

	// A fleet with two same-named nodes is deleted whole: the nodes go by id, then the user.
	idD, secD := r.createFleet("D")
	userD := r.fleetUser["D"]
	r.startNodeAs("D", "dup", "dupD1", r.joinKey(idD, secD))
	r.startNodeAs("D", "dup", "dupD2", r.joinKey(idD, secD))
	if code := r.deleteCall("/v1/fleets/"+idD, secD); code != http.StatusNoContent {
		t.Fatalf("delete D (two nodes named dup) = %d, want 204", code)
	}
	if r.userExists(userD) || len(r.nodeNames(userD)) != 0 {
		t.Fatal("D's user or nodes are still in Headscale")
	}

	// DELETE a whole fleet that still has a live node and an unused key.
	idB, secB := r.createFleet("B")
	userB := r.fleetUser["B"]
	r.startNode("B", "b1", r.joinKey(idB, secB))
	r.joinKey(idB, secB)
	if !strings.Contains(r.policy(), userB) {
		t.Fatal("policy does not name B before the deletion")
	}
	if code := r.deleteCall("/v1/fleets/"+idB, secB); code != http.StatusNoContent {
		t.Fatalf("delete B = %d, want 204", code)
	}
	if r.userExists(userB) || len(r.nodeNames(userB)) != 0 {
		t.Fatal("B's user or nodes are still in Headscale")
	}
	if keys, err := r.hs.ListPreAuthKeys(context.Background(), userB); err != nil || len(keys) != 0 {
		t.Fatalf("B's keys after deletion: %v %v", keys, err)
	}
	if pol := r.policy(); strings.Contains(pol, userB) || !strings.Contains(pol, userA) {
		t.Fatalf("policy after deleting B: %s", pol)
	}
	if code := r.deleteCall("/v1/fleets/"+idB, secB); code != http.StatusNotFound {
		t.Fatalf("second delete of B = %d, want 404", code)
	}

	// A fleet that never gets a node is deleted by the janitor once it has been idle for IDLE_AFTER,
	// while A (a1 is online, so it is touched on every pass) stays.
	idC, secC := r.createFleet("C")
	userC := r.fleetUser["C"]
	started := time.Now()
	eventually(t, "idle fleet C is deleted", 3*time.Minute, func() error {
		if r.userExists(userC) {
			return fmt.Errorf("user still there")
		}
		return nil
	})
	if age := time.Since(started); age < 100*time.Second {
		t.Fatalf("C deleted after only %s: the janitor ignores IDLE_AFTER", age)
	}
	if code := r.deleteCall("/v1/fleets/"+idC, secC); code != http.StatusNotFound {
		t.Fatalf("C's secret still works after the janitor deleted it: %d", code)
	}
	if pol := r.policy(); strings.Contains(pol, userC) || !strings.Contains(pol, userA) {
		t.Fatalf("policy after the janitor deleted C: %s", pol)
	}
	if !r.userExists(userA) || len(r.nodeNames(userA)) != 1 {
		t.Fatal("the janitor touched A")
	}
}

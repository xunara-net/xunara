package dnsprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCloudflare is a minimal Cloudflare API v4 stand-in.
type fakeCloudflare struct {
	mu      sync.Mutex
	records map[string]string // name -> content (one record per name)
	created []map[string]any
	deleted []string

	token string
	t     *testing.T
}

func (f *fakeCloudflare) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		f.auth(w, r)
		if name := r.URL.Query().Get("name"); name != "example.com" {
			f.write(w, map[string]any{"success": true, "result": []any{}})
			return
		}
		f.write(w, map[string]any{"success": true, "result": []any{map[string]any{"id": "zone1", "name": "example.com"}}})
	})
	mux.HandleFunc("/zones/zone1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		f.auth(w, r)
		switch r.Method {
		case http.MethodGet:
			name := r.URL.Query().Get("name")
			f.mu.Lock()
			defer f.mu.Unlock()
			result := []any{}
			if _, ok := f.records[name]; ok {
				result = append(result, map[string]any{"id": "rec-" + name, "name": name, "content": f.records[name]})
			}
			f.writeLocked(w, map[string]any{"success": true, "result": result})
		case http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				f.t.Errorf("decoding create body: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			f.created = append(f.created, body)
			name, _ := body["name"].(string)
			content, _ := body["content"].(string)
			f.records[name] = content
			f.writeLocked(w, map[string]any{"success": true, "result": map[string]any{"id": "rec-" + name}})
		default:
			http.Error(w, "bogus", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/zones/zone1/dns_records/", func(w http.ResponseWriter, r *http.Request) {
		f.auth(w, r)
		if r.Method != http.MethodDelete {
			http.Error(w, "bogus", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/zones/zone1/dns_records/rec-")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.deleted = append(f.deleted, name)
		delete(f.records, name)
		f.writeLocked(w, map[string]any{"success": true, "result": map[string]any{"id": "rec-" + name}})
	})
	return mux
}

func (f *fakeCloudflare) auth(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+f.token {
		f.t.Errorf("Authorization = %q, want the bearer token", got)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

func (f *fakeCloudflare) write(w http.ResponseWriter, body map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeLocked(w, body)
}

func (f *fakeCloudflare) writeLocked(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

func TestCloudflarePutTXT(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]string{
		// A stale challenge value from an earlier attempt.
		"_acme-challenge.example.com": "old-token",
	}, token: "cf-token", t: t}
	hs := httptest.NewServer(fake.handler())
	defer hs.Close()

	provider, err := NewCloudflare("example.com", "cf-token")
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}
	provider.BaseURL = hs.URL

	if err := provider.PutTXT(context.Background(), "_acme-challenge.example.com", "new-token"); err != nil {
		t.Fatalf("PutTXT: %v", err)
	}

	if got := fake.records["_acme-challenge.example.com"]; got != "new-token" {
		t.Errorf("record content = %q, want new-token", got)
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != "_acme-challenge.example.com" {
		t.Errorf("deleted = %v, want the stale record", fake.deleted)
	}
	if len(fake.created) != 1 {
		t.Fatalf("created = %v, want one record", fake.created)
	}
	created := fake.created[0]
	if created["type"] != "TXT" || created["name"] != "_acme-challenge.example.com" ||
		created["content"] != "new-token" || created["ttl"] != float64(60) {
		t.Errorf("created record = %v", created)
	}
}

func TestCloudflareDeleteTXT(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]string{
		"_acme-challenge.example.com": "token",
	}, token: "cf-token", t: t}
	hs := httptest.NewServer(fake.handler())
	defer hs.Close()

	provider, err := NewCloudflare("example.com", "cf-token")
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}
	provider.BaseURL = hs.URL

	if err := provider.DeleteTXT(context.Background(), "_acme-challenge.example.com"); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if _, ok := fake.records["_acme-challenge.example.com"]; ok {
		t.Error("record was not deleted")
	}

	// Deleting a missing record is not an error.
	if err := provider.DeleteTXT(context.Background(), "_acme-challenge.example.com"); err != nil {
		t.Fatalf("second DeleteTXT: %v", err)
	}
}

func TestCloudflareAPIError(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"bad token"}],"result":null}`)
	}))
	defer hs.Close()

	provider, err := NewCloudflare("example.com", "cf-token")
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}
	provider.BaseURL = hs.URL

	err = provider.PutTXT(context.Background(), "_acme-challenge.example.com", "token")
	if err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("PutTXT error = %v, want the API error", err)
	}
}

func TestNewCloudflareValidation(t *testing.T) {
	if _, err := NewCloudflare("", "token"); err == nil {
		t.Error("empty zone accepted")
	}
	if _, err := NewCloudflare("example.com", ""); err != ErrMissingToken {
		t.Errorf("empty token error = %v, want ErrMissingToken", err)
	}
	provider, err := NewCloudflare("example.com.", "token")
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}
	if provider.Zone != "example.com" {
		t.Errorf("zone = %q, want the trailing dot trimmed", provider.Zone)
	}
}

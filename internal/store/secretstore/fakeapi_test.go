// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstore_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
)

// fakeAPI is an httptest.Server implementing the Secret subset of the
// Kubernetes API with real optimistic concurrency: every write assigns a new
// resourceVersion, and an update carrying anything but the current one is
// rejected with a 409. Without that the concurrency tests would prove nothing.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server
	ns  string

	mu      sync.Mutex
	objects map[string]*fakeSecret
	rv      int
	// counters, read only after the exercise finishes.
	gets, creates, updates, conflicts int
	// hooks, set before the exercise starts.
	beforeWrite func()
	failEvery   func(method string) (code int, reason, message string, ok bool)
}

type fakeSecret struct {
	rv          int
	data        map[string][]byte
	labels      map[string]string
	annotations map[string]string
}

type wireSecret struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   wireMeta          `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
}

type wireMeta struct {
	Name            string            `json:"name,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

type wireStatus struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// newFakeAPI starts a fake API server and returns it with a kube.Client
// pointed at it.
func newFakeAPI(t *testing.T) (*fakeAPI, *kube.Client) {
	t.Helper()
	f := &fakeAPI{t: t, ns: "monitoring", objects: map[string]*fakeSecret{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	c, err := kube.New(kube.Config{
		APIServerURL: f.srv.URL,
		Namespace:    f.ns,
		HTTPClient:   f.srv.Client(),
	})
	if err != nil {
		t.Fatalf("kube.New: %v", err)
	}
	return f, c
}

// seed installs a Secret without going through the API, for tests that need
// one to already exist.
func (f *fakeAPI) seed(name string, data map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	f.objects[name] = &fakeSecret{rv: f.rv, data: maps.Clone(data)}
}

// get returns a copy of a stored Secret's data.
func (f *fakeAPI) get(name string) (map[string][]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		return nil, false
	}
	return maps.Clone(obj.data), true
}

// counts returns the request counters.
func (f *fakeAPI) counts() (gets, creates, updates, conflicts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.creates, f.updates, f.conflicts
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	prefix := "/api/v1/namespaces/" + f.ns + "/secrets"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		f.status(w, http.StatusNotFound, "NotFound", "unexpected path "+r.URL.Path)
		return
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")

	if f.failEvery != nil {
		if code, reason, message, ok := f.failEvery(r.Method); ok {
			f.status(w, code, reason, message)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		f.handleGet(w, name)
	case http.MethodPost:
		f.handleCreate(w, r)
	case http.MethodPut:
		f.handleUpdate(w, r, name)
	default:
		f.status(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (f *fakeAPI) handleGet(w http.ResponseWriter, name string) {
	f.mu.Lock()
	f.gets++
	obj, ok := f.objects[name]
	var out *wireSecret
	if ok {
		out = f.render(name, obj)
	}
	f.mu.Unlock()
	if !ok {
		f.status(w, http.StatusNotFound, "NotFound", `secrets "`+name+`" not found`)
		return
	}
	f.write(w, http.StatusOK, out)
}

func (f *fakeAPI) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in wireSecret
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		f.status(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if f.beforeWrite != nil {
		f.beforeWrite()
	}
	f.mu.Lock()
	f.creates++
	if _, exists := f.objects[in.Metadata.Name]; exists {
		f.mu.Unlock()
		f.status(w, http.StatusConflict, "AlreadyExists", `secrets "`+in.Metadata.Name+`" already exists`)
		return
	}
	f.rv++
	obj := &fakeSecret{rv: f.rv, data: maps.Clone(in.Data), labels: maps.Clone(in.Metadata.Labels), annotations: maps.Clone(in.Metadata.Annotations)}
	f.objects[in.Metadata.Name] = obj
	out := f.render(in.Metadata.Name, obj)
	f.mu.Unlock()
	f.write(w, http.StatusCreated, out)
}

func (f *fakeAPI) handleUpdate(w http.ResponseWriter, r *http.Request, name string) {
	var in wireSecret
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		f.status(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if f.beforeWrite != nil {
		f.beforeWrite()
	}
	f.mu.Lock()
	f.updates++
	obj, ok := f.objects[name]
	if !ok {
		f.mu.Unlock()
		f.status(w, http.StatusNotFound, "NotFound", `secrets "`+name+`" not found`)
		return
	}
	if in.Metadata.ResourceVersion != strconv.Itoa(obj.rv) {
		f.conflicts++
		f.mu.Unlock()
		f.status(w, http.StatusConflict, "Conflict",
			`Operation cannot be fulfilled on secrets "`+name+`": the object has been modified; please apply your changes to the latest version and try again`)
		return
	}
	f.rv++
	obj.rv = f.rv
	obj.data = maps.Clone(in.Data)
	obj.labels = maps.Clone(in.Metadata.Labels)
	obj.annotations = maps.Clone(in.Metadata.Annotations)
	out := f.render(name, obj)
	f.mu.Unlock()
	f.write(w, http.StatusOK, out)
}

// render builds the wire form of a stored object. The caller holds the lock.
func (f *fakeAPI) render(name string, obj *fakeSecret) *wireSecret {
	return &wireSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: wireMeta{
			Name:            name,
			Namespace:       f.ns,
			ResourceVersion: strconv.Itoa(obj.rv),
			Labels:          maps.Clone(obj.labels),
			Annotations:     maps.Clone(obj.annotations),
		},
		Type: "Opaque",
		Data: maps.Clone(obj.data),
	}
}

func (f *fakeAPI) write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("fake api: encode response: %v", err)
	}
}

func (f *fakeAPI) status(w http.ResponseWriter, code int, reason, message string) {
	f.write(w, code, wireStatus{Kind: "Status", Code: code, Reason: reason, Message: message})
}

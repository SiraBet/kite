package agent

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnrollRetriesAConnectionThatDropsAndNotARefusal(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 { // drop the first connection without answering
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	resp, err := postWithRetry(srv.Client(), srv.URL, []byte("{}"), 3, time.Millisecond)
	if err != nil || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	resp.Body.Close()

	calls = 0
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, `{"detail":"token used"}`, http.StatusBadRequest)
	}))
	defer refusing.Close()
	resp, err = postWithRetry(refusing.Client(), refusing.URL, []byte("{}"), 3, time.Millisecond)
	if err != nil || calls != 1 {
		t.Fatalf("a refusal was retried: err=%v calls=%d", err, calls)
	}
	resp.Body.Close()
}

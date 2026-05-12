package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeKeepAliveSender struct {
	mu        sync.Mutex
	requests  []keepAliveRequest
	done      chan struct{}
	closeOnce sync.Once
}

type keepAliveRequest struct {
	name      string
	wantReply bool
}

func newFakeKeepAliveSender() *fakeKeepAliveSender {
	return &fakeKeepAliveSender{done: make(chan struct{})}
}

func (f *fakeKeepAliveSender) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	f.mu.Lock()
	f.requests = append(f.requests, keepAliveRequest{name: name, wantReply: wantReply})
	f.mu.Unlock()

	f.closeOnce.Do(func() { close(f.done) })
	return false, nil, fmt.Errorf("stop test keepalive")
}

func (f *fakeKeepAliveSender) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeKeepAliveSender) firstRequest() keepAliveRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return keepAliveRequest{}
	}
	return f.requests[0]
}

func TestStartSSHKeepAliveSendsOpenSSHKeepAlive(t *testing.T) {
	f := newFakeKeepAliveSender()

	startSSHKeepAlive(f, time.Millisecond)

	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for keepalive request")
	}

	req := f.firstRequest()
	if req.name != "keepalive@openssh.com" {
		t.Fatalf("keepalive request name = %q, want keepalive@openssh.com", req.name)
	}
	if req.wantReply {
		t.Fatal("keepalive request should not require a reply")
	}
}

func TestStartSSHKeepAliveDisabled(t *testing.T) {
	f := newFakeKeepAliveSender()

	startSSHKeepAlive(f, 0)

	select {
	case <-f.done:
		t.Fatal("keepalive should not run when interval is disabled")
	case <-time.After(10 * time.Millisecond):
	}
	if got := f.requestCount(); got != 0 {
		t.Fatalf("keepalive request count = %d, want 0", got)
	}
}

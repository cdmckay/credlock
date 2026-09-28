package daemon

import (
	"context"
	"testing"

	"github.com/cdmckay/credlock/internal/approve"
	"github.com/cdmckay/credlock/internal/proto"
)

type silentApprover struct{}

func (silentApprover) Approve(context.Context, approve.Request) (bool, error) {
	return false, approve.ErrTimedOut
}

func TestAnUnansweredDialogIsADenialThatSaysSo(t *testing.T) {
	h := newHarness(t, true, func(s *Server) { s.Approver = silentApprover{} })
	resp, err := h.resolve(proto.Secret{Name: "A", Ref: "op://v/a/f"})
	if err != nil || !resp.Denied || !resp.TimedOut || resp.Values != nil {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if len(h.provider.fetches()) != 0 {
		t.Fatal("fetched a secret nobody approved")
	}
}

package executor

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
)

// The upstream's Daybreak refusal must stay recognisable after the websocket
// parser rebuilds its payload, or the model is cooled down for hours.
func TestParseCodexWebsocketErrorKeepsAccessProgramRejection(t *testing.T) {
	const msg = "Daybreak isn't available for this model. Turn off Daybreak or choose another model."
	for _, payload := range []string{
		`{"type":"error","status":404,"detail":"` + msg + `"}`,
		`{"type":"error","status":404,"body":{"detail":"` + msg + `"}}`,
		`{"type":"error","status":404,"error":{"detail":"` + msg + `"}}`,
		`{"type":"error","status":404,"error":{"message":"` + msg + `"}}`,
		`{"type":"error","status":404,"error":"` + msg + `"}`,
	} {
		err, ok := parseCodexWebsocketError([]byte(payload))
		if !ok {
			t.Fatalf("expected websocket error for %s", payload)
		}
		if !clienterror.IsRequestFault(0, err) {
			t.Errorf("IsRequestFault = false for %s; parsed=%s", payload, err.Error())
		}
	}
}

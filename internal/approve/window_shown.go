//go:build darwin || (linux && gtk)

package approve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// parseView reads the helper's View for the window process, refusing one that
// asks nothing, so the window sees only the fields credlock defines.
func parseView(r io.Reader) (View, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return View{}, err
	}
	var v View
	if err := json.Unmarshal(data, &v); err != nil {
		return View{}, fmt.Errorf("reading the approval window's content: %w", err)
	}
	asks := len(v.Secrets) > 0 || v.Kind == "pair" || (v.Kind == "search" && v.Search != "")
	if !asks || v.Timeout <= 0 {
		return View{}, errors.New("the approval window was started without secrets, a search or a timeout")
	}
	return v, nil
}

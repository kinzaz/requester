package requester

import (
	"fmt"
	"io"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/kinzaz/helpers/slices"
)

type ApifyUA struct {
	UserAgent        string `json:"userAgent,omitempty"`
	SoftwareNameCode string `json:"softwareNameCode,omitempty"`
	TimeSeen         int    `json:"timeSeen,omitempty"`
	SoftwareVersion  int    `json:"softwareVersion,omitempty"`
	HardwareType     string `json:"hardwareType,omitempty"`
}

func (r *Requester) LoadUAs() ([]*ApifyUA, error) {
	resp, err := http.Get("https://api.apify.com/v2/key-value-stores/z1V7YjyftOYIqNsww/records/USER-AGENTS?disableRedirect=true")
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	var uas []*ApifyUA
	err = jsoniter.Unmarshal(b, &uas)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	uas = slices.Filter(uas, func(_ int, ua *ApifyUA) bool {
		return ua.TimeSeen >= 1000
	})

	return uas, nil
}

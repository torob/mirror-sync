package logging

import (
	"bytes"
	"strings"
	"testing"

	"github.com/torob/mirror-sync/internal/config"
)

func TestNewDefaultsToInfoTextWithUTCTime(t *testing.T) {
	var out bytes.Buffer
	logger := New(config.Logging{}, &out)
	logger.Debug("hidden")
	logger.Info("ready", "repository", "apt/ubuntu")

	got := out.String()
	if strings.Contains(got, "hidden") {
		t.Fatalf("default logger emitted debug record: %s", got)
	}
	for _, want := range []string{"time=", "Z level=INFO", "msg=ready", "repository=apt/ubuntu"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log output %q does not contain %q", got, want)
		}
	}
}

func TestNewHonorsConfiguredLevels(t *testing.T) {
	for _, tc := range []struct {
		level   string
		visible bool
	}{
		{level: "debug", visible: true},
		{level: "warn", visible: false},
		{level: "error", visible: false},
		{level: "off", visible: false},
	} {
		t.Run(tc.level, func(t *testing.T) {
			var out bytes.Buffer
			logger := New(config.Logging{Level: tc.level}, &out)
			logger.Info("info record")
			if got := strings.Contains(out.String(), "info record"); got != tc.visible {
				t.Fatalf("info visibility for %s = %t, want %t; output %q", tc.level, got, tc.visible, out.String())
			}
		})
	}
}

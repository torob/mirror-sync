package logging

import (
	"io"
	"log/slog"
	"time"

	"github.com/torob/mirror-sync/internal/config"
)

const disabledLevel = slog.Level(100)

func New(cfg config.Logging, out io.Writer) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "off":
		level = disabledLevel
	}
	handler := slog.NewTextHandler(out, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) == 0 && attr.Key == slog.TimeKey {
				attr.Value = slog.StringValue(attr.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return attr
		},
	})
	return slog.New(handler)
}

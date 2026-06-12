package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/torob/mirror-sync/internal/config"
)

type Schedule interface {
	Next(time.Time) time.Time
}

func New(cfg config.Schedule) (Schedule, error) {
	if cfg.Interval != "" {
		d, err := time.ParseDuration(cfg.Interval)
		if err != nil {
			return nil, err
		}
		if d <= 0 {
			return nil, fmt.Errorf("interval must be positive")
		}
		return intervalSchedule{d: d}, nil
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return nil, err
	}
	expr, err := parseCron(cfg.Cron)
	if err != nil {
		return nil, err
	}
	return cronSchedule{expr: expr, loc: loc}, nil
}

type intervalSchedule struct{ d time.Duration }

func (s intervalSchedule) Next(t time.Time) time.Time { return t.Add(s.d) }

type cronSchedule struct {
	expr cronExpr
	loc  *time.Location
}

func (s cronSchedule) Next(t time.Time) time.Time {
	local := t.In(s.loc).Add(time.Minute).Truncate(time.Minute)
	for i := 0; i < 366*24*60; i++ {
		if s.expr.matches(local) {
			return local
		}
		local = local.Add(time.Minute)
	}
	return t.Add(24 * time.Hour)
}

type cronExpr struct {
	min, hour, dom, month, dow map[int]bool
	domAny, dowAny             bool
}

func parseCron(s string) (cronExpr, error) {
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return cronExpr{}, fmt.Errorf("cron must have five fields")
	}
	min, err := parseField(fields[0], 0, 59, false)
	if err != nil {
		return cronExpr{}, err
	}
	hour, err := parseField(fields[1], 0, 23, false)
	if err != nil {
		return cronExpr{}, err
	}
	dom, err := parseField(fields[2], 1, 31, false)
	if err != nil {
		return cronExpr{}, err
	}
	month, err := parseField(fields[3], 1, 12, false)
	if err != nil {
		return cronExpr{}, err
	}
	dow, err := parseField(fields[4], 0, 7, true)
	if err != nil {
		return cronExpr{}, err
	}
	return cronExpr{min: min, hour: hour, dom: dom, month: month, dow: dow, domAny: fields[2] == "*", dowAny: fields[4] == "*"}, nil
}

func parseField(field string, min, max int, sunday7 bool) (map[int]bool, error) {
	out := map[int]bool{}
	if field == "*" {
		for i := min; i <= max; i++ {
			if sunday7 && i == 7 {
				out[0] = true
			} else {
				out[i] = true
			}
		}
		return out, nil
	}
	for _, part := range strings.Split(field, ",") {
		step := 1
		base := part
		if b, st, ok := strings.Cut(part, "/"); ok {
			base = b
			n, err := strconv.Atoi(st)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid cron step %q", part)
			}
			step = n
		}
		start, end := min, max
		if base != "*" {
			if a, b, ok := strings.Cut(base, "-"); ok {
				var err error
				start, err = strconv.Atoi(a)
				if err != nil {
					return nil, err
				}
				end, err = strconv.Atoi(b)
				if err != nil {
					return nil, err
				}
			} else {
				n, err := strconv.Atoi(base)
				if err != nil {
					return nil, err
				}
				start, end = n, n
			}
		}
		if start < min || end > max || start > end {
			return nil, fmt.Errorf("cron value %q out of range", part)
		}
		for i := start; i <= end; i += step {
			if sunday7 && i == 7 {
				out[0] = true
			} else {
				out[i] = true
			}
		}
	}
	return out, nil
}

func (e cronExpr) matches(t time.Time) bool {
	dow := int(t.Weekday())
	domMatch := e.dom[t.Day()]
	dowMatch := e.dow[dow]
	dayMatch := false
	switch {
	case e.domAny && e.dowAny:
		dayMatch = true
	case e.domAny:
		dayMatch = dowMatch
	case e.dowAny:
		dayMatch = domMatch
	default:
		dayMatch = domMatch || dowMatch
	}
	return e.min[t.Minute()] && e.hour[t.Hour()] && e.month[int(t.Month())] && dayMatch
}

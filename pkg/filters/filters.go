package filters

import (
	"regexp"
	"strings"

	t "github.com/containrrr/watchtower/pkg/types"
	log "github.com/sirupsen/logrus"
)

// WatchtowerContainersFilter filters only watchtower containers
func WatchtowerContainersFilter(c t.FilterableContainer) bool { return c.IsWatchtower() }

// NoFilter will not filter out any containers
func NoFilter(t.FilterableContainer) bool { return true }

// FilterByNames returns all containers that match one of the specified names
func FilterByNames(names []string, baseFilter t.Filter) t.Filter {
	if len(names) == 0 {
		return baseFilter
	}

	return func(c t.FilterableContainer) bool {
		for _, name := range names {
			if name == c.Name() || name == c.Name()[1:] {
				return baseFilter(c)
			}

			if re, err := regexp.Compile(name); err == nil {
				indices := re.FindStringIndex(c.Name())
				if indices == nil {
					continue
				}
				start := indices[0]
				end := indices[1]
				if start <= 1 && end >= len(c.Name())-1 {
					return baseFilter(c)
				}
			}
		}
		return false
	}
}

// FilterByDisableNames returns all containers that don't match any of the specified names
func FilterByDisableNames(disableNames []string, baseFilter t.Filter) t.Filter {
	if len(disableNames) == 0 {
		return baseFilter
	}

	return func(c t.FilterableContainer) bool {
		for _, name := range disableNames {
			if name == c.Name() || name == c.Name()[1:] {
				return false
			}
		}
		return baseFilter(c)
	}
}

// FilterByEnableLabel returns all containers that have the enabled label set
func FilterByEnableLabel(baseFilter t.Filter) t.Filter {
	return func(c t.FilterableContainer) bool {
		// If label filtering is enabled, containers should only be considered
		// if the label is specifically set.
		_, ok := c.Enabled()
		if !ok {
			return false
		}

		return baseFilter(c)
	}
}

// FilterByDisabledLabel returns all containers that have the enabled label set to disable
func FilterByDisabledLabel(baseFilter t.Filter) t.Filter {
	return func(c t.FilterableContainer) bool {
		enabledLabel, ok := c.Enabled()
		if ok && !enabledLabel {
			// If the label has been set and it demands a disable
			return false
		}

		return baseFilter(c)
	}
}

// FilterByScope returns all containers that belongs to a specific scope
func FilterByScope(scope string, baseFilter t.Filter) t.Filter {
	return func(c t.FilterableContainer) bool {
		containerScope, containerHasScope := c.Scope()

		if !containerHasScope || containerScope == "" {
			containerScope = "none"
		}

		if containerScope == scope {
			return baseFilter(c)
		}

		return false
	}
}

// ResolveSchedule determines the effective cron schedule spec for a container.
//
// Precedence (most specific wins):
//  1. the inline .schedule label (raw cron expression)
//  2. the .schedule-name label, resolved against the named schedules map
//  3. the global schedule spec (fallback)
//
// The returned isOverride is true when the container defines its own schedule
// (either inline or named) that differs from the global spec. When a container
// sets both the inline and the named label, the inline value wins and a warning
// is logged. When a .schedule-name references a name that is not declared in
// named, the container falls back to the global spec and isOverride is false.
func ResolveSchedule(c t.FilterableContainer, named map[string]string, globalSpec string) (spec string, isOverride bool) {
	inline, hasInline := c.Schedule()
	name, hasName := c.ScheduleName()

	if hasInline && inline != "" {
		if hasName && name != "" {
			log.WithField("container", c.Name()).
				Warnf("Container defines both a schedule and a schedule-name label; using the inline schedule %q and ignoring schedule-name %q", inline, name)
		}
		return inline, true
	}

	if hasName && name != "" {
		if resolved, ok := named[name]; ok {
			return resolved, true
		}
		// Unknown named schedule: CheckForSanity rejects this at startup, but be
		// defensive at runtime and fall back to the global schedule.
		log.WithField("container", c.Name()).
			Warnf("Container references unknown schedule-name %q; falling back to the global schedule", name)
		return globalSpec, false
	}

	return globalSpec, false
}

// FilterBySchedule returns a filter matching containers whose effective
// schedule (resolved via ResolveSchedule) equals targetSpec. It is used to
// build a dedicated cron entry per distinct schedule.
func FilterBySchedule(targetSpec string, named map[string]string, globalSpec string, baseFilter t.Filter) t.Filter {
	return func(c t.FilterableContainer) bool {
		spec, _ := ResolveSchedule(c, named, globalSpec)
		if spec == targetSpec {
			return baseFilter(c)
		}
		return false
	}
}

// FilterByGlobalSchedule returns a filter matching only containers that run on
// the global schedule, i.e. that do not define a recognized per-container
// override. Containers whose override resolves to the global spec (because of
// an unknown schedule-name) are folded into the global entry as well.
func FilterByGlobalSchedule(named map[string]string, globalSpec string, baseFilter t.Filter) t.Filter {
	return func(c t.FilterableContainer) bool {
		spec, isOverride := ResolveSchedule(c, named, globalSpec)
		if !isOverride || spec == globalSpec {
			return baseFilter(c)
		}
		return false
	}
}

// FilterByImage returns all containers that have a specific image
func FilterByImage(images []string, baseFilter t.Filter) t.Filter {
	if images == nil {
		return baseFilter
	}

	return func(c t.FilterableContainer) bool {
		image := strings.Split(c.ImageName(), ":")[0]
		for _, targetImage := range images {
			if image == targetImage {
				return baseFilter(c)
			}
		}

		return false
	}
}

// BuildFilter creates the needed filter of containers
func BuildFilter(names []string, disableNames []string, enableLabel bool, scope string) (t.Filter, string) {
	sb := strings.Builder{}
	filter := NoFilter
	filter = FilterByNames(names, filter)
	filter = FilterByDisableNames(disableNames, filter)

	if len(names) > 0 {
		sb.WriteString("which name matches \"")
		for i, n := range names {
			sb.WriteString(n)
			if i < len(names)-1 {
				sb.WriteString(`" or "`)
			}
		}
		sb.WriteString(`", `)
	}
	if len(disableNames) > 0 {
		sb.WriteString("not named one of \"")
		for i, n := range disableNames {
			sb.WriteString(n)
			if i < len(disableNames)-1 {
				sb.WriteString(`" or "`)
			}
		}
		sb.WriteString(`", `)
	}

	if enableLabel {
		// If label filtering is enabled, containers should only be considered
		// if the label is specifically set.
		filter = FilterByEnableLabel(filter)
		sb.WriteString("using enable label, ")
	}

	if scope == "none" {
		// If a scope has explicitly defined as "none", containers should only be considered
		// if they do not have a scope defined, or if it's explicitly set to "none".
		filter = FilterByScope(scope, filter)
		sb.WriteString(`without a scope, "`)
	} else if scope != "" {
		// If a scope has been defined, containers should only be considered
		// if the scope is specifically set.
		filter = FilterByScope(scope, filter)
		sb.WriteString(`in scope "`)
		sb.WriteString(scope)
		sb.WriteString(`", `)
	}
	filter = FilterByDisabledLabel(filter)

	filterDesc := "Checking all containers (except explicitly disabled with label)"
	if sb.Len() > 0 {
		filterDesc = "Only checking containers " + sb.String()

		// Remove the last ", "
		filterDesc = filterDesc[:len(filterDesc)-2]
	}

	return filter, filterDesc
}

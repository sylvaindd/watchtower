package actions

import (
	"fmt"
	"sort"
	"time"

	"github.com/containrrr/watchtower/pkg/container"
	"github.com/containrrr/watchtower/pkg/filters"
	"github.com/containrrr/watchtower/pkg/sorter"
	"github.com/containrrr/watchtower/pkg/types"

	"github.com/robfig/cron"
	log "github.com/sirupsen/logrus"
)

// CheckForSanity makes sure everything is sane before starting
func CheckForSanity(client container.Client, filter types.Filter, rollingRestarts bool) error {
	log.Debug("Making sure everything is sane before starting")

	if rollingRestarts {
		containers, err := client.ListContainers(filter)
		if err != nil {
			return err
		}
		for _, c := range containers {
			if len(c.Links()) > 0 {
				return fmt.Errorf(
					"%q is depending on at least one other container. This is not compatible with rolling restarts",
					c.Name(),
				)
			}
		}
	}
	return nil
}

// CheckSchedules validates the named schedules and the per-container schedule
// labels before starting. It returns an error if:
//   - a declared named schedule has an invalid cron expression, or
//   - a container's inline .schedule label has an invalid cron expression, or
//   - a container's .schedule-name label references a name that is not declared
//     in the named schedules.
//
// named maps lowercased schedule names to their cron specs (as produced by
// flags.GetNamedSchedules).
func CheckSchedules(client container.Client, filter types.Filter, named map[string]string) error {
	for name, spec := range named {
		if _, err := cron.Parse(spec); err != nil {
			return fmt.Errorf("named schedule %q has an invalid cron expression %q: %w", name, spec, err)
		}
	}

	containers, err := client.ListContainers(filter)
	if err != nil {
		return err
	}

	for _, c := range containers {
		if inline, ok := c.Schedule(); ok && inline != "" {
			if _, err := cron.Parse(inline); err != nil {
				return fmt.Errorf(
					"container %q has an invalid schedule label %q: %w",
					c.Name(), inline, err,
				)
			}
			// Inline schedule takes precedence; no need to validate the name.
			continue
		}

		if scheduleName, ok := c.ScheduleName(); ok && scheduleName != "" {
			if _, declared := named[scheduleName]; !declared {
				return fmt.Errorf(
					"container %q references undeclared schedule-name %q (declare it via WATCHTOWER_SCHEDULE_NAMED_%s)",
					c.Name(), scheduleName, scheduleName,
				)
			}
		}
	}

	return nil
}

// CheckForMultipleWatchtowerInstances will ensure that there are not multiple instances of the
// watchtower running simultaneously. If multiple watchtower containers are detected, this function
// will stop and remove all but the most recently started container. This behaviour can be bypassed
// if a scope UID is defined.
func CheckForMultipleWatchtowerInstances(client container.Client, cleanup bool, scope string) error {
	filter := filters.WatchtowerContainersFilter
	if scope != "" {
		filter = filters.FilterByScope(scope, filter)
	}
	containers, err := client.ListContainers(filter)

	if err != nil {
		return err
	}

	if len(containers) <= 1 {
		log.Debug("There are no additional watchtower containers")
		return nil
	}

	log.Info("Found multiple running watchtower instances. Cleaning up.")
	return cleanupExcessWatchtowers(containers, client, cleanup)
}

func cleanupExcessWatchtowers(containers []types.Container, client container.Client, cleanup bool) error {
	var stopErrors int

	sort.Sort(sorter.ByCreated(containers))
	allContainersExceptLast := containers[0 : len(containers)-1]

	for _, c := range allContainersExceptLast {
		if err := client.StopContainer(c, 10*time.Minute); err != nil {
			// logging the original here as we're just returning a count
			log.WithError(err).Error("Could not stop a previous watchtower instance.")
			stopErrors++
			continue
		}

		if cleanup {
			if err := client.RemoveImageByID(c.ImageID()); err != nil {
				log.WithError(err).Warning("Could not cleanup watchtower images, possibly because of other watchtowers instances in other scopes.")
			}
		}
	}

	if stopErrors > 0 {
		return fmt.Errorf("%d errors while stopping watchtower containers", stopErrors)
	}

	return nil
}

// Discovery orchestrator: runs configured sources, scope-filters every
// endpoint, and attaches relative-base resolution for specs that lack
// absolute servers.
package discovery

import (
	"context"
	"strings"

	"github.com/Lutfifakee-Project/owntrace/internal/config"
	"github.com/Lutfifakee-Project/owntrace/internal/endpoints"
	"github.com/Lutfifakee-Project/owntrace/internal/httpclient"
	"github.com/Lutfifakee-Project/owntrace/internal/logger"
	"github.com/Lutfifakee-Project/owntrace/internal/scope"
)

// Run executes discovery according to configuration.
func Run(ctx context.Context, cfg *config.Config, client *httpclient.Client, sc *scope.Checker, log *logger.Logger) (*Result, error) {
	res := NewResult()

	for _, src := range cfg.Discovery.Sources {
		switch src {
		case "url":
			for _, seed := range cfg.Discovery.Seeds {
				if d := sc.Check("GET", seed); !d.Allowed {
					res.Note("seed %s rejected: %s", seed, d.Reason)
					continue
				}
				if ep, ok := BuildFromURL("GET", seed, endpoints.SourceURL, "config:seeds"); ok {
					res.Endpoints.Add(ep)
				}
			}
		case "har":
			for _, f := range cfg.Discovery.HARFiles {
				if err := ParseHAR(f, cfg.Auth.HARProfileHeader, res); err != nil {
					res.Note("HAR import %s failed: %v", f, err)
				}
			}
		case "openapi":
			for _, f := range cfg.Discovery.OpenAPIFiles {
				if err := ParseOpenAPI(f, res); err != nil {
					res.Note("OpenAPI import %s failed: %v", f, err)
				}
			}
		case "crawl":
			if len(cfg.Discovery.CrawlSeeds) == 0 {
				res.Note("crawl source enabled but no crawl_seeds configured")
				continue
			}
			Crawl(ctx, client, sc, cfg.Discovery.CrawlSeeds, cfg.Scope.MaxCrawlDepth, cfg.Scope.MaxCrawlPages, log, res)
		default:
			res.Note("unknown discovery source %q ignored", src)
		}
	}

	// Resolve spec-relative hosts against configured targets when needed.
	resolveRelativeHosts(res, sc)

	// Final scope filter + auth requirement application from scope methods.
	kept := endpoints.NewSet()
	for _, ep := range res.Endpoints.List() {
		if d := sc.Check(ep.Method, ep.URL()); !d.Allowed {
			log.Debugf("discovery filtered out %s %s: %s", ep.Method, ep.URL(), d.Reason)
			continue
		}
		kept.Add(ep)
	}
	res.Endpoints = kept
	return res, nil
}

// resolveRelativeHosts fixes endpoints discovered with no concrete host by
// mapping them onto the single configured target, when unambiguous.
func resolveRelativeHosts(res *Result, sc *scope.Checker) {
	fixed := endpoints.NewSet()
	for _, ep := range res.Endpoints.List() {
		if ep.Host != "" && strings.Contains(ep.Host, "://") {
			fixed.Add(ep)
			continue
		}
		targets := sc.Targets()
		if len(targets) != 1 {
			res.Note("endpoint %s %s has no resolvable host; skipped", ep.Method, ep.Path)
			continue
		}
		ep.Host = "http://" + targets[0]
		fixed.Add(ep)
	}
	res.Endpoints = fixed
}

// Targeted repair for dangling edges left behind when a referenced cve or
// purl document is missing.
//
// This does not run a general integrity check. It only scans for the exact
// subset of edges currently pointing at a missing document, fixes just
// those, and is safe to run every time this job runs: once a document has
// been recreated, the detection query that feeds each repair pass simply
// won't find it anymore, so a run where nothing is broken does no extra
// work beyond the two (cheap, streamed) detection scans.
//
// Both repairs reuse the exact same functions the normal import path uses
// (processEdges, newVuln) -- no duplicated PURL/CVSS logic anywhere.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/ortelius/v12/util"
)

const (
	// repairBatchSize keeps each network round-trip small while scanning
	// for dangling edges, instead of pulling a whole edge collection's
	// worth of rows into memory in one go.
	repairBatchSize = 500

	// repairQueryTimeout bounds how long any single detection scan is
	// allowed to run, so a run can't hang forever.
	repairQueryTimeout = 5 * time.Minute

	// envRepairEnabled is a full kill switch. Set to "false" to skip
	// repair for this run (e.g. while the server is already under memory
	// pressure and you don't want any extra load).
	envRepairEnabled = "ARANGO_REPAIR_ENABLED"

	// envRepairQueryMemoryLimitMB overrides defaultRepairQueryMemoryLimitMB.
	envRepairQueryMemoryLimitMB = "ARANGO_REPAIR_QUERY_MEMORY_LIMIT_MB"

	// defaultRepairQueryMemoryLimitMB caps the memory a single detection
	// scan is allowed to use on the server, as a safety net for
	// memory-constrained deployments. Set envRepairQueryMemoryLimitMB to
	// "0" to remove the cap.
	defaultRepairQueryMemoryLimitMB = 512
)

// RunRepair scans only for the currently-dangling subset of cve2purl and
// release2cve edges and attempts to recreate whatever document each is
// missing. Meant to be called once per job run, after LoadFromOSVDev.
func RunRepair() {
	if os.Getenv(envRepairEnabled) == "false" {
		logger.Sugar().Infof("Dangling-edge repair disabled via %s=false", envRepairEnabled)
		return
	}

	ctx := context.Background()

	logger.Sugar().Infoln("Starting targeted repair of dangling edges (cve2purl, release2cve)...")
	start := time.Now()

	purlRepaired, purlAttempted, purlErr := RepairCVE2Purl(ctx)
	if purlErr != nil {
		logger.Sugar().Errorf("repair: cve2purl pass failed: %v", purlErr)
	}

	cveRepaired, cveUnrepairable, cveErr := RepairRelease2CVE(ctx)
	if cveErr != nil {
		logger.Sugar().Errorf("repair: release2cve pass failed: %v", cveErr)
	}

	elapsed := time.Since(start)
	logger.Sugar().Infof(
		"Dangling-edge repair complete in %s: cve2purl %d/%d purl document(s) recreated | release2cve %d recovered, %d unrecoverable (not on osv.dev)",
		elapsed, purlRepaired, purlAttempted, cveRepaired, cveUnrepairable,
	)
}

func repairQueryMemoryLimitBytes() int64 {
	raw := os.Getenv(envRepairQueryMemoryLimitMB)
	megabytes := defaultRepairQueryMemoryLimitMB
	if raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			megabytes = parsed
		} else {
			logger.Sugar().Warnf("repair: invalid %s=%q, using default of %dMB", envRepairQueryMemoryLimitMB, raw, defaultRepairQueryMemoryLimitMB)
		}
	}
	return int64(megabytes) * 1024 * 1024
}

// ============================================================================
// cve2purl repair: recreate missing purl documents from the still-existing
// source CVE's own affected[] data. Reuses processEdges() unchanged -- it's
// already idempotent (UPSERT for the purl document, existence-check before
// creating an edge), so re-running it against a CVE that's already fully
// processed does nothing extra.
// ============================================================================

// missingEdgeTarget is one distinct missing document referenced by a
// dangling edge, along with the _id of one edge that points at it.
type missingEdgeTarget struct {
	To   string `json:"to"`
	From string `json:"from"`
}

// RepairCVE2Purl finds cve2purl edges whose target purl document no longer
// exists, and for each distinct source CVE involved, re-runs processEdges()
// against that CVE's already-stored content. Only CVEs actually implicated
// in a missing purl target are touched.
func RepairCVE2Purl(ctx context.Context) (repaired, attempted int, err error) {
	targets, err := findMissingCVE2PurlTargets(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("scanning cve2purl for missing purl targets: %w", err)
	}

	attempted = len(targets)
	if attempted == 0 {
		logger.Sugar().Infoln("repair: cve2purl - no dangling edges found, nothing to do")
		return 0, 0, nil
	}

	logger.Sugar().Infof("repair: cve2purl - found %d CVE(s) referencing a missing purl document, repairing...", attempted)

	for _, target := range targets {
		sourceKey := strings.TrimPrefix(target.From, "cve/")

		var content map[string]interface{}
		if _, err := dbconn.Collections["cve"].ReadDocument(ctx, sourceKey, &content); err != nil {
			logger.Sugar().Warnf("repair: cve2purl - could not read source CVE %s for missing purl %s: %v", target.From, target.To, err)
			continue
		}

		if err := processEdges(ctx, content); err != nil {
			logger.Sugar().Warnf("repair: cve2purl - failed reprocessing edges for %s: %v", target.From, err)
			continue
		}

		repaired++
	}

	logger.Sugar().Infof("repair: cve2purl - reprocessed %d/%d CVE(s) referencing a missing purl document", repaired, attempted)
	return repaired, attempted, nil
}

// findMissingCVE2PurlTargets returns, for every distinct purl document that
// a cve2purl edge points at but which no longer exists, the target id and
// the id of one CVE that references it. Streams with a bounded batch size
// and memory cap so scanning a large cve2purl collection can't overrun a
// constrained server.
func findMissingCVE2PurlTargets(ctx context.Context) ([]missingEdgeTarget, error) {
	queryCtx, cancel := context.WithTimeout(ctx, repairQueryTimeout)
	defer cancel()

	const query = `
		FOR e IN cve2purl
			FILTER DOCUMENT(e._to) == null
			COLLECT toID = e._to INTO grp KEEP e
			RETURN { to: toID, from: FIRST(grp).e._from }
	`

	cursor, err := dbconn.Database.Query(queryCtx, query, &arangodb.QueryOptions{
		BatchSize:   repairBatchSize,
		MemoryLimit: repairQueryMemoryLimitBytes(),
		Options: arangodb.QuerySubOptions{
			Stream:     true,
			AllowRetry: true,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var targets []missingEdgeTarget
	for cursor.HasMore() {
		var t missingEdgeTarget
		if _, err := cursor.ReadDocument(queryCtx, &t); err != nil {
			logger.Sugar().Warnf("repair: scan for missing purl targets aborted early after %d result(s): %v", len(targets), err)
			break
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// ============================================================================
// release2cve repair: the CVE document itself is genuinely gone, so this
// half needs osv.dev. Only the specific missing IDs are fetched (one HTTP
// call each), not a whole ecosystem's worth of data. Recreating the CVE
// document via the normal newVuln() path is all that's needed -- the
// existing (currently dangling) release2cve edges already point at the
// right key, so they resolve again automatically once it exists.
// newVuln() also calls processEdges() internally, so this recovers any
// cve2purl edges for the CVE too.
// ============================================================================

// RepairRelease2CVE finds release2cve edges whose target CVE document no
// longer exists, fetches just those specific advisories from osv.dev's
// single-vulnerability API, and reinserts them via the normal newVuln()
// path. IDs no longer published on osv.dev can't be recovered.
func RepairRelease2CVE(ctx context.Context) (repaired, unrepairable int, err error) {
	keys, err := findMissingRelease2CVEKeys(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("scanning release2cve for missing cve targets: %w", err)
	}

	if len(keys) == 0 {
		logger.Sugar().Infoln("repair: release2cve - no dangling edges found, nothing to do")
		return 0, 0, nil
	}

	logger.Sugar().Infof("repair: release2cve - found %d missing CVE document(s), attempting recovery from osv.dev...", len(keys))

	client := &http.Client{Timeout: 30 * time.Second}
	var unrepairableIDs []string

	for _, key := range keys {
		content, found, fetchErr := fetchOSVVulnByID(client, key)
		if fetchErr != nil {
			logger.Sugar().Warnf("repair: release2cve - error fetching %s from osv.dev: %v", key, fetchErr)
			unrepairableIDs = append(unrepairableIDs, key)
			continue
		}
		if !found {
			logger.Sugar().Warnf("repair: release2cve - %s is no longer published on osv.dev, cannot recover", key)
			unrepairableIDs = append(unrepairableIDs, key)
			continue
		}

		id, _ := content["id"].(string)
		if id == "" || util.SanitizeKey(id) != key {
			logger.Sugar().Warnf("repair: release2cve - osv.dev record for %s has an unexpected or missing id, skipping", key)
			unrepairableIDs = append(unrepairableIDs, key)
			continue
		}

		util.AddCVSSScoresToContent(content)

		wasUpdated, insertErr := newVuln(content)
		if insertErr != nil {
			logger.Sugar().Warnf("repair: release2cve - failed to insert recovered CVE %s: %v", key, insertErr)
			unrepairableIDs = append(unrepairableIDs, key)
			continue
		}
		if !wasUpdated {
			logger.Sugar().Warnf("repair: release2cve - recovered record for %s had no affected packages, nothing to recreate", key)
			continue
		}

		repaired++
	}

	unrepairable = len(unrepairableIDs)
	if unrepairable > 0 {
		logger.Sugar().Warnf("repair: release2cve - unrecoverable CVE IDs (not currently on osv.dev, or malformed): %s", strings.Join(unrepairableIDs, ", "))
	}
	logger.Sugar().Infof("repair: release2cve - recovered %d/%d missing CVE document(s)", repaired, len(keys))

	return repaired, unrepairable, nil
}

// findMissingRelease2CVEKeys returns the distinct CVE keys referenced by
// release2cve edges whose target CVE document no longer exists.
func findMissingRelease2CVEKeys(ctx context.Context) ([]string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, repairQueryTimeout)
	defer cancel()

	const query = `
		FOR e IN release2cve
			FILTER DOCUMENT(e._to) == null
			COLLECT toID = e._to
			RETURN toID
	`

	cursor, err := dbconn.Database.Query(queryCtx, query, &arangodb.QueryOptions{
		BatchSize:   repairBatchSize,
		MemoryLimit: repairQueryMemoryLimitBytes(),
		Options: arangodb.QuerySubOptions{
			Stream:     true,
			AllowRetry: true,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var keys []string
	for cursor.HasMore() {
		var docID string
		if _, err := cursor.ReadDocument(queryCtx, &docID); err != nil {
			logger.Sugar().Warnf("repair: scan for missing cve targets aborted early after %d result(s): %v", len(keys), err)
			break
		}
		keys = append(keys, strings.TrimPrefix(docID, "cve/"))
	}
	return keys, nil
}

// fetchOSVVulnByID fetches a single vulnerability record directly from
// osv.dev by its ID. found is false (with a nil error) for a plain 404 --
// i.e. the ID is no longer published, an expected outcome that just means
// this particular document can't be recovered.
func fetchOSVVulnByID(client *http.Client, id string) (content map[string]interface{}, found bool, err error) {
	endpoint := "https://api.osv.dev/v1/vulns/" + url.PathEscape(id)

	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("unexpected status %d from osv.dev", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return nil, false, err
	}

	return content, true, nil
}

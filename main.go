// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
//
// CRITICAL FIXES APPLIED:
// 1. Restored Robust Materialized Edge logic (release2cve) from working snippet
// 2. Fixed cve2purl Hub population to prevent empty collections
// 3. Permanent Fix for Bad Dates using DATE_ISO8601 and DATE_TIMESTAMP
// 4. Maintained Go-side and AQL version validation
// 5. Normalized all outgoing timestamps to RFC3339 strings for AQL compatibility
// 6. BACKEND CONSISTENCY: Matching validation logic with restapi/modules/releases/handlers.go
// 7. IMPROVED FORMATTING: All AQL queries formatted for maximum readability
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/ortelius/v12/database"
	"github.com/ortelius/ortelius/v12/restapi/modules/lifecycle"
	"github.com/ortelius/ortelius/v12/util"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// ============================================================================
// Main Import Logic
// ============================================================================

func LoadFromOSVDev() {
	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
		MaxIdleConns:    100,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(baseURL)
	if err != nil {
		logger.Sugar().Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Fatalln(err)
	}

	lines := strings.Split(string(body), "\n")
	totalCVEsUpdated := 0

	for _, line := range lines {
		platform := strings.TrimSpace(line)
		if len(platform) == 0 {
			continue
		}

		cveCount := processEcosystem(client, platform)
		totalCVEsUpdated += cveCount
	}

	if totalCVEsUpdated > 0 {
		logger.Sugar().Infof("All ecosystems processed. Total CVEs updated: %d. Running lifecycle tracking...", totalCVEsUpdated)
		if err := updateLifecycleForNewCVEs(totalCVEsUpdated); err != nil {
			logger.Sugar().Warnf("Failed to update lifecycle tracking after CVE updates: %v", err)
		} else {
			logger.Sugar().Infof("Lifecycle tracking update complete")
		}
	} else {
		logger.Sugar().Infof("No CVE updates. Skipping lifecycle tracking.")
	}
}

// ============================================================================
// Ecosystem Processing
// ============================================================================

func processEcosystem(client *http.Client, platform string) int {
	lastRunTime, _ := util.GetLastRun(dbconn, platform)
	urlStr := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

	resp, err := client.Get(urlStr)
	if err != nil {
		logger.Sugar().Errorf("Failed to download %s: %v", platform, err)
		return 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Errorf("Failed to read body for %s: %v", platform, err)
		return 0
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logger.Sugar().Errorf("Failed to open zip reader for %s: %v", platform, err)
		return 0
	}

	var maxSeenTime = lastRunTime
	var cveCount int

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || strings.Contains(f.Name, "/") {
			continue
		}

		func() {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			var content map[string]interface{}
			if err := json.NewDecoder(rc).Decode(&content); err != nil {
				return
			}

			modStr, _ := content["modified"].(string)
			if modStr != "" {
				modTime, err := time.Parse(time.RFC3339, modStr)
				if err == nil {
					if modTime.After(maxSeenTime) {
						maxSeenTime = modTime
					}
					if !modTime.After(lastRunTime) {
						return
					}
				}
			}

			// Add CVSS scores
			util.AddCVSSScoresToContent(content)

			wasUpdated, _ := newVuln(content)
			if wasUpdated {
				cveCount++
				if cveKey, ok := content["_key"].(string); ok {
					if err := updateReleaseEdgesForCVE(context.Background(), cveKey); err != nil {
						logger.Sugar().Errorf("Failed to update release edges for CVE %s: %v", cveKey, err)
					}
				}
			}
		}()
	}

	if cveCount > 0 {
		if maxSeenTime.IsZero() {
			maxSeenTime = time.Now().UTC()
		}
		logger.Sugar().Infof("Ecosystem: %s | New CVEs: %d | Updating high water mark to %s", platform, cveCount, maxSeenTime.Format(time.RFC3339))
		util.SaveLastRun(dbconn, platform, maxSeenTime)
	} else {
		logger.Sugar().Infof("Ecosystem: %s | No new CVEs found", platform)
	}

	return cveCount
}

// ============================================================================
// CVE Document Processing
// ============================================================================

func newVuln(content map[string]interface{}) (bool, error) {
	var ctx = context.Background()
	id, ok := content["id"].(string)
	if !ok || id == "" {
		return false, nil
	}

	cveKey := util.SanitizeKey(id)
	content["_key"] = cveKey
	content["objtype"] = "CVE"

	// Check if already processed with same modification date
	modDate, _ := content["modified"].(string)
	parameters := map[string]interface{}{"key": cveKey}

	checkModQuery := `
		FOR vuln IN cve 
			FILTER vuln._key == @key 
			RETURN vuln.modified
	`

	cursor, err := dbconn.Database.Query(ctx, checkModQuery, &arangodb.QueryOptions{
		BindVars: parameters,
	})
	if err == nil {
		defer cursor.Close()
		if cursor.HasMore() {
			var existingMod string
			if _, err := cursor.ReadDocument(ctx, &existingMod); err == nil {
				if existingMod == modDate {
					return false, nil // No update needed
				}
			}
		}
	}

	// Skip CVEs without affected packages
	if _, exists := content["affected"]; !exists {
		return false, nil
	}

	// Upsert CVE document
	upsertQuery := `
		UPSERT { _key: @key } 
		INSERT @doc 
		UPDATE @doc 
		IN cve
	`
	bindVars := map[string]interface{}{
		"key": cveKey,
		"doc": content,
	}

	if _, err := dbconn.Database.Query(ctx, upsertQuery, &arangodb.QueryOptions{
		BindVars: bindVars,
	}); err != nil {
		return false, err
	}

	// Populate cve2purl Hub edges
	processEdges(ctx, content)

	return true, nil
}

// githubRepoToPURL converts a GitHub repository URL to a pkg:github PURL.
// "https://github.com/curl/curl.git" → "pkg:github/curl/curl"
func githubRepoToPURL(repoURL string) string {
	repoURL = strings.TrimSuffix(strings.TrimSuffix(repoURL, "/"), ".git")

	const githubPrefix = "https://github.com/"
	if !strings.HasPrefix(repoURL, githubPrefix) {
		return ""
	}

	parts := strings.Split(strings.TrimPrefix(repoURL, githubPrefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}

	// Reuse the shared, centrally-normalized purl builder instead of
	// hand-rolling the string, so github owner/repo casing matches every
	// other consumer (e.g. SBOM component purls built the same way).
	return util.GetBasePURLFromComponents("Github", parts[0], parts[1])
}

// resolvePURL attempts to determine a base PURL for an affected entry using
// a four-tier fallback strategy:
//
//  1. affected.package.purl         — explicit PURL (most ecosystems)
//  2. affected.package.ecosystem    — synthesise from ecosystem + name
//  3. affected.ranges[GIT].repo     — synthesise pkg:github from repo URL (C/C++)
//  4. database_specific.package     — last resort pkg:generic
func resolvePURL(affMap map[string]interface{}, content map[string]interface{}) string {
	// Tier 1 & 2 — package block present
	if pkgMap, ok := affMap["package"].(map[string]interface{}); ok {
		if purl, ok := pkgMap["purl"].(string); ok && purl != "" {
			cleaned, err := util.CleanPURL(purl)
			if err != nil {
				return ""
			}
			basePurl, err := util.GetStandardBasePURL(cleaned)
			if err != nil {
				return ""
			}
			return basePurl
		}

		ecosystem, _ := pkgMap["ecosystem"].(string)
		namespace, _ := pkgMap["namespace"].(string)
		name, _ := pkgMap["name"].(string)
		if ecosystem != "" && name != "" {
			// Julia is a registered purl type (added to the purl-spec Oct 2025):
			// pkg:julia/<Name> — no namespace, case preserved (Julia package
			// names are case-sensitive, e.g. HTTP != http). This must match
			// what real Julia SBOM tools (Trivy, PkgToSoftwareBOM.jl) emit,
			// so the JLL suffix (e.g. rsync_jll) is kept as-is rather than
			// resolved to the wrapped upstream library name.
			if strings.EqualFold(ecosystem, "Julia") {
				return "pkg:julia/" + name
			}
			return util.GetBasePURLFromComponents(ecosystem, namespace, name)
		}
	}

	// Tier 3 — find the first GIT range and extract repo URL
	if ranges, ok := affMap["ranges"].([]interface{}); ok {
		for _, rangeItem := range ranges {
			rangeMap, ok := rangeItem.(map[string]interface{})
			if !ok || rangeMap["type"] != "GIT" {
				continue
			}
			if repo, ok := rangeMap["repo"].(string); ok {
				if purl := githubRepoToPURL(repo); purl != "" {
					return purl
				}
			}
			break // only need the first GIT range
		}
	}

	// Tier 4 — database_specific.package as pkg:generic last resort
	if dbSpecific, ok := content["database_specific"].(map[string]interface{}); ok {
		if pkgName, ok := dbSpecific["package"].(string); ok && pkgName != "" {
			logger.Sugar().Warnf("Using pkg:generic fallback for package %q — consider improving OSV record", pkgName)
			return "pkg:generic/" + strings.ToLower(pkgName)
		}
	}

	return ""
}

// processEdges populates purl hub nodes and cve2purl edges.
// Only SEMVER ranges are stored — GIT ranges are skipped as commit SHAs
// cannot be used for semver version range matching.
func processEdges(ctx context.Context, content map[string]interface{}) error {
	cveID, _ := content["id"].(string)
	cveKey := util.SanitizeKey(cveID)
	cveDocID := "cve/" + cveKey

	affected, ok := content["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return nil
	}

	for _, affItem := range affected {
		affMap, ok := affItem.(map[string]interface{})
		if !ok {
			continue
		}

		basePurl := resolvePURL(affMap, content)
		if basePurl == "" {
			logger.Sugar().Warnf("Could not resolve PURL for CVE %s, skipping affected entry", cveID)
			continue
		}

		purlKey := util.SanitizeKey(basePurl)
		purlNode := map[string]interface{}{
			"_key":    purlKey,
			"purl":    basePurl,
			"objtype": "PURL",
		}

		purlUpsertQuery := `
			UPSERT { _key: @key }
			INSERT @doc
			UPDATE {}
			IN purl
		`
		if _, err := dbconn.Database.Query(ctx, purlUpsertQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"key": purlKey,
				"doc": purlNode,
			},
		}); err != nil {
			// Don't create a cve2purl edge pointing at a purl document
			// that was never actually written -- that produces a
			// permanently-dangling edge (ArangoDB doesn't enforce
			// referential integrity on edge collections), which repair
			// would then "fix" and immediately recreate as dangling
			// again on every subsequent run, forever.
			logger.Sugar().Warnf("Failed to upsert purl document %q for CVE %s, skipping edge: %v", basePurl, cveID, err)
			continue
		}

		purlDocID := "purl/" + purlKey

		ranges, _ := affMap["ranges"].([]interface{})
		if len(ranges) == 0 {
			continue
		}

		for _, rangeItem := range ranges {
			rangeMap, ok := rangeItem.(map[string]interface{})
			if !ok {
				continue
			}

			rangeType, _ := rangeMap["type"].(string)

			// Only process SEMVER ranges — GIT ranges use commit SHAs
			// which cannot be used for semver version matching
			if rangeType != "SEMVER" {
				continue
			}

			events, _ := rangeMap["events"].([]interface{})

			var introduced, fixed, lastAffected string
			for _, eventItem := range events {
				eventMap, ok := eventItem.(map[string]interface{})
				if !ok {
					continue
				}
				if v, ok := eventMap["introduced"].(string); ok {
					introduced = v
				}
				if v, ok := eventMap["fixed"].(string); ok {
					fixed = v
				}
				if v, ok := eventMap["last_affected"].(string); ok {
					lastAffected = v
				}
			}

			if introduced == "" {
				introduced = "0"
			}

			introducedParsed := util.ParseSemanticVersion(introduced)
			fixedParsed := util.ParseSemanticVersion(fixed)
			lastAffectedParsed := util.ParseSemanticVersion(lastAffected)

			edge := map[string]interface{}{
				"_from":         cveDocID,
				"_to":           purlDocID,
				"type":          rangeType,
				"introduced":    introduced,
				"fixed":         fixed,
				"last_affected": lastAffected,
			}

			if introducedParsed.Major != nil {
				edge["introduced_major"] = *introducedParsed.Major
			}
			if introducedParsed.Minor != nil {
				edge["introduced_minor"] = *introducedParsed.Minor
			}
			if introducedParsed.Patch != nil {
				edge["introduced_patch"] = *introducedParsed.Patch
			}
			if fixedParsed.Major != nil {
				edge["fixed_major"] = *fixedParsed.Major
			}
			if fixedParsed.Minor != nil {
				edge["fixed_minor"] = *fixedParsed.Minor
			}
			if fixedParsed.Patch != nil {
				edge["fixed_patch"] = *fixedParsed.Patch
			}
			if lastAffectedParsed.Major != nil {
				edge["last_affected_major"] = *lastAffectedParsed.Major
			}
			if lastAffectedParsed.Minor != nil {
				edge["last_affected_minor"] = *lastAffectedParsed.Minor
			}
			if lastAffectedParsed.Patch != nil {
				edge["last_affected_patch"] = *lastAffectedParsed.Patch
			}

			// UPSERT instead of check-then-create: one round-trip instead
			// of two, and as a side benefit it now also updates the edge
			// if a re-modified CVE's SEMVER range changed (introduced/
			// fixed/last_affected) -- the previous check-then-create only
			// checked for _from/_to existence, so a changed range on an
			// already-processed CVE silently kept the stale edge forever.
			edgeKey := cveKey + "_" + purlKey
			edge["_key"] = edgeKey

			edgeUpsertQuery := `
				UPSERT { _key: @key }
				INSERT @doc
				UPDATE @doc
				IN cve2purl
			`
			if _, err := dbconn.Database.Query(ctx, edgeUpsertQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"key": edgeKey,
					"doc": edge,
				},
			}); err != nil {
				logger.Sugar().Warnf("Failed to upsert cve2purl edge from %s to %s: %v", cveDocID, purlDocID, err)
			}
		}
	}

	return nil
}

// ============================================================================
// Release to CVE Materialized Edge Creation
// BACKEND CONSISTENCY: Matches restapi/modules/releases/handlers.go
// ============================================================================
func updateReleaseEdgesForCVE(ctx context.Context, cveKey string) error {
	cveID := "cve/" + cveKey

	cleanupQuery := `
		FOR edge IN release2cve 
			FILTER edge._to == @cveID 
			REMOVE edge IN release2cve
	`
	dbconn.Database.Query(ctx, cleanupQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveID": cveID,
		},
	})

	query := `
		FOR cve IN cve
			FILTER cve._key == @cveKey

			FOR purl, cveEdge IN 1..1 OUTBOUND cve cve2purl

				FOR sbom, sbomEdge IN 1..1 INBOUND purl sbom2purl

					FILTER (
						sbomEdge.version_major != null AND
						cveEdge.introduced_major != null AND
						(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
					) ? (
						(
							sbomEdge.version_major > cveEdge.introduced_major OR
							(
								sbomEdge.version_major == cveEdge.introduced_major AND
								sbomEdge.version_minor > cveEdge.introduced_minor
							) OR
							(
								sbomEdge.version_major == cveEdge.introduced_major AND
								sbomEdge.version_minor == cveEdge.introduced_minor AND
								sbomEdge.version_patch >= cveEdge.introduced_patch
							)
						)
						AND
						(
							cveEdge.fixed_major != null ? (
								sbomEdge.version_major < cveEdge.fixed_major OR
								(
									sbomEdge.version_major == cveEdge.fixed_major AND
									sbomEdge.version_minor < cveEdge.fixed_minor
								) OR
								(
									sbomEdge.version_major == cveEdge.fixed_major AND
									sbomEdge.version_minor == cveEdge.fixed_minor AND
									sbomEdge.version_patch < cveEdge.fixed_patch
								)
							) : (
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(
									sbomEdge.version_major == cveEdge.last_affected_major AND
									sbomEdge.version_minor < cveEdge.last_affected_minor
								) OR
								(
									sbomEdge.version_major == cveEdge.last_affected_major AND
									sbomEdge.version_minor == cveEdge.last_affected_minor AND
									sbomEdge.version_patch <= cveEdge.last_affected_patch
								)
							)
						)
					) : true

					FOR release, r2s IN 1..1 INBOUND sbom release2sbom
						RETURN {
							release_id: release._id,
							package_purl_full: sbomEdge.full_purl,
							package_purl_base: purl.purl,
							package_version: sbomEdge.version,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveKey": cveKey,
		},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	type Candidate struct {
		ReleaseID       string `json:"release_id"`
		PackagePurlFull string `json:"package_purl_full"`
		PackagePurlBase string `json:"package_purl_base"`
		PackageVersion  string `json:"package_version"`
		NeedsValidation bool   `json:"needs_validation"`
	}

	var candidates []Candidate
	needsValidation := false

	for cursor.HasMore() {
		var cand Candidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}
		candidates = append(candidates, cand)
		if cand.NeedsValidation {
			needsValidation = true
		}
	}

	var cveAffectedMap map[string][]models.Affected
	if needsValidation {
		cveAffectedMap, err = util.FetchCVEAffectedData(ctx, dbconn.Database, []string{cveKey})
		if err != nil {
			return err
		}
	}

	var edgesToInsert []map[string]interface{}
	seenInstances := make(map[string]bool)

	for _, cand := range candidates {
		instanceKey := cand.ReleaseID + ":" + cand.PackagePurlBase
		if seenInstances[instanceKey] {
			continue
		}

		if cand.NeedsValidation {
			affectedData := cveAffectedMap[cveKey]
			if len(affectedData) > 0 {
				matchFound := false
				for _, affected := range affectedData {
					affectedPurl := ""
					if affected.Package.Purl != "" {
						affectedPurl = affected.Package.Purl
					} else {
						ecosystem := string(affected.Package.Ecosystem)
						namespace := affected.Package.Name
						if strings.Contains(namespace, "/") {
							parts := strings.Split(namespace, "/")
							if len(parts) == 2 {
								namespace = parts[0]
							}
						}
						affectedPurl = util.GetBasePURLFromComponents(ecosystem, namespace, affected.Package.Name)
					}

					standardizedAffectedPurl, err := util.GetStandardBasePURL(affectedPurl)
					if err != nil {
						continue
					}

					if standardizedAffectedPurl == cand.PackagePurlBase {
						if util.IsVersionAffected(cand.PackageVersion, affected) {
							matchFound = true
							break
						}
					}
				}
				if !matchFound {
					continue
				}
			}
		}

		seenInstances[instanceKey] = true

		edgesToInsert = append(edgesToInsert, map[string]interface{}{
			"_from":           cand.ReleaseID,
			"_to":             cveID,
			"type":            "static_analysis",
			"package_purl":    cand.PackagePurlFull,
			"package_base":    cand.PackagePurlBase,
			"package_version": cand.PackageVersion,
			"created_at":      time.Now().UTC().Format(time.RFC3339),
		})
	}

	if len(edgesToInsert) > 0 {
		insertQuery := `
			FOR edge IN @edges 
				INSERT edge INTO release2cve
		`
		_, err := dbconn.Database.Query(ctx, insertQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"edges": edgesToInsert,
			},
		})
		return err
	}

	return nil
}

// ============================================================================
// Lifecycle Tracking Update
// ============================================================================

func updateLifecycleForNewCVEs(_ int) error {
	ctx := context.Background()

	// Get current state of all endpoints with their active releases
	// Uses DATE_ISO8601 for robust parsing of string-based synced_at timestamps
	endpointStateQuery := `
		FOR endpoint IN endpoint
			// Find latest sync event for this endpoint
			LET latestSync = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					SORT DATE_TIMESTAMP(sync.synced_at) DESC
					LIMIT 1
					RETURN sync
			)[0]
			
			FILTER latestSync != null
			
			// Get all releases at this sync timestamp (current state)
			LET activeReleases = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					FILTER sync.synced_at == latestSync.synced_at
					RETURN {
						name: sync.release_name,
						version: sync.release_version
					}
			)
			
			RETURN {
				endpoint_name: endpoint.name,
				releases: activeReleases,
				last_sync_time: DATE_ISO8601(latestSync.synced_at)
			}
	`

	cursor, err := dbconn.Database.Query(ctx, endpointStateQuery, nil)
	if err != nil {
		return err
	}
	defer cursor.Close()

	// Process each endpoint
	for cursor.HasMore() {
		var state struct {
			EndpointName string
			Releases     []ReleaseInfo
			LastSyncTime time.Time
		}
		if _, err := cursor.ReadDocument(ctx, &state); err != nil || state.LastSyncTime.IsZero() {
			continue
		}

		// Get all CVEs affecting these releases
		currentCVEs, _ := getCVEsForReleases(ctx, state.Releases)

		// Update lifecycle records for each CVE
		for _, cveInfo := range currentCVEs {
			// Check if CVE was disclosed after deployment
			disclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(state.LastSyncTime)

			// Create or update lifecycle record
			// The lifecycle package handles normalization of state.LastSyncTime internally
			lifecycle.CreateOrUpdateLifecycleRecord(
				ctx,
				dbconn,
				state.EndpointName,
				cveInfo.ReleaseName,
				cveInfo.ReleaseVersion,
				cveInfo,
				state.LastSyncTime,
				disclosedAfter,
			)
		}
	}

	return nil
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

type ReleaseInfo struct {
	Name    string
	Version string
}

// getCVEsForReleases retrieves all CVEs affecting the given releases
func getCVEsForReleases(ctx context.Context, releases []ReleaseInfo) (map[string]lifecycle.CVEInfo, error) {
	result := make(map[string]lifecycle.CVEInfo)

	for _, rel := range releases {
		// Query CVEs via materialized release2cve edges
		cveQuery := `
			FOR r IN release
				FILTER r.name == @name 
				   AND r.version == @version
				
				// Traverse release2cve materialized edges
				FOR cve, edge IN 1..1 OUTBOUND r release2cve
					RETURN {
						cve_id: cve.id,
						published: cve.published,
						package: edge.package_base,
						severity_rating: cve.database_specific.severity_rating,
						severity_score: cve.database_specific.cvss_base_score
					}
		`

		cursor, _ := dbconn.Database.Query(ctx, cveQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"name":    rel.Name,
				"version": rel.Version,
			},
		})

		for cursor.HasMore() {
			var v struct {
				CveID          string  `json:"cve_id"`
				Published      string  `json:"published"`
				Package        string  `json:"package"`
				SeverityRating string  `json:"severity_rating"`
				SeverityScore  float64 `json:"severity_score"`
			}

			if _, err := cursor.ReadDocument(ctx, &v); err == nil {
				pub, _ := time.Parse(time.RFC3339, v.Published)

				// Create unique key for deduplication
				key := fmt.Sprintf("%s:%s:%s", v.CveID, v.Package, rel.Name)

				result[key] = lifecycle.CVEInfo{
					CVEID:          v.CveID,
					Package:        v.Package,
					SeverityRating: v.SeverityRating,
					SeverityScore:  v.SeverityScore,
					Published:      pub,
					ReleaseName:    rel.Name,
					ReleaseVersion: rel.Version,
				}
			}
		}
		cursor.Close()
	}

	return result, nil
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	LoadFromOSVDev()
}

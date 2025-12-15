// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
//
// CRITICAL FIXES APPLIED:
// 1. Added Materialized Edge updating (release2cve) for instant lookups
// 2. Maintained robust version validation (AQL + Go-side)
// 3. Fixed "unused variable" error by restoring debug logger in getCVEsForRelease
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
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"

	// CVSS libraries
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// EcosystemMetadata stores the high-water mark for imports
type EcosystemMetadata struct {
	Key          string `json:"_key"`          // e.g., "npm", "maven"
	LastModified string `json:"last_modified"` // RFC3339 Timestamp
	Type         string `json:"type"`          // "ecosystem_metadata"
}

// ----------------------------------------------------------------------------
// CVSS & Helper Functions
// ----------------------------------------------------------------------------

func calculateCVSSScore(vectorStr string) float64 {
	if vectorStr == "" || !strings.HasPrefix(vectorStr, "CVSS:") {
		return 0
	}
	if strings.HasPrefix(vectorStr, "CVSS:3.1") || strings.HasPrefix(vectorStr, "CVSS:3.0") {
		if cvss31, err := gocvss31.ParseVector(vectorStr); err == nil {
			return cvss31.BaseScore()
		}
	}
	if strings.HasPrefix(vectorStr, "CVSS:4.0") {
		if cvss40, err := gocvss40.ParseVector(vectorStr); err == nil {
			return cvss40.Score()
		}
	}
	return 0
}

func addCVSSScoresToContent(content map[string]interface{}) {
	severity, ok := content["severity"].([]interface{})
	var baseScores []float64
	var highestScore float64
	hasValidScore := false

	if ok && len(severity) > 0 {
		for _, sev := range severity {
			sevMap, ok := sev.(map[string]interface{})
			if !ok {
				continue
			}
			scoreStr, ok := sevMap["score"].(string)
			if !ok || scoreStr == "" {
				continue
			}
			sevType, _ := sevMap["type"].(string)
			if sevType == "CVSS_V3" || sevType == "CVSS_V4" {
				baseScore := calculateCVSSScore(scoreStr)
				if baseScore > 0 {
					baseScores = append(baseScores, baseScore)
					hasValidScore = true
					if baseScore > highestScore {
						highestScore = baseScore
					}
				}
			}
		}
	}

	if !hasValidScore {
		highestScore = 0.1
		baseScores = []float64{0.1}
	}

	if content["database_specific"] == nil {
		content["database_specific"] = make(map[string]interface{})
	}
	dbSpecific := content["database_specific"].(map[string]interface{})
	dbSpecific["cvss_base_scores"] = baseScores
	dbSpecific["cvss_base_score"] = highestScore
	dbSpecific["severity_rating"] = getSeverityRating(highestScore)
	content["database_specific"] = dbSpecific
}

func getSeverityRating(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// ----------------------------------------------------------------------------
// DB Logic
// ----------------------------------------------------------------------------

// SanitizeKey ensures the database key is valid
// ArangoDB keys cannot contain spaces, slashes, or brackets
func SanitizeKey(key string) string {
	// 1. Trim whitespace/newlines first
	key = strings.TrimSpace(key)

	// 2. Use Replacer for cleaner, faster, multi-string replacement
	replacer := strings.NewReplacer(
		" ", "-",
		"/", "-",
		"[", "",
		"]", "",
		"(", "",
		")", "",
	)

	return replacer.Replace(key)
}

// GetLastRun retrieves the timestamp of the last successful import for an ecosystem
func GetLastRun(ecosystem string) (time.Time, error) {
	key := SanitizeKey(ecosystem)
	if key == "" {
		return time.Time{}, nil
	}

	ctx := context.Background()
	query := `RETURN DOCUMENT("metadata", @key)`
	bindVars := map[string]interface{}{"key": key}

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	if err != nil {
		return time.Time{}, nil
	}
	defer cursor.Close()

	var meta EcosystemMetadata
	if _, err := cursor.ReadDocument(ctx, &meta); err != nil {
		return time.Time{}, nil
	}

	return time.Parse(time.RFC3339, meta.LastModified)
}

// SaveLastRun updates the timestamp after a successful import
func SaveLastRun(ecosystem string, lastModified time.Time) error {
	key := SanitizeKey(ecosystem)

	// Final safety check to prevent empty keys
	if key == "" {
		return fmt.Errorf("cannot save last run for empty ecosystem key (original: %s)", ecosystem)
	}

	ctx := context.Background()
	query := `
		UPSERT { _key: @key }
		INSERT { _key: @key, last_modified: @time, type: "ecosystem_metadata" }
		UPDATE { last_modified: @time }
		IN metadata
	`

	bindVars := map[string]interface{}{
		"key":  key,
		"time": lastModified.Format(time.RFC3339),
	}

	_, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	return err
}

// ----------------------------------------------------------------------------
// Main Import Logic
// ----------------------------------------------------------------------------

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

	// Split by newline
	lines := strings.Split(string(body), "\n")

	// Aggregate total CVE updates
	totalCVEsUpdated := 0

	// SERIAL EXECUTION: Loop through lines one by one
	for _, line := range lines {
		// CRITICAL FIX: Trim whitespace/carriage returns (\r) BEFORE using the string
		platform := strings.TrimSpace(line)

		if len(platform) == 0 {
			continue
		}

		cveCount := processEcosystem(client, platform)
		totalCVEsUpdated += cveCount
	}

	// Trigger lifecycle tracking update ONCE after all CVEs are loaded
	// This maintains the cve_lifecycle table for MTTR metrics
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

func processEcosystem(client *http.Client, platform string) int {
	// 1. Get High Water Mark from database
	lastRunTime, _ := GetLastRun(platform)

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

	// SERIAL EXECUTION: Loop through zip files one by one
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

			// 2. CHECK TIMESTAMP (Optimization)
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

			// 3. Process if new
			wasUpdated, err := newVuln(content)
			if err != nil {
				logger.Sugar().Debugf("Error processing %s: %v", f.Name, err)
			}
			if wasUpdated {
				cveCount++
				// OPTION 2: Trigger Materialized Edge Update for this CVE
				// This finds all existing releases affected by this new/updated CVE
				if cveKey, ok := content["_key"].(string); ok {
					if err := updateReleaseEdgesForCVE(context.Background(), cveKey); err != nil {
						logger.Sugar().Errorf("Failed to update release edges for CVE %s: %v", cveKey, err)
					}
				}
			}
		}()
	}

	// 4. Save High Water Mark to database
	if maxSeenTime.IsZero() {
		maxSeenTime = time.Now().UTC()
	}

	if maxSeenTime.After(lastRunTime) {
		if err := SaveLastRun(platform, maxSeenTime); err != nil {
			logger.Sugar().Errorf("Failed to save high water mark for %s: %v", platform, err)
		} else {
			logger.Sugar().Infof("Completed %s. Added/Updated %d vulnerabilities since %v. New High Water Mark: %v", platform, cveCount, lastRunTime, maxSeenTime)
		}
	} else {
		logger.Sugar().Infof("Completed %s. No new data.", platform)
	}

	return cveCount
}

// newVuln persists the vulnerability
// Returns true if the vulnerability was upserted (added or updated), false if skipped
func newVuln(content map[string]interface{}) (bool, error) {
	var ctx = context.Background()

	id, ok := content["id"].(string)
	if !ok || id == "" {
		return false, nil
	}

	content["_key"] = strings.ReplaceAll(id, " ", "-")
	key := content["_key"]

	// Double-check existence in DB
	modDate, _ := content["modified"].(string)
	parameters := map[string]interface{}{"key": key}
	aql := `FOR vuln in cve FILTER vuln._key == @key RETURN vuln.modified`

	cursor, err := dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters})
	if err == nil {
		defer cursor.Close()
		if cursor.HasMore() {
			var existingMod string
			if _, err := cursor.ReadDocument(ctx, &existingMod); err == nil {
				if existingMod == modDate {
					return false, nil // Exact match exists
				}
			}
		}
	}

	if _, exists := content["affected"]; !exists {
		return false, nil
	}

	content["objtype"] = "CVE"
	addCVSSScoresToContent(content)

	query := `UPSERT { _key: @key } INSERT @doc UPDATE @doc IN cve`
	bindVars := map[string]interface{}{"key": key, "doc": content}

	if _, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars}); err != nil {
		return false, err
	}

	return true, processEdges(ctx, content)
}

func processEdges(ctx context.Context, content map[string]interface{}) error {
	type EdgeCandidate struct {
		BasePurl, Ecosystem                                     string
		IntroducedMajor, IntroducedMinor, IntroducedPatch       *int
		FixedMajor, FixedMinor, FixedPatch                      *int
		LastAffectedMajor, LastAffectedMinor, LastAffectedPatch *int
	}

	var edgeCandidates []EdgeCandidate
	uniqueBasePurls := make(map[string]bool)

	if affected, ok := content["affected"].([]interface{}); ok {
		for _, aff := range affected {
			var affectedData models.Affected
			affBytes, _ := json.Marshal(aff)
			json.Unmarshal(affBytes, &affectedData)

			var basePurl, ecosystem string
			if affMap, ok := aff.(map[string]interface{}); ok {
				if pkg, ok := affMap["package"].(map[string]interface{}); ok {
					if purlStr, ok := pkg["purl"].(string); ok && purlStr != "" {
						if cleanedPurl, err := util.CleanPURL(purlStr); err == nil {
							if bp, err := util.GetBasePURL(cleanedPurl); err == nil {
								basePurl = bp
								if parsed, err := util.ParsePURL(cleanedPurl); err == nil {
									ecosystem = parsed.Type
								}
							}
						}
					} else if eco, ok := pkg["ecosystem"].(string); ok {
						if name, ok := pkg["name"].(string); ok {
							if pt := util.EcosystemToPurlType(eco); pt != "" {
								basePurl = fmt.Sprintf("pkg:%s/%s", pt, name)
								ecosystem = pt
							}
						}
					}
				}
			}

			if basePurl == "" {
				continue
			}
			uniqueBasePurls[basePurl] = true

			for _, vrange := range affectedData.Ranges {
				if vrange.Type != models.RangeEcosystem && vrange.Type != models.RangeSemVer {
					continue
				}
				var introduced, fixed, lastAffected *util.ParsedVersion
				for _, event := range vrange.Events {
					if event.Introduced != "" {
						introduced = util.ParseSemanticVersion(event.Introduced)
					}
					if event.Fixed != "" {
						fixed = util.ParseSemanticVersion(event.Fixed)
					}
					if event.LastAffected != "" {
						lastAffected = util.ParseSemanticVersion(event.LastAffected)
					}
				}

				candidate := EdgeCandidate{BasePurl: basePurl, Ecosystem: ecosystem}
				if introduced != nil {
					candidate.IntroducedMajor = introduced.Major
					candidate.IntroducedMinor = introduced.Minor
					candidate.IntroducedPatch = introduced.Patch
				}
				if fixed != nil {
					candidate.FixedMajor = fixed.Major
					candidate.FixedMinor = fixed.Minor
					candidate.FixedPatch = fixed.Patch
				}
				if lastAffected != nil {
					candidate.LastAffectedMajor = lastAffected.Major
					candidate.LastAffectedMinor = lastAffected.Minor
					candidate.LastAffectedPatch = lastAffected.Patch
				}
				edgeCandidates = append(edgeCandidates, candidate)
			}
		}
	}

	if len(edgeCandidates) == 0 {
		return nil
	}

	var basePurls []string
	for p := range uniqueBasePurls {
		basePurls = append(basePurls, p)
	}

	// Bulk PURL Upsert
	purlAql := `
		FOR purl IN @purls
			LET upserted = FIRST(
				UPSERT { purl: purl }
				INSERT { purl: purl, objtype: "PURL" }
				UPDATE {} IN purl
				RETURN NEW
			)
			RETURN { purl: purl, key: upserted._key }
	`
	cursor, err := dbconn.Database.Query(ctx, purlAql, &arangodb.QueryOptions{BindVars: map[string]interface{}{"purls": basePurls}})
	if err != nil {
		return err
	}
	defer cursor.Close()

	purlKeyMap := make(map[string]string)
	for cursor.HasMore() {
		var res struct{ Purl, Key string }
		if _, err := cursor.ReadDocument(ctx, &res); err == nil {
			purlKeyMap[res.Purl] = res.Key
		}
	}

	var edges []map[string]interface{}
	for _, c := range edgeCandidates {
		if pKey, ok := purlKeyMap[c.BasePurl]; ok {
			edge := map[string]interface{}{
				"_from": fmt.Sprintf("cve/%s", content["_key"]),
				"_to":   fmt.Sprintf("purl/%s", pKey),
			}
			if c.Ecosystem != "" {
				edge["ecosystem"] = c.Ecosystem
			}
			if c.IntroducedMajor != nil {
				edge["introduced_major"] = *c.IntroducedMajor
			}
			if c.IntroducedMinor != nil {
				edge["introduced_minor"] = *c.IntroducedMinor
			}
			if c.IntroducedPatch != nil {
				edge["introduced_patch"] = *c.IntroducedPatch
			}
			if c.FixedMajor != nil {
				edge["fixed_major"] = *c.FixedMajor
			}
			if c.FixedMinor != nil {
				edge["fixed_minor"] = *c.FixedMinor
			}
			if c.FixedPatch != nil {
				edge["fixed_patch"] = *c.FixedPatch
			}
			if c.LastAffectedMajor != nil {
				edge["last_affected_major"] = *c.LastAffectedMajor
			}
			if c.LastAffectedMinor != nil {
				edge["last_affected_minor"] = *c.LastAffectedMinor
			}
			if c.LastAffectedPatch != nil {
				edge["last_affected_patch"] = *c.LastAffectedPatch
			}
			edges = append(edges, edge)
		}
	}

	if len(edges) > 0 {
		// Delete old edges
		delQ := `FOR edge IN cve2purl FILTER edge._from == @cveId REMOVE edge IN cve2purl`
		dbconn.Database.Query(ctx, delQ, &arangodb.QueryOptions{BindVars: map[string]interface{}{"cveId": fmt.Sprintf("cve/%s", content["_key"])}})

		// Insert new edges
		insQ := `FOR edge IN @edges INSERT edge INTO cve2purl`
		dbconn.Database.Query(ctx, insQ, &arangodb.QueryOptions{BindVars: map[string]interface{}{"edges": edges}})
	}

	return nil
}

// updateReleaseEdgesForCVE is the Reverse Lookup function for Option 2
// It finds all releases affected by the given CVE and creates/updates the release2cve edges
func updateReleaseEdgesForCVE(ctx context.Context, cveKey string) error {
	cveID := "cve/" + cveKey

	// 1. Cleanup old edges for this CVE
	// Note: We filter by _to because release2cve is Release -> CVE
	cleanupQuery := `
		FOR edge IN release2cve
			FILTER edge._to == @cveID
			REMOVE edge IN release2cve
	`
	if _, err := dbconn.Database.Query(ctx, cleanupQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"cveID": cveID},
	}); err != nil {
		return err
	}

	// 2. Find Candidates using Robust AQL Filter
	// We traverse from CVE -> PURL -> SBOM -> Release
	query := `
		FOR cve IN cve
			FILTER cve._key == @cveKey
			
			// 1. Find PURLs linked to this CVE
			FOR cveEdge IN cve2purl
				FILTER cveEdge._from == cve._id
				
				// 2. Find SBOMs that use this PURL (Reverse Lookup)
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._to == cveEdge._to
					
					// 3. Robust AQL Version Filter (Copied from existing logic)
					FILTER (
						sbomEdge.version_major != null AND 
						cveEdge.introduced_major != null AND 
						(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
					) ? (
						(sbomEdge.version_major > cveEdge.introduced_major OR
						(sbomEdge.version_major == cveEdge.introduced_major AND 
						sbomEdge.version_minor > cveEdge.introduced_minor) OR
						(sbomEdge.version_major == cveEdge.introduced_major AND 
						sbomEdge.version_minor == cveEdge.introduced_minor AND 
						sbomEdge.version_patch >= cveEdge.introduced_patch))
						AND
						(cveEdge.fixed_major != null ? (
							sbomEdge.version_major < cveEdge.fixed_major OR
							(sbomEdge.version_major == cveEdge.fixed_major AND 
							sbomEdge.version_minor < cveEdge.fixed_minor) OR
							(sbomEdge.version_major == cveEdge.fixed_major AND 
							sbomEdge.version_minor == cveEdge.fixed_minor AND 
							sbomEdge.version_patch < cveEdge.fixed_patch)
						) : (
							sbomEdge.version_major < cveEdge.last_affected_major OR
							(sbomEdge.version_major == cveEdge.last_affected_major AND 
							sbomEdge.version_minor < cveEdge.last_affected_minor) OR
							(sbomEdge.version_major == cveEdge.last_affected_major AND 
							sbomEdge.version_minor == cveEdge.last_affected_minor AND 
							sbomEdge.version_patch <= cveEdge.last_affected_patch)
						))
					) : true
					
					// 4. Find the Release that owns this SBOM
					FOR release IN 1..1 INBOUND sbomEdge._from release2sbom
					
						RETURN {
							release_id: release._id,
							package_purl: sbomEdge.full_purl,
							package_version: sbomEdge.version,
							all_affected: cve.affected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"cveKey": cveKey},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	var edgesToInsert []map[string]interface{}
	type Candidate struct {
		ReleaseID       string            `json:"release_id"`
		PackagePurl     string            `json:"package_purl"`
		PackageVersion  string            `json:"package_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	for cursor.HasMore() {
		var cand Candidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}

		// Perform Go-side validation if DB couldn't confirm
		if cand.NeedsValidation {
			if !isVersionAffectedAny(cand.PackageVersion, cand.AllAffected) {
				continue
			}
		}

		// Prepare Materialized Edge
		edgesToInsert = append(edgesToInsert, map[string]interface{}{
			"_from":           cand.ReleaseID,
			"_to":             cveID,
			"type":            "static_analysis",
			"package_purl":    cand.PackagePurl,
			"package_version": cand.PackageVersion,
			"created_at":      time.Now(),
		})
	}

	// 3. Batch Insert Edges
	if len(edgesToInsert) > 0 {
		query := `FOR edge IN @edges INSERT edge INTO release2cve`
		_, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{"edges": edgesToInsert},
		})
		return err
	}

	return nil
}

// updateLifecycleForNewCVEs updates lifecycle tracking after CVE database updates
func updateLifecycleForNewCVEs(cveUpdateCount int) error {
	logger.Sugar().Infof("Triggering lifecycle update for %d newly disclosed CVEs", cveUpdateCount)

	ctx := context.Background()

	// Get all endpoints with their current releases
	query := `
		FOR endpoint IN endpoint
			LET latestSync = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					SORT sync.synced_at DESC
					LIMIT 1
					RETURN sync
			)[0]
			
			FILTER latestSync != null
			
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
				last_sync_time: latestSync.synced_at
			}
	`

	cursor, err := dbconn.Database.Query(ctx, query, nil)
	if err != nil {
		return fmt.Errorf("failed to query active endpoints: %w", err)
	}
	defer cursor.Close()

	type EndpointState struct {
		EndpointName string        `json:"endpoint_name"`
		Releases     []ReleaseInfo `json:"releases"`
		LastSyncTime time.Time     `json:"last_sync_time"`
	}

	processedCount := 0
	newCVEsDetected := 0
	errorCount := 0

	for cursor.HasMore() {
		var state EndpointState
		if _, err := cursor.ReadDocument(ctx, &state); err != nil {
			errorCount++
			continue
		}

		if len(state.Releases) == 0 {
			continue
		}

		// Get current CVEs for these releases
		currentCVEs, err := getCVEsForReleases(ctx, state.Releases)
		if err != nil {
			logger.Sugar().Warnf("Failed to get CVEs for endpoint %s: %v", state.EndpointName, err)
			errorCount++
			continue
		}

		// Get tracked CVEs from lifecycle collection
		trackedCVEs, err := getTrackedCVEsForEndpoint(ctx, state.EndpointName)
		if err != nil {
			logger.Sugar().Warnf("Failed to get lifecycle CVEs for endpoint %s: %v", state.EndpointName, err)
			errorCount++
			continue
		}

		// Find newly-disclosed CVEs (in current but not tracked)
		for cveKey, cveInfo := range currentCVEs {
			if _, tracked := trackedCVEs[cveKey]; !tracked {
				if err := createLifecycleRecord(ctx, state.EndpointName, cveInfo, state.LastSyncTime, true); err != nil {
					logger.Sugar().Warnf("Failed to create lifecycle record for %s on %s: %v",
						cveKey, state.EndpointName, err)
					errorCount++
				} else {
					newCVEsDetected++
					logger.Sugar().Debugf("Detected newly-disclosed CVE: %s on endpoint %s", cveInfo.CveID, state.EndpointName)
				}
			}
		}

		processedCount++
	}

	logger.Sugar().Infof("CVE lifecycle update complete: %d endpoints, %d new CVEs detected, %d errors",
		processedCount, newCVEsDetected, errorCount)

	return nil
}

// ReleaseInfo represents a release name and version
type ReleaseInfo struct {
	Name    string
	Version string
}

// getCVEsForReleases fetches all CVEs for the given list of releases
func getCVEsForReleases(ctx context.Context, releases []ReleaseInfo) (map[string]CVEInfo, error) {
	result := make(map[string]CVEInfo)

	for _, release := range releases {
		// Optimization: This could also use release2cve edges now, but for lifecycle tracking
		// using the existing method ensures consistency during the transition.
		cves, err := getCVEsForRelease(ctx, release.Name, release.Version)
		if err != nil {
			logger.Sugar().Warnf("Failed to get CVEs for release %s:%s: %v", release.Name, release.Version, err)
			continue
		}

		for cveID, cveInfo := range cves {
			key := fmt.Sprintf("%s:%s:%s", cveID, cveInfo.Package, release.Name)
			result[key] = cveInfo
		}
	}

	return result, nil
}

// getCVEsForRelease queries CVEs for a specific release
func getCVEsForRelease(ctx context.Context, releaseName, releaseVersion string) (map[string]CVEInfo, error) {
	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			LIMIT 1
			
			LET sbomData = (
				FOR s IN 1..1 OUTBOUND release release2sbom
					LIMIT 1
					RETURN { id: s._id }
			)[0]
			
			FILTER sbomData != null
			
			LET vulns = (
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbomData.id
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						
						// ROBUST AQL FILTER
						FILTER (
							sbomEdge.version_major != null AND 
							cveEdge.introduced_major != null AND 
							(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
						) ? (
							(sbomEdge.version_major > cveEdge.introduced_major OR
							(sbomEdge.version_major == cveEdge.introduced_major AND 
							sbomEdge.version_minor > cveEdge.introduced_minor) OR
							(sbomEdge.version_major == cveEdge.introduced_major AND 
							sbomEdge.version_minor == cveEdge.introduced_minor AND 
							sbomEdge.version_patch >= cveEdge.introduced_patch))
							AND
							(cveEdge.fixed_major != null ? (
								sbomEdge.version_major < cveEdge.fixed_major OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								sbomEdge.version_minor < cveEdge.fixed_minor) OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								sbomEdge.version_minor == cveEdge.fixed_minor AND 
								sbomEdge.version_patch < cveEdge.fixed_patch)
							) : (
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								sbomEdge.version_minor < cveEdge.last_affected_minor) OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								sbomEdge.version_minor == cveEdge.last_affected_minor AND 
								sbomEdge.version_patch <= cveEdge.last_affected_patch)
							))
						) : true
						
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						
						LET matchedAffected = (
							FOR affected IN cve.affected != null ? cve.affected : []
								LET cveBasePurl = affected.package.purl != null ? 
									affected.package.purl : 
									CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
								FILTER cveBasePurl == purl.purl
								RETURN affected
						)
						FILTER LENGTH(matchedAffected) > 0
						
						RETURN {
							cve_id: cve.id,
							severity_rating: cve.database_specific.severity_rating,
							severity_score: cve.database_specific.cvss_base_score,
							package: purl.purl,
							affected_version: sbomEdge.version,
							all_affected: matchedAffected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
			)
			
			RETURN vulns
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    releaseName,
			"version": releaseVersion,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type VulnRaw struct {
		CveID           string            `json:"cve_id"`
		SeverityRating  string            `json:"severity_rating"`
		SeverityScore   float64           `json:"severity_score"`
		Package         string            `json:"package"`
		AffectedVersion string            `json:"affected_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	result := make(map[string]CVEInfo)
	totalFromQuery := 0
	filteredByValidation := 0
	deduplicated := 0

	if cursor.HasMore() {
		var vulns []VulnRaw
		if _, err := cursor.ReadDocument(ctx, &vulns); err == nil {
			totalFromQuery = len(vulns)
			seen := make(map[string]bool)

			for _, v := range vulns {
				if v.NeedsValidation {
					if len(v.AllAffected) > 0 {
						if !isVersionAffectedAny(v.AffectedVersion, v.AllAffected) {
							filteredByValidation++
							logger.Sugar().Debugf("FILTERED OUT (Validation Needed): CVE %s for package %s version %s",
								v.CveID, v.Package, v.AffectedVersion)
							continue
						}
					} else {
						logger.Sugar().Warnf("CVE %s for package %s needs validation but has no all_affected data - skipping",
							v.CveID, v.Package)
						filteredByValidation++
						continue
					}
				}

				key := v.CveID + ":" + v.Package
				if seen[key] {
					deduplicated++
					continue
				}
				seen[key] = true

				result[v.CveID] = CVEInfo{
					CveID:          v.CveID,
					Package:        v.Package,
					SeverityRating: v.SeverityRating,
					SeverityScore:  v.SeverityScore,
				}
			}
		}
	}

	// Debug logging to track filtering
	logger.Sugar().Debugf("Release %s:%s - CVEs from query: %d, filtered by validation: %d, deduplicated: %d, final: %d",
		releaseName, releaseVersion, totalFromQuery, filteredByValidation, deduplicated, len(result))

	return result, nil
}

// isVersionAffectedAny checks if a version is affected using Go-side validation
func isVersionAffectedAny(version string, allAffected []models.Affected) bool {
	for _, affected := range allAffected {
		if util.IsVersionAffected(version, affected) {
			return true
		}
	}
	return false
}

// getTrackedCVEsForEndpoint gets all open CVEs from lifecycle collection for an endpoint
func getTrackedCVEsForEndpoint(ctx context.Context, endpointName string) (map[string]bool, error) {
	query := `
		FOR record IN cve_lifecycle
			FILTER record.endpoint_name == @endpoint_name
			FILTER record.is_remediated == false
			RETURN {
				cve_id: record.cve_id,
				package: record.package,
				release_name: record.release_name
			}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"endpoint_name": endpointName,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type TrackedCVE struct {
		CveID       string `json:"cve_id"`
		Package     string `json:"package"`
		ReleaseName string `json:"release_name"`
	}

	result := make(map[string]bool)
	for cursor.HasMore() {
		var tracked TrackedCVE
		if _, err := cursor.ReadDocument(ctx, &tracked); err == nil {
			key := fmt.Sprintf("%s:%s:%s", tracked.CveID, tracked.Package, tracked.ReleaseName)
			result[key] = true
		}
	}

	return result, nil
}

// CVEInfo holds CVE information for lifecycle tracking
type CVEInfo struct {
	CveID          string
	Package        string
	SeverityRating string
	SeverityScore  float64
}

// createLifecycleRecord creates a new CVE lifecycle tracking record
func createLifecycleRecord(ctx context.Context, endpointName string, cveInfo CVEInfo,
	introducedAt time.Time, disclosedAfterDeployment bool) error {

	record := map[string]interface{}{
		"cve_id":                     cveInfo.CveID,
		"endpoint_name":              endpointName,
		"release_name":               "", // Not available in this context
		"package":                    cveInfo.Package,
		"severity_rating":            cveInfo.SeverityRating,
		"severity_score":             cveInfo.SeverityScore,
		"introduced_at":              introducedAt,
		"introduced_version":         "", // Not available in this context
		"is_remediated":              false,
		"disclosed_after_deployment": disclosedAfterDeployment,
		"objtype":                    "CVELifecycleEvent",
		"created_at":                 time.Now(),
		"updated_at":                 time.Now(),
	}

	query := `INSERT @record INTO cve_lifecycle`
	_, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"record": record},
	})
	return err
}

func main() {
	LoadFromOSVDev()
}

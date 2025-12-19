// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
//
// CRITICAL FIXES APPLIED:
// 1. Added Materialized Edge updating (release2cve) for instant lookups
// 2. Maintained robust version validation (AQL + Go-side)
// 3. Fixed cve_lifecycle tracking:
//   - Now checks for existing records by version to prevent duplicates
//   - Allows multiple lifecycle records per CVE (one per version)
//   - Enables proper version-to-version remediation tracking
//   - Uses introducedAt from sync time (not time.Now())
//
// 4. Refactored helper functions into reusable modules
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
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/lifecycle"
	"github.com/ortelius/pdvd-backend/v12/util"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// ----------------------------------------------------------------------------
// Main Import Logic
// ----------------------------------------------------------------------------

// LoadFromOSVDev main entrypoint to load the osv data
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

			modTimeStr, ok := content["modified"].(string)
			if !ok {
				return
			}
			modTime, err := time.Parse(time.RFC3339, modTimeStr)
			if err != nil {
				return
			}

			// HIGH WATER MARK: Skip if not newer than last run
			if !modTime.After(lastRunTime) {
				return
			}

			// Add CVSS scores using helper
			util.AddCVSSScoresToContent(content)

			updated, err := newVuln(content)
			if err != nil {
				logger.Sugar().Errorf("Failed to process CVE %v: %v", content["id"], err)
				return
			}

			if updated {
				cveCount++

				// Update the high-water mark
				if modTime.After(maxSeenTime) {
					maxSeenTime = modTime
				}
			}
		}()
	}

	// 2. Update High Water Mark in database
	if cveCount > 0 {
		logger.Sugar().Infof("Ecosystem: %s | New CVEs: %d | Updating high water mark to %s", platform, cveCount, maxSeenTime.Format(time.RFC3339))
		if err := util.SaveLastRun(dbconn, platform, maxSeenTime); err != nil {
			logger.Sugar().Warnf("Failed to update last run for %s: %v", platform, err)
		}
	} else {
		logger.Sugar().Infof("Ecosystem: %s | No new CVEs found", platform)
	}

	return cveCount
}

func newVuln(content map[string]interface{}) (bool, error) {
	ctx := context.Background()

	cveID, ok := content["id"].(string)
	if !ok || cveID == "" {
		return false, fmt.Errorf("missing CVE ID")
	}

	// 1. Generate the sanitized key (e.g., "CVE-2024-1234")
	cveKey := util.SanitizeKey(cveID)

	// 2. CRITICAL FIX: Explicitly set the _key so it matches what processEdges and traversals expect
	content["_key"] = cveKey
	content["objtype"] = "CVE"

	// 3. UPSERT: Attempt to create. If it fails due to conflict, update the existing document.
	_, err := dbconn.Collections["cve"].CreateDocument(ctx, content)
	if err != nil {
		// If the document already exists, update it using the explicit cveKey
		_, err = dbconn.Collections["cve"].UpdateDocument(ctx, cveKey, content)
		if err != nil {
			return false, err
		}
	}

	// 4. Process edges (PURL relationships) - these will now point to the correct ID
	if err := processEdges(ctx, content); err != nil {
		return false, err
	}

	// 5. Update release2cve materialized edges - the AQL join will now succeed
	if err := updateReleaseEdgesForCVE(ctx, cveKey); err != nil {
		logger.Sugar().Warnf("Failed to update release edges for %s: %v", cveID, err)
	}

	return true, nil
}

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

		pkgMap, ok := affMap["package"].(map[string]interface{})
		if !ok {
			continue
		}

		// Get base PURL
		var basePurl string
		if purl, ok := pkgMap["purl"].(string); ok && purl != "" {
			cleaned, err := util.CleanPURL(purl)
			if err != nil {
				continue
			}
			basePurl, err = util.GetBasePURL(cleaned)
			if err != nil {
				continue
			}
		} else {
			// Construct from ecosystem + name
			ecosystem, _ := pkgMap["ecosystem"].(string)
			name, _ := pkgMap["name"].(string)
			if ecosystem == "" || name == "" {
				continue
			}
			basePurl = fmt.Sprintf("pkg:%s/%s", strings.ToLower(ecosystem), name)
		}

		// Ensure PURL node exists
		purlKey := util.SanitizeKey(basePurl)
		purlNode := map[string]interface{}{
			"purl":    basePurl,
			"objtype": "PURL",
		}
		_, err := dbconn.Collections["purl"].CreateDocument(ctx, purlNode)
		if err != nil {
			// Already exists, continue
		}

		purlDocID := "purl/" + purlKey

		// Parse version ranges
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
			if rangeType != "ECOSYSTEM" && rangeType != "SEMVER" {
				continue
			}

			events, _ := rangeMap["events"].([]interface{})
			var introduced, fixed, lastAffected string

			for _, evt := range events {
				evtMap, _ := evt.(map[string]interface{})
				if intro, ok := evtMap["introduced"].(string); ok {
					introduced = intro
				}
				if fix, ok := evtMap["fixed"].(string); ok {
					fixed = fix
				}
				if last, ok := evtMap["last_affected"].(string); ok {
					lastAffected = last
				}
			}

			// Parse versions
			introducedParsed := util.ParseSemanticVersion(introduced)
			fixedParsed := util.ParseSemanticVersion(fixed)
			lastAffectedParsed := util.ParseSemanticVersion(lastAffected)

			// Get ecosystem
			ecosystem, _ := pkgMap["ecosystem"].(string)

			// Build edge
			edge := map[string]interface{}{
				"_from":     cveDocID,
				"_to":       purlDocID,
				"ecosystem": ecosystem,
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

			// Check if edge exists
			checkQuery := `
				FOR e IN cve2purl
					FILTER e._from == @from AND e._to == @to
					LIMIT 1
					RETURN e
			`
			cursor, err := dbconn.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"from": cveDocID,
					"to":   purlDocID,
				},
			})
			if err != nil {
				continue
			}

			exists := cursor.HasMore()
			cursor.Close()

			if !exists {
				_, err = dbconn.Collections["cve2purl"].CreateDocument(ctx, edge)
				if err != nil {
					logger.Sugar().Warnf("Failed to create edge: %v", err)
				}
			}
		}
	}

	return nil
}

func updateReleaseEdgesForCVE(ctx context.Context, cveKey string) error {
	// Query to find all releases affected by this CVE
	query := `
		FOR r IN release
			FOR sbom IN 1..1 OUTBOUND r release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						FILTER cveEdge._from == @cveID
						
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
							release_id: r._id,
							cve_id: cve._id,
							package_purl: sbomEdge.full_purl,
							package_version: sbomEdge.version,
							all_affected: matchedAffected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveID": "cve/" + cveKey,
		},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	type EdgeCandidate struct {
		ReleaseID       string            `json:"release_id"`
		CveID           string            `json:"cve_id"`
		PackagePurl     string            `json:"package_purl"`
		PackageVersion  string            `json:"package_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	seenEdges := make(map[string]bool)

	for cursor.HasMore() {
		var cand EdgeCandidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}

		// Validate if needed
		if cand.NeedsValidation {
			isAffected := false
			for _, affected := range cand.AllAffected {
				if util.IsVersionAffected(cand.PackageVersion, affected) {
					isAffected = true
					break
				}
			}
			if !isAffected {
				continue
			}
		}

		// Create unique key
		edgeKey := cand.ReleaseID + ":" + cand.CveID + ":" + cand.PackagePurl
		if seenEdges[edgeKey] {
			continue
		}
		seenEdges[edgeKey] = true

		// Check if edge exists
		checkQuery := `
			FOR e IN release2cve
				FILTER e._from == @from AND e._to == @to AND e.package_purl == @purl
				LIMIT 1
				RETURN e
		`
		checkCursor, err := dbconn.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"from": cand.ReleaseID,
				"to":   cand.CveID,
				"purl": cand.PackagePurl,
			},
		})
		if err != nil {
			continue
		}

		edgeExists := checkCursor.HasMore()
		checkCursor.Close()

		if !edgeExists {
			edge := map[string]interface{}{
				"_from":           cand.ReleaseID,
				"_to":             cand.CveID,
				"type":            "static_analysis",
				"package_purl":    cand.PackagePurl,
				"package_version": cand.PackageVersion,
				"created_at":      time.Now(),
			}

			_, err = dbconn.Collections["release2cve"].CreateDocument(ctx, edge)
			if err != nil {
				logger.Sugar().Debugf("Failed to create release2cve edge: %v", err)
			}
		}
	}

	return nil
}

// ----------------------------------------------------------------------------
// CVE Lifecycle Tracking
// ----------------------------------------------------------------------------

type ReleaseInfo struct {
	Name    string
	Version string
}

// Note: Using lifecycle.CVEInfo from shared package
// type CVEInfo is defined in restapi/modules/lifecycle/handlers.go

func updateLifecycleForNewCVEs(cveUpdateCount int) error {
	ctx := context.Background()

	// Get all active deployments (syncs) with their sync timestamps
	query := `
		FOR sync IN sync
			COLLECT release_name = sync.release_name, 
			        release_version = sync.release_version 
			INTO groups = sync
			
			LET latest_sync = FIRST(
				FOR s IN groups
					SORT s.sync.synced_at DESC
					LIMIT 1
					RETURN s.sync
			)
			
			RETURN {
				release_name: release_name,
				release_version: release_version,
				synced_at: latest_sync.synced_at,
				endpoints: UNIQUE(groups[*].sync.endpoint_name)
			}
	`

	cursor, err := dbconn.Database.Query(ctx, query, nil)
	if err != nil {
		return err
	}
	defer cursor.Close()

	type DeployedRelease struct {
		ReleaseName    string    `json:"release_name"`
		ReleaseVersion string    `json:"release_version"`
		SyncedAt       time.Time `json:"synced_at"`
		Endpoints      []string  `json:"endpoints"`
	}

	var deployedReleases []DeployedRelease
	for cursor.HasMore() {
		var dr DeployedRelease
		if _, err := cursor.ReadDocument(ctx, &dr); err == nil {
			deployedReleases = append(deployedReleases, dr)
		}
	}

	logger.Sugar().Infof("Found %d unique deployed releases to check for lifecycle updates", len(deployedReleases))

	// For each deployed release, check for new CVEs
	for _, dr := range deployedReleases {
		releases := []ReleaseInfo{{Name: dr.ReleaseName, Version: dr.ReleaseVersion}}
		cves, err := getCVEsForReleases(ctx, releases)
		if err != nil {
			continue
		}

		// For each endpoint, create/update lifecycle records
		for _, endpointName := range dr.Endpoints {
			for _, cveInfo := range cves {
				// Determine if CVE was disclosed after deployment
				disclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(dr.SyncedAt)

				// CRITICAL: Use shared lifecycle package
				// This ensures consistency with sync-based lifecycle tracking
				err := lifecycle.CreateOrUpdateLifecycleRecord(
					ctx, dbconn,
					endpointName,
					dr.ReleaseName,
					dr.ReleaseVersion,
					cveInfo,
					dr.SyncedAt, // ✅ Actual deployment time
					disclosedAfter,
				)

				if err != nil {
					logger.Sugar().Debugf("Failed to create lifecycle record for %s: %v", cveInfo.CVEID, err)
				}
			}
		}
	}

	return nil
}

func getCVEsForReleases(ctx context.Context, releases []ReleaseInfo) (map[string]lifecycle.CVEInfo, error) {
	result := make(map[string]lifecycle.CVEInfo)

	for _, rel := range releases {
		cves, err := getCVEsForRelease(ctx, rel.Name, rel.Version)
		if err != nil {
			continue
		}
		for k, v := range cves {
			result[k] = v
		}
	}

	return result, nil
}

func getCVEsForRelease(ctx context.Context, releaseName, releaseVersion string) (map[string]lifecycle.CVEInfo, error) {
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
							published: cve.published,
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
		Published       string            `json:"published"`
		SeverityRating  string            `json:"severity_rating"`
		SeverityScore   float64           `json:"severity_score"`
		Package         string            `json:"package"`
		AffectedVersion string            `json:"affected_version"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	result := make(map[string]lifecycle.CVEInfo)
	seen := make(map[string]bool)

	if !cursor.HasMore() {
		return result, nil
	}

	var vulns []VulnRaw
	if _, err = cursor.ReadDocument(ctx, &vulns); err != nil {
		return nil, err
	}

	for _, v := range vulns {
		if v.NeedsValidation {
			if !util.IsVersionAffectedAny(v.AffectedVersion, v.AllAffected) {
				continue
			}
		}

		key := v.CveID + ":" + v.Package
		if seen[key] {
			continue
		}
		seen[key] = true

		var publishedTime time.Time
		if v.Published != "" {
			if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
				publishedTime = t
			}
		}

		result[v.CveID] = lifecycle.CVEInfo{
			CVEID:          v.CveID,
			Package:        v.Package,
			SeverityRating: v.SeverityRating,
			SeverityScore:  v.SeverityScore,
			Published:      publishedTime,
		}
	}

	return result, nil
}

func main() {
	LoadFromOSVDev()
}

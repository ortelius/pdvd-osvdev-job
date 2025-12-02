// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
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
	"os"
	"strings"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/util"

	// CVSS libraries
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// vulnID holds basic vulnerability identification information
type vulnID struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// cveText holds vulnerability description for MITRE mapping
type cveText struct {
	Description string `json:"cvetext"`
}

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// getMitreURL retrieves the MITRE mapping URL from environment
func getMitreURL() string {
	// Get the environment variable value for MITER_MAPPING_URL
	mitreURL := os.Getenv("MITRE_MAPPING_URL")
	return mitreURL
}

// calculateCVSSScore calculates numeric base score from CVSS vector string
// Returns 0 if unable to parse
func calculateCVSSScore(vectorStr string) float64 {
	if vectorStr == "" || !strings.HasPrefix(vectorStr, "CVSS:") {
		return 0
	}

	if strings.HasPrefix(vectorStr, "CVSS:3.1") || strings.HasPrefix(vectorStr, "CVSS:3.0") {
		cvss31, err := gocvss31.ParseVector(vectorStr)
		if err == nil {
			return cvss31.BaseScore()
		}
		logger.Sugar().Debugf("Failed to parse CVSS v3 vector %s: %v", vectorStr, err)
	}

	if strings.HasPrefix(vectorStr, "CVSS:4.0") {
		cvss40, err := gocvss40.ParseVector(vectorStr)
		if err == nil {
			return cvss40.Score()
		}
		logger.Sugar().Debugf("Failed to parse CVSS v4 vector %s: %v", vectorStr, err)
	}

	return 0
}

// addCVSSScoresToContent adds calculated base scores to CVE content
// Modifies the content map in place
// If severity is null or no valid scores found, defaults to LOW (score: 0.1)
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
		logger.Sugar().Debugf("CVE %s has no valid CVSS scores, defaulting to LOW (0.1)", content["_key"])
	}

	if content["database_specific"] == nil {
		content["database_specific"] = make(map[string]interface{})
	}

	dbSpecific := content["database_specific"].(map[string]interface{})
	dbSpecific["cvss_base_scores"] = baseScores
	dbSpecific["cvss_base_score"] = highestScore

	dbSpecific["severity_rating"] = getSeverityRating(highestScore)

	content["database_specific"] = dbSpecific

	if hasValidScore {
		logger.Sugar().Debugf("Added CVSS scores to CVE %s: highest=%.1f", content["_key"], highestScore)
	}
}

// getSeverityRating returns CVSS severity rating based on base score
func getSeverityRating(score float64) string {
	if score == 0 {
		return "NONE"
	} else if score < 4.0 {
		return "LOW"
	} else if score < 7.0 {
		return "MEDIUM"
	} else if score < 9.0 {
		return "HIGH"
	}
	return "CRITICAL"
}

// unpackAndLoad extracts and processes vulnerabilities from a zip archive
func unpackAndLoad(src string) error {

	fmt.Println(src)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	extractAndWriteFile := func(f *zip.File) error {

		if strings.Contains(f.Name, "/") {
			return fmt.Errorf("%s: illegal file path", f.Name)
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		if !f.FileInfo().IsDir() {
			var vulnJSON strings.Builder

			_, err = io.Copy(&vulnJSON, rc)
			if err != nil {
				return err
			}

			var vulnIDMod vulnID
			var vulnStr = vulnJSON.String()
			if err := json.Unmarshal([]byte(vulnStr), &vulnIDMod); err != nil {
				logger.Sugar().Infoln(err)
			}

			if err := newVuln(vulnStr); err != nil {
				logger.Sugar().Infoln(err)
				logger.Sugar().Infoln(vulnStr)
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadFromOSVDev retrieves the vulns from osv.dev and adds them to the Arangodb
func LoadFromOSVDev() {

	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(baseURL)
	if err != nil {
		logger.Sugar().Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Fatalln(err)
	}
	resp.Body.Close()

	ecosystems := strings.Split(string(body), "\n")

	for _, platform := range ecosystems {
		if len(strings.TrimSpace(platform)) == 0 {
			continue
		}

		url := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

		if resp, err := client.Get(url); err == nil {
			filename := fmt.Sprintf("%s.zip", platform)
			if out, err := os.Create(filename); err == nil {
				if _, err := io.Copy(out, resp.Body); err != nil {
					logger.Sugar().Infoln(err)
				}
				out.Close()
			} else {
				logger.Sugar().Infoln(err)
			}

			if err := unpackAndLoad(filename); err != nil {
				logger.Sugar().Infoln(err)
				logger.Sugar().Fatalln(filename)
			}
			os.Remove(filename)
			resp.Body.Close()
		} else {
			logger.Sugar().Infoln(err)
		}
	}
}

// newVuln godoc
// @Summary Create a Vulnerability
// @Description Create a new Vulnerability and persist it with version-aware edges
// @Tags vulnerability
// This function processes CVE/OSV data and creates hub-and-spoke relationships using:
// - One CVE document in the 'cve' collection
// - Multiple PURL hub documents in the 'purl' collection (one per unique package)
// - Multiple cve2purl edges with parsed version boundaries for indexed filtering
//
// CRITICAL: Handles CVEs with multiple affected entries and multiple ranges per entry
// Example: A CVE affecting package versions 0-19.2.16, 20.0.0-20.3.14, and 21.0.0-21.0.1
// will create THREE separate edges, one for each range, enabling accurate version filtering
func newVuln(vulnJSON string) error {
	var existsCursor arangodb.Cursor
	var err error
	var ctx = context.Background()

	var content map[string]interface{}

	if err = json.Unmarshal([]byte(vulnJSON), &content); err != nil {
		logger.Sugar().Errorf("Failed to unmarshal vuln JSON: %v", err)
		return err
	}

	if id, ok := content["id"].(string); ok && id != "" {
		content["_key"] = strings.ReplaceAll(id, " ", "-")
	} else {
		logger.Sugar().Errorf("Document is missing a valid 'id' field to use as _key: %v", vulnJSON)
		return nil
	}

	parameters := map[string]interface{}{
		"key": content["_key"],
	}

	aql := `FOR vuln in cve
			FILTER vuln._key == @key
			RETURN vuln.modified`

	if existsCursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err)
	}

	defer existsCursor.Close()

	moddate := ""

	if existsCursor.HasMore() {
		if _, err = existsCursor.ReadDocument(ctx, &moddate); err != nil {
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
	}

	if content["modified"] == moddate {
		return nil
	}

	combinedJSON := vulnJSON

	if _, exists := content["affected"]; !exists {
		return nil
	}

	summary := ""
	details := ""

	if val, ok := content["summary"]; ok {
		if s, ok := val.(string); ok {
			summary = s
		}
	}

	if val, ok := content["details"]; ok {
		if d, ok := val.(string); ok {
			details = d
		}
	}

	cve := cveText{
		Description: summary + " " + details,
	}

	jsonData, err := json.Marshal(cve)
	if err != nil {
		logger.Sugar().Errorln("Error marshaling JSON:", err)
		return err
	}

	mitreURL := getMitreURL()

	if len(mitreURL) > 0 {
		resp, err := http.Post(mitreURL, "application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				if body, err := io.ReadAll(resp.Body); err == nil {
					techniqueJSON := ", \"techniques\":" + string(body)
					lastBraceIndex := strings.LastIndex(vulnJSON, "}")
					if lastBraceIndex != -1 {
						combinedJSON = vulnJSON[:lastBraceIndex] + techniqueJSON + "}"
					}

					combinedJSON = strings.Replace(combinedJSON, "\"id\":", "\"_key\":", 1)
				}
			}
		} else {
			logger.Sugar().Errorln("Error sending POST request:", err)
		}
	}

	if err := json.Unmarshal([]byte(combinedJSON), &content); err != nil {
		logger.Sugar().Infoln(err)
	}

	key := content["_key"]

	if key == "" {
		logger.Sugar().Errorf("Document is missing a `_key` field for UPSERT: %v", content)
		return nil
	}

	content["objtype"] = "CVE"

	addCVSSScoresToContent(content)

	query := `
		UPSERT { _key: @key }
		INSERT @doc
		UPDATE @doc
		IN cve
	`

	bindVars := map[string]interface{}{
		"key": key,
		"doc": content,
	}

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	if err != nil {
		logger.Sugar().Errorf("AQL UPSERT failed for key '%s': %v", key, err)
		return err
	}
	cursor.Close()

	// ============================================================================
	// CRITICAL SECTION: Multi-Range Edge Creation
	// ============================================================================
	// This section processes CVE vulnerability ranges and creates version-aware edges.
	//
	// IMPORTANT: CVEs can have multiple affected entries (e.g., one CVE affecting
	// multiple version ranges like 0-19.x, 20.x-20.3.x, 21.0.x-21.0.y).
	// Each affected entry and each range within an entry creates a SEPARATE edge.
	//
	// Example CVE structure:
	// {
	//   "affected": [
	//     { "package": "pkg:npm/@angular/common", "ranges": [{"introduced": "0", "fixed": "19.2.16"}] },
	//     { "package": "pkg:npm/@angular/common", "ranges": [{"introduced": "20.0.0", "fixed": "20.3.14"}] },
	//     { "package": "pkg:npm/@angular/common", "ranges": [{"introduced": "21.0.0", "fixed": "21.0.1"}] }
	//   ]
	// }
	//
	// This creates THREE edges, enabling the AQL query to match versions in ANY of these ranges
	// using indexed numeric comparison instead of expensive Go validation.
	// ============================================================================

	// EdgeCandidate represents one complete version range for edge creation
	// Each candidate will become a separate cve2purl edge in the database
	type EdgeCandidate struct {
		BasePurl          string // Base PURL without version (e.g., pkg:npm/@angular/common)
		Ecosystem         string // Package ecosystem (npm, pypi, maven, etc.)
		IntroducedMajor   *int   // Introduced version major component
		IntroducedMinor   *int   // Introduced version minor component
		IntroducedPatch   *int   // Introduced version patch component
		FixedMajor        *int   // Fixed version major component
		FixedMinor        *int   // Fixed version minor component
		FixedPatch        *int   // Fixed version patch component
		LastAffectedMajor *int   // Last affected version major component (alternative to fixed)
		LastAffectedMinor *int   // Last affected version minor component
		LastAffectedPatch *int   // Last affected version patch component
	}

	var edgeCandidates []EdgeCandidate
	uniqueBasePurls := make(map[string]bool)

	// CRITICAL FIX: Process each affected entry and each range separately
	// This handles CVEs with multiple affected entries (like GHSA-58c5-g7wp-6w37)
	// and CVEs with multiple ranges per affected entry
	if affected, ok := content["affected"].([]interface{}); ok {
		for _, aff := range affected {
			var affectedData models.Affected
			affBytes, _ := json.Marshal(aff)
			json.Unmarshal(affBytes, &affectedData)

			var basePurl string
			var ecosystem string

			if affMap, ok := aff.(map[string]interface{}); ok {
				if pkg, ok := affMap["package"].(map[string]interface{}); ok {
					if purlStr, ok := pkg["purl"].(string); ok && purlStr != "" {
						cleanedPurl, err := util.CleanPURL(purlStr)
						if err != nil {
							logger.Sugar().Warnf("Failed to parse PURL %s: %v", purlStr, err)
							continue
						}
						basePurl, err = util.GetBasePURL(cleanedPurl)
						if err != nil {
							logger.Sugar().Warnf("Failed to get base PURL from %s: %v", cleanedPurl, err)
							continue
						}
						parsed, _ := util.ParsePURL(cleanedPurl)
						ecosystem = parsed.Type
					} else {
						if ecosystemStr, ok := pkg["ecosystem"].(string); ok {
							if name, ok := pkg["name"].(string); ok {
								purlType := util.EcosystemToPurlType(ecosystemStr)
								if purlType != "" {
									basePurl = fmt.Sprintf("pkg:%s/%s", purlType, name)
									ecosystem = purlType
								}
							}
						}
					}
				}
			}

			if basePurl == "" {
				continue
			}

			uniqueBasePurls[basePurl] = true

			// Process EACH range in this affected entry
			// This is critical for CVEs with multiple version ranges
			for _, vrange := range affectedData.Ranges {
				if vrange.Type != models.RangeEcosystem && vrange.Type != models.RangeSemVer {
					continue
				}

				// Extract version boundaries for THIS specific range
				// Note: We do NOT use "introduced == nil" checks here, allowing
				// multiple ranges to be processed independently
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

				// Create a separate edge candidate for this range
				// This ensures each version range gets its own indexed edge for AQL filtering
				candidate := EdgeCandidate{
					BasePurl:  basePurl,
					Ecosystem: ecosystem,
				}

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

	if len(edgeCandidates) > 0 {
		// Convert unique PURLs map to slice
		var basePurls []string
		for basePurl := range uniqueBasePurls {
			basePurls = append(basePurls, basePurl)
		}

		// Upsert all unique PURLs and get their keys
		// This creates or retrieves PURL hub documents for the hub-and-spoke pattern
		aql = `
			FOR purl IN @purls
				LET upsertedPurl = FIRST(
					UPSERT { purl: purl }
					INSERT { purl: purl, objtype: "PURL" }
					UPDATE {} IN purl
					RETURN NEW
				)
				RETURN {
					purl: purl,
					key: upsertedPurl._key
				}
		`

		parameters = map[string]interface{}{
			"purls": basePurls,
		}

		cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters})
		if err != nil {
			logger.Sugar().Errorf("Failed to execute PURL upsert query: %v", err)
			return err
		}

		purlKeyMap := make(map[string]string)
		for cursor.HasMore() {
			var result struct {
				Purl string `json:"purl"`
				Key  string `json:"key"`
			}
			_, err := cursor.ReadDocument(ctx, &result)
			if err != nil {
				continue
			}
			purlKeyMap[result.Purl] = result.Key
		}
		cursor.Close()

		// Create edges for all candidates
		// Each candidate becomes a separate cve2purl edge with version boundaries
		// This allows AQL queries to use indexed numeric comparison for version filtering
		var edges []map[string]interface{}
		for _, candidate := range edgeCandidates {
			purlKey, exists := purlKeyMap[candidate.BasePurl]
			if !exists {
				logger.Sugar().Warnf("PURL key not found for %s", candidate.BasePurl)
				continue
			}

			edge := map[string]interface{}{
				"_from": fmt.Sprintf("cve/%s", content["_key"]),
				"_to":   fmt.Sprintf("purl/%s", purlKey),
			}

			if candidate.Ecosystem != "" {
				edge["ecosystem"] = candidate.Ecosystem
			}

			// Store parsed version components for indexed filtering in AQL
			if candidate.IntroducedMajor != nil {
				edge["introduced_major"] = *candidate.IntroducedMajor
			}
			if candidate.IntroducedMinor != nil {
				edge["introduced_minor"] = *candidate.IntroducedMinor
			}
			if candidate.IntroducedPatch != nil {
				edge["introduced_patch"] = *candidate.IntroducedPatch
			}

			if candidate.FixedMajor != nil {
				edge["fixed_major"] = *candidate.FixedMajor
			}
			if candidate.FixedMinor != nil {
				edge["fixed_minor"] = *candidate.FixedMinor
			}
			if candidate.FixedPatch != nil {
				edge["fixed_patch"] = *candidate.FixedPatch
			}

			if candidate.LastAffectedMajor != nil {
				edge["last_affected_major"] = *candidate.LastAffectedMajor
			}
			if candidate.LastAffectedMinor != nil {
				edge["last_affected_minor"] = *candidate.LastAffectedMinor
			}
			if candidate.LastAffectedPatch != nil {
				edge["last_affected_patch"] = *candidate.LastAffectedPatch
			}

			edges = append(edges, edge)
		}

		if len(edges) > 0 {
			// Delete existing edges for this CVE to ensure clean state
			// This handles CVE updates where the affected versions change
			// Uses delete-then-insert pattern to avoid duplicate edge conflicts
			deleteQuery := `
				FOR edge IN cve2purl
					FILTER edge._from == @cveId
					REMOVE edge IN cve2purl
			`
			deleteCursor, err := dbconn.Database.Query(ctx, deleteQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"cveId": fmt.Sprintf("cve/%s", content["_key"]),
				},
			})
			if err != nil {
				logger.Sugar().Warnf("Failed to delete old edges for CVE %s: %v", content["_key"], err)
			} else {
				deleteCursor.Close()
			}

			// Insert all new edges in a single batch operation
			// This creates one edge per version range, enabling indexed AQL filtering
			insertQuery := `
				FOR edge IN @edges
					INSERT edge INTO cve2purl
			`
			insertCursor, err := dbconn.Database.Query(ctx, insertQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"edges": edges,
				},
			})
			if err != nil {
				logger.Sugar().Errorf("Failed to insert edges: %v", err)
				return err
			}
			insertCursor.Close()

			logger.Sugar().Debugf("Created %d cve2purl edges for CVE %s", len(edges), content["_key"])
		}
	}

	return nil
}

func main() {
	LoadFromOSVDev()
}

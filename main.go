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
	// Replaces spaces and slashes with hyphens
	// Removes brackets and parentheses entirely
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

	// SERIAL EXECUTION: Loop through lines one by one
	for _, line := range lines {
		// CRITICAL FIX: Trim whitespace/carriage returns (\r) BEFORE using the string
		platform := strings.TrimSpace(line)

		if len(platform) == 0 {
			continue
		}

		processEcosystem(client, platform)
	}
}

func processEcosystem(client *http.Client, platform string) {
	// 1. Get High Water Mark from database
	lastRunTime, _ := GetLastRun(platform)

	urlStr := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

	resp, err := client.Get(urlStr)
	if err != nil {
		logger.Sugar().Errorf("Failed to download %s: %v", platform, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Errorf("Failed to read body for %s: %v", platform, err)
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logger.Sugar().Errorf("Failed to open zip reader for %s: %v", platform, err)
		return
	}

	var maxSeenTime = lastRunTime
	var cveCount int

	// SERIAL EXECUTION: Loop through zip files one by one
	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || strings.Contains(f.Name, "/") {
			continue
		}

		// Use anonymous function to ensure 'defer rc.Close()' runs immediately after file processing,
		// preventing file descriptor exhaustion in a serial loop.
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
					// Update maxSeenTime (No Mutex needed in serial mode)
					if modTime.After(maxSeenTime) {
						maxSeenTime = modTime
					}

					// If this vuln is older than our last run, SKIP IT
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
			}
		}()
	}

	// 4. Save High Water Mark to database
	// Default to NOW if no new timestamps were found
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

func main() {
	LoadFromOSVDev()
}

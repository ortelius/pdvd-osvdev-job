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
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/lifecycle"
	"github.com/ortelius/pdvd-backend/v12/util"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

func LoadFromOSVDev() {
	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}

	resp, _ := client.Get(baseURL)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	totalCVEsUpdated := 0
	for _, line := range strings.Split(string(body), "\n") {
		platform := strings.TrimSpace(line)
		if platform != "" {
			totalCVEsUpdated += processEcosystem(client, platform)
		}
	}

	if totalCVEsUpdated > 0 {
		logger.Sugar().Infof("Updated %d CVEs. Running lifecycle tracking...", totalCVEsUpdated)
		updateLifecycleForNewCVEs()
	}
}

func processEcosystem(client *http.Client, platform string) int {
	lastRunTime, _ := util.GetLastRun(dbconn, platform)
	urlStr := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

	resp, _ := client.Get(urlStr)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	zipReader, _ := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	cveCount := 0
	maxTime := lastRunTime

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || strings.Contains(f.Name, "/") {
			continue
		}
		rc, _ := f.Open()
		var content map[string]interface{}
		json.NewDecoder(rc).Decode(&content)
		rc.Close()

		modTime, _ := time.Parse(time.RFC3339, content["modified"].(string))
		if modTime.After(lastRunTime) {
			util.AddCVSSScoresToContent(content)
			cveKey := util.SanitizeKey(content["id"].(string))
			content["_key"] = cveKey
			content["objtype"] = "CVE"

			if _, err := dbconn.Collections["cve"].CreateDocument(context.Background(), content); err != nil {
				dbconn.Collections["cve"].UpdateDocument(context.Background(), cveKey, content)
			}
			cveCount++
			if modTime.After(maxTime) {
				maxTime = modTime
			}
		}
	}

	if cveCount > 0 {
		util.SaveLastRun(dbconn, platform, maxTime)
	}
	return cveCount
}

func updateLifecycleForNewCVEs() error {
	ctx := context.Background()
	// FIX: Use DATE_TIMESTAMP and DATE_ISO8601 for robust timestamp handling
	query := `
		FOR sync IN sync
			COLLECT rel_name = sync.release_name, rel_ver = sync.release_version INTO groups = sync
			LET latest_sync = FIRST(FOR s IN groups SORT DATE_TIMESTAMP(s.sync.synced_at) DESC LIMIT 1 RETURN s.sync)
			RETURN {
				release_name: rel_name, release_version: rel_ver,
				synced_at: DATE_ISO8601(latest_sync.synced_at),
				endpoints: UNIQUE(groups[*].sync.endpoint_name)
			}
	`
	cursor, _ := dbconn.Database.Query(ctx, query, nil)
	defer cursor.Close()

	for cursor.HasMore() {
		var dr struct {
			ReleaseName, ReleaseVersion string
			SyncedAt                    time.Time
			Endpoints                   []string
		}
		if _, err := cursor.ReadDocument(ctx, &dr); err != nil {
			continue
		}
		if dr.SyncedAt.IsZero() {
			continue
		} // Block pollution

		cves, _ := getCVEsForRelease(ctx, dr.ReleaseName, dr.ReleaseVersion)
		for _, ep := range dr.Endpoints {
			for _, cve := range cves {
				disclosedAfter := !cve.Published.IsZero() && cve.Published.After(dr.SyncedAt)
				lifecycle.CreateOrUpdateLifecycleRecord(ctx, dbconn, ep, dr.ReleaseName, dr.ReleaseVersion, cve, dr.SyncedAt, disclosedAfter)
			}
		}
	}
	return nil
}

func getCVEsForRelease(ctx context.Context, name, version string) (map[string]lifecycle.CVEInfo, error) {
	query := `
		FOR r IN release
			FILTER r.name == @name AND r.version == @version
			FOR cve, edge IN 1..1 OUTBOUND r release2cve
				RETURN {
					cve_id: cve.id, published: cve.published, package: edge.package_purl,
					severity_rating: cve.database_specific.severity_rating,
					severity_score: cve.database_specific.cvss_base_score
				}
	`
	cursor, _ := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"name": name, "version": version}})
	defer cursor.Close()

	result := make(map[string]lifecycle.CVEInfo)
	for cursor.HasMore() {
		var v struct {
			CveID, Published, Package, SeverityRating string
			SeverityScore                             float64
		}
		if _, err := cursor.ReadDocument(ctx, &v); err == nil {
			pub, _ := time.Parse(time.RFC3339, v.Published)
			result[v.CveID] = lifecycle.CVEInfo{CVEID: v.CveID, Package: v.Package, SeverityRating: v.SeverityRating, SeverityScore: v.SeverityScore, Published: pub}
		}
	}
	return result, nil
}

func main() { LoadFromOSVDev() }

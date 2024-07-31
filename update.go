package main

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"k8s.io/klog"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	url          = "https://pricing.api.infracost.io/data-download/latest"
	dataDir      = "./data"
	dumpFileName = "cloud-pricing.json.gz"
)

type Region string
type InstanceType string
type PurchaseOption string
type DBDeploymentOption string
type Engine string

const (
	OnDemand PurchaseOption     = "OnDemand"
	Spot     PurchaseOption     = "Spot"
	SingleAz DBDeploymentOption = "Single-AZ"
	MultiAz  DBDeploymentOption = "Multi-AZ"
)

type InstancePricing struct {
	OnDemand float64 `json:"on_demand"`
	Spot     float64 `json:"spot"`
}

type DBInstancePricing struct {
	SingleAz *InstancePricing `json:"single_az"`
	MultiAz  *InstancePricing `json:"multi_az"`
}

type StartUsageAmountGB int64

type DataTransferPricing struct {
	IngressPerGB float64 `json:"ingress_per_gb"`
	EgressPerGB  float64 `json:"egress_per_gb"`
}

type CloudPricing struct {
	Compute                 map[Region]map[InstanceType]*InstancePricing              `json:"compute"`
	ManagedDB               map[Region]map[Engine]map[InstanceType]*DBInstancePricing `json:"managed_db"`
	ManagedCache            map[Region]map[Engine]map[InstanceType]*InstancePricing   `json:"managed_cache"`
	InternetEgress          map[Region]map[StartUsageAmountGB]float64                 `json:"internet_egress"`
	IntraRegionDataTransfer map[Region]DataTransferPricing                            `json:"inter_region_data_transfer"`
}

func NewCloudPricing() *CloudPricing {
	return &CloudPricing{
		Compute:                 map[Region]map[InstanceType]*InstancePricing{},
		ManagedDB:               map[Region]map[Engine]map[InstanceType]*DBInstancePricing{},
		ManagedCache:            map[Region]map[Engine]map[InstanceType]*InstancePricing{},
		InternetEgress:          map[Region]map[StartUsageAmountGB]float64{},
		IntraRegionDataTransfer: map[Region]DataTransferPricing{},
	}
}

func (cp *CloudPricing) SetPrice(region Region, instanceType InstanceType, po PurchaseOption, price float64) {
	if region == "" {
		return
	}
	byRegion, ok := cp.Compute[region]
	if !ok {
		byRegion = map[InstanceType]*InstancePricing{}
		cp.Compute[region] = byRegion
	}
	instance := byRegion[instanceType]
	if instance == nil {
		instance = &InstancePricing{}
		byRegion[instanceType] = instance
	}
	switch po {
	case OnDemand:
		instance.OnDemand = price
	case Spot:
		instance.Spot = price
	}
}

func (cp *CloudPricing) SetIntraRegionDataTransferPrice(region Region, ingress, egress float64) {
	if region == "" {
		return
	}
	cp.IntraRegionDataTransfer[region] = DataTransferPricing{IngressPerGB: ingress, EgressPerGB: egress}
}

func (cp *CloudPricing) SetInternetEgress(region Region, pricing map[string][]map[string]string, unit string) {
	if region == "" {
		return
	}
	res := map[StartUsageAmountGB]float64{}
	for _, v := range pricing {
		for _, m := range v {
			if m["unit"] != unit {
				continue
			}
			s := m["USD"]
			if s == "" {
				continue
			}
			if p, _ := strconv.ParseFloat(s, 32); p > 0 {
				startUsageAmount, _ := strconv.ParseInt(m["startUsageAmount"], 10, 64)
				res[StartUsageAmountGB(startUsageAmount)] = p
			}
		}
	}
	if len(res) > 0 {
		cp.InternetEgress[region] = res
	}
}

func (cp *CloudPricing) SetDBPrice(region Region, engine Engine, instanceType InstanceType, do DBDeploymentOption, price float64) {
	if region == "" {
		return
	}
	byRegion, ok := cp.ManagedDB[region]
	if !ok {
		byRegion = map[Engine]map[InstanceType]*DBInstancePricing{}
		cp.ManagedDB[region] = byRegion
	}
	byEngine := byRegion[engine]
	if byEngine == nil {
		byEngine = map[InstanceType]*DBInstancePricing{}
		byRegion[engine] = map[InstanceType]*DBInstancePricing{}
	}
	instance := byEngine[instanceType]
	if instance == nil {
		instance = &DBInstancePricing{
			SingleAz: &InstancePricing{},
			MultiAz:  &InstancePricing{},
		}
		byEngine[instanceType] = instance
	}
	switch do {
	case SingleAz:
		instance.SingleAz.OnDemand = price
	case MultiAz:
		instance.MultiAz.OnDemand = price
	}
}

func (cp *CloudPricing) SetCachePrice(region Region, engine Engine, instanceType InstanceType, price float64) {
	if region == "" {
		return
	}
	byRegion, ok := cp.ManagedCache[region]
	if !ok {
		byRegion = map[Engine]map[InstanceType]*InstancePricing{}
		cp.ManagedCache[region] = byRegion
	}
	byEngine := byRegion[engine]
	if byEngine == nil {
		byEngine = map[InstanceType]*InstancePricing{}
		byRegion[engine] = map[InstanceType]*InstancePricing{}
	}
	instance := byEngine[instanceType]
	if instance == nil {
		instance = &InstancePricing{}
		byEngine[instanceType] = instance
	}
	instance.OnDemand = price
}

func (cp *CloudPricing) Stats() string {
	var regions []string
	for r, instances := range cp.Compute {
		regions = append(regions, fmt.Sprintf("%s:%d", r, len(instances)))
	}
	sort.Strings(regions)
	return strings.Join(regions, ", ")
}

type Model struct {
	AWS   *CloudPricing `json:"aws"`
	GCP   *CloudPricing `json:"gcp"`
	Azure *CloudPricing `json:"azure"`
}

func main() {
	apiKey := os.Getenv("INFRACOST_API_KEY")

	downloadUrl, err := getDownloadUrl(apiKey)
	if err != nil {
		klog.Exitln(err)
	}
	dbFile, err := os.CreateTemp("", "cloud_pricing*.csv")
	if err != nil {
		klog.Exitln(err)
	}
	defer os.Remove(dbFile.Name())
	klog.Infof("downloading DB to %s", dbFile.Name())
	if err := downloadAndDecompress(downloadUrl, dbFile); err != nil {
		klog.Exitln(err)
	}
	klog.Infoln("downloaded")
	model, err := loadModel(dbFile.Name())
	if err != nil {
		klog.Exitln(err)
	}
	klog.Infof("model:\nAWS:%s\nGCP: %s\nAzure:%s", model.AWS.Stats(), model.GCP.Stats(), model.Azure.Stats())
	if err = dumpModel(model); err != nil {
		klog.Exitln(err)
	}
	klog.Infoln("done")

}

type pricingRow struct {
	vendor        string
	region        Region
	service       string
	productFamily string
	attrs         map[string]string
	pricing       map[string][]map[string]string
}

func dumpModel(model *Model) error {
	f, err := os.CreateTemp("", "cloud-pricing.json.gz")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	gzipWriter := gzip.NewWriter(f)
	if err = json.NewEncoder(gzipWriter).Encode(model); err != nil {
		return err
	}
	if err = gzipWriter.Close(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	if _, err = os.Stat(dataDir); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(dataDir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return os.Rename(f.Name(), path.Join(dataDir, dumpFileName))
}

func loadModel(dbFile string) (*Model, error) {
	model := &Model{
		AWS:   NewCloudPricing(),
		GCP:   NewCloudPricing(),
		Azure: NewCloudPricing(),
	}
	f, err := os.Open(dbFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	if _, err = csvReader.Read(); err != nil {
		return nil, err
	}
	for {
		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		row := &pricingRow{
			vendor:        rec[2],
			region:        Region(rec[3]),
			service:       rec[4],
			productFamily: rec[5],
		}
		switch row.service {
		case "AmazonEC2", "AmazonRDS", "AmazonElastiCache", "AWSDataTransfer":
		case "Compute Engine":
		case "Virtual Machines", "Bandwidth":
		default:
			continue
		}
		if err = json.Unmarshal([]byte(rec[6]), &row.attrs); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(rec[7]), &row.pricing); err != nil {
			return nil, err
		}
		switch row.vendor {
		case "aws":
			aws(row, model.AWS)
		case "gcp":
			gcp(row, model.GCP)
		case "azure":
			azure(row, model.Azure)
		}
	}
	for region := range model.AWS.Compute {
		model.AWS.SetIntraRegionDataTransferPrice(region, 0.01, 0.01)
	}
	for region := range model.GCP.Compute {
		model.GCP.SetIntraRegionDataTransferPrice(region, 0, 0.01)
	}
	for region := range model.Azure.Compute {
		model.Azure.SetIntraRegionDataTransferPrice(region, 0, 0.)
	}
	return model, nil
}

func aws(r *pricingRow, pricing *CloudPricing) {
	instanceType := InstanceType(r.attrs["instanceType"])
	switch r.service {
	case "AWSDataTransfer":
		fromRegion := Region(r.attrs["fromRegionCode"])
		switch r.attrs["transferType"] {
		case "AWS Outbound":
			if r.attrs["fromLocationType"] != "AWS Region" {
				return
			}
			pricing.SetInternetEgress(fromRegion, r.pricing, "GB")
		}
	case "AmazonEC2":
		if instanceType == "" {
			return
		}
		if r.attrs["operatingSystem"] != "Linux" || r.attrs["preInstalledSw"] != "NA" {
			return
		}
		for _, v := range r.pricing {
			for _, m := range v {
				if m["unit"] != "Hrs" {
					continue
				}
				var po PurchaseOption
				switch m["purchaseOption"] {
				case "on_demand":
					po = OnDemand
				case "spot":
					po = Spot
				default:
					continue
				}
				p, _ := m["USD"]
				price, _ := strconv.ParseFloat(p, 64)
				if price == 0 {
					continue
				}
				pricing.SetPrice(r.region, instanceType, po, price)
			}
		}
	case "AmazonRDS":
		if instanceType == "" {
			return
		}
		var engine Engine
		switch r.attrs["databaseEngine"] {
		case "Aurora MySQL":
			engine = "aurora-mysql"
		case "MySQL":
			engine = "mysql"
		case "Aurora PostgreSQL":
			engine = "aurora-postgresql"
		case "PostgreSQL":
			engine = "postgres"
		default:
			return
		}
		var do DBDeploymentOption
		switch r.attrs["deploymentOption"] {
		case "Single-AZ":
			do = SingleAz
		case "Multi-AZ":
			do = MultiAz
		default:
			return
		}
		for _, v := range r.pricing {
			for _, m := range v {
				if m["unit"] != "Hrs" || m["purchaseOption"] != "on_demand" {
					continue
				}
				p, _ := m["USD"]
				price, _ := strconv.ParseFloat(p, 64)
				if price == 0 {
					continue
				}
				pricing.SetDBPrice(r.region, engine, instanceType, do, price)
			}
		}
	case "AmazonElastiCache":
		if instanceType == "" {
			return
		}
		var engine Engine
		switch r.attrs["cacheEngine"] {
		case "Memcached":
			engine = "memcached"
		case "Redis":
			engine = "redis"
		default:
			return
		}
		if r.attrs["locationType"] != "AWS Region" {
			return
		}
		for _, v := range r.pricing {
			for _, m := range v {
				if m["unit"] != "Hrs" || m["purchaseOption"] != "on_demand" {
					continue
				}
				p, _ := m["USD"]
				price, _ := strconv.ParseFloat(p, 64)
				if price == 0 {
					continue
				}
				pricing.SetCachePrice(r.region, engine, instanceType, price)
			}
		}
	}
}

func gcp(r *pricingRow, pricing *CloudPricing) {
	switch r.productFamily {
	case "Network":
		switch r.attrs["resourceGroup"] {
		case "StandardInternetEgress":
			pricing.SetInternetEgress(r.region, r.pricing, "gibibyte")
		}
	case "Compute Instance":
		instanceType := InstanceType(r.attrs["machineType"])
		if instanceType == "" {
			return
		}
		for _, v := range r.pricing {
			for _, m := range v {
				if m["unit"] != "Hours" {
					continue
				}
				var po PurchaseOption
				switch m["purchaseOption"] {
				case "on_demand":
					po = OnDemand
				case "preemptible":
					po = Spot
				default:
					continue
				}
				p, _ := m["USD"]
				price, _ := strconv.ParseFloat(p, 64)
				if price == 0 {
					continue
				}
				pricing.SetPrice(Region(r.region), instanceType, po, price)
			}
		}
	}
}

func azure(r *pricingRow, pricing *CloudPricing) {
	if r.region == "" {
		return
	}
	switch r.productFamily {
	case "Networking":
		if r.attrs["productName"] == "Bandwidth - Routing Preference: Internet" {
			pricing.SetInternetEgress(r.region, r.pricing, "1 GB")
		}
	case "Compute":
		instanceType := InstanceType(r.attrs["armSkuName"])
		if instanceType == "" {
			return
		}
		for _, v := range r.pricing {
			for _, m := range v {
				if m["unit"] != "1 Hour" {
					continue
				}
				var po PurchaseOption
				switch m["purchaseOption"] {
				case "Consumption":
					po = OnDemand
				case "Spot":
					po = Spot
				default:
					continue
				}
				p, _ := m["USD"]
				price, _ := strconv.ParseFloat(p, 64)
				if price == 0 {
					continue
				}
				pricing.SetPrice(Region(r.region), instanceType, po, price)
			}
		}
	}
}

func getDownloadUrl(apiKey string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Api-Key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}
	res := map[string]string{}
	err = json.NewDecoder(resp.Body).Decode(&res)
	return res["downloadUrl"], err
}

func downloadAndDecompress(url string, dest *os.File) (err error) {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = io.Copy(dest, r)
	if err != nil {
		return err
	}
	return dest.Close()
}

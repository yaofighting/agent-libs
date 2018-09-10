package compliance

import (
	"bytes"
	"cointerface/draiosproto"
	"cointerface/sdc_internal"
	"encoding/json"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"io/ioutil"
	log "github.com/cihub/seelog"
	"os/exec"
	"strings"
	"text/template"
	"time"
)

func findProcess(candidates []string) (bool) {
	for _, cand := range candidates {
		cmd := exec.Command("ps", "-C", cand)

		out, err := cmd.Output()

		log.Debugf("Output from checking %s: %s %v", cand, out, err)

		if err == nil {
			return true
		}
	}

	return false
}

func (impl *KubeBenchImpl) Variant(task *draiosproto.CompTask) (string) {

	if impl.variant != "" {
		return impl.variant
	}

	// kube-bench can either perform master or node checks,
	// depending on whether the program is running on the host
	// where the api server is running, or any other node.

	impl.variant = "none"

	// If a variant was explicitly provided, use it
	for _, param := range task.TaskParams {
		if *param.Key == "variant" {
			if *param.Val != "master" && *param.Val != "node" {
				log.Errorf("Ignoring configured variant %s, as it is not \"master\" or \"node\"", *param.Val)
			} else {
				impl.variant = *param.Val
			}
		}
	}

	if impl.variant == "none" {
		//
		// Figure out which way to run by looking for an apiserver
		// process. kube-bench requires additional services such as
		// the scheduler, etcd, etc to be running on the master, but
		// at this level we only need to distinguish between master
		// and node versions.

		servercmds := []string{"kube-apiserver", "hyperkube apiserver", "apiserver"}
		if findProcess(servercmds) {
			impl.variant = "master"
		} else {
			nodecmds := []string{"hyperkube kubelet", "kubelet"}
			if findProcess(nodecmds) {
				impl.variant = "node"
			}
		}
	}

	log.Debugf("Variant %s", impl.variant);
	return impl.variant
}

func (impl *KubeBenchImpl) GenArgs(task *draiosproto.CompTask) ([]string, error) {
	return []string{"--json", impl.Variant(task)}, nil
}

func (impl *KubeBenchImpl) ShouldRun(task *draiosproto.CompTask) (bool, error) {

	return (impl.Variant(task) != "none"), nil
}

type KubeBenchImpl struct {
	customerId string `json:"customerId"`
	machineId string `json:"machineId"`
	variant string `json:"variant"`
}

type kubeTestResult struct {
	TestNumber string `json:"test_number"`
	TestDesc string `json:"test_desc"`
	Type string `json:"type"`
	TestInfo []string `json:"test_info"`
	Status string `json:"status"`
}

type kubeTestSection struct {
	Section string `json:"section"`
	Pass uint64 `json:"pass"`
	Fail uint64 `json:"fail"`
	Warn uint64 `json:"warn"`
	Desc string `json:"desc"`
	Results []kubeTestResult `json:"results"`
}

type kubeBenchResults struct {
	Id string `json:"id"`
	Version string `json:"version"`
	Text string `json:"text"`
	NodeType string `json:"node_type"`
	Tests []kubeTestSection `json:"tests"`
	TotalPass uint64 `json:"total_pass"`
	TotalFail uint64 `json:"total_fail"`
	TotalWarn uint64 `json:"total_warn"`
}

type kubeOutputSection struct {
	Section string `json:"section"`
	Total uint64 `json:"total"`
	Pass uint64 `json:"pass"`
	Fail uint64 `json:"fail"`
	Warn uint64 `json:"warn"`
	PassTestIds []string `json:"passTestIds,omitempty"`
	FailTestIds []string `json:"failTestIds,omitempty"`
	WarnTestIds []string `json:"warnTestIds,omitempty"`
}

type kubeOutputFields struct {
	Version string `json:"version"`
	NodeType string `json:"nodeType"`
	Total uint64 `json:"total"`
	Pass uint64 `json:"pass"`
	Fail uint64 `json:"fail"`
	Warn uint64 `json:"warn"`
	Tests []kubeOutputSection `json:"tests"`
}

// Given a test id, result, and current risk, assign a new risk based
// on the result of the test.
// The risk defaults to low and becomes medium/high if:
// - medium: any test has a WARN or FAIL result
// - high: any of the following tests has a non-PASS result:
//     - 1.1.5-8 (Insecure kubelet api access)
//     - 1.1.11 (Allow all images unconditionally)
//     - 1.1.22 (Ensure that the --kubelet-certificate-authority argument is set as appropriate)
//     - 1.1.29 (Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate)
//     - 1.1.30 (Ensure that the --client-ca-file argument is set as appropriate)
//     - 1.3.3 (Ensure that the --insecure-experimental-approve-all-kubelet-csrs-for-group argument is not set)
//     - 2.1.2 (Ensure that the --anonymous-auth argument is set to false (Scored))
//     - 2.1.3 (Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored))
//     - 2.1.4 (Ensure that the --client-ca-file argument is set as appropriate (Scored))
//     - 2.1.12 (Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Scored))
//     - Anything in 1.4 or 2.2
func (impl *KubeBenchImpl) AssignRisk(id string, result string, curRisk string) string {
	newRisk := "low"

	highTestIds := map[string]int {
		"1.1.5": 1,
		"1.1.6": 1,
		"1.1.7": 1,
		"1.1.8": 1,
		"1.1.11": 1,
		"1.1.22": 1,
		"1.1.29": 1,
		"1.1.30": 1,
		"1.3.3": 1,
		"2.1.2": 1,
		"2.1.3": 1,
		"2.1.4": 1,
		"2.1.12": 1,
	}

	if (result != "PASS" &&
		((highTestIds[id] == 1 || strings.HasPrefix(id, "1.4")) ||
		(highTestIds[id] == 2 || strings.HasPrefix(id, "2.2")))) {
		newRisk = "high"
	} else if (result != "PASS") {
		newRisk = "medium"
	}

	if (newRisk == "high" || (newRisk == "medium" && curRisk == "low")) {
		return newRisk
	}

	return curRisk
}

func (impl *KubeBenchImpl) Scrape(rootPath string, moduleName string,
	task *draiosproto.CompTask,
	evtsChannel chan *sdc_internal.CompTaskEvent,
	metricsChannel chan string) error {

	evt := &sdc_internal.CompTaskEvent{
		TaskName: proto.String(moduleName),
		Successful: proto.Bool(true),
	}
	cevts := &draiosproto.CompEvents{
		MachineId: proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}
	results := &draiosproto.CompResults{
		MachineId: proto.String(impl.machineId),
		CustomerId: proto.String(impl.customerId),
	}

	metrics := []string{}

	// Read kube-bench's stdout, which contains the test results as json
	raw, err := ioutil.ReadFile(rootPath + "/stdout.txt")
	if err != nil {
		log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	var bres kubeBenchResults
	err = json.Unmarshal(raw, &bres)

	if err != nil {
		log.Errorf("Could not read json output: %v", err.Error())
		return err
	}

	output_fields := &kubeOutputFields{
		Version: bres.Version,
		NodeType: bres.NodeType,
		Total: bres.TotalPass + bres.TotalFail + bres.TotalWarn,
		Pass: bres.TotalPass,
		Fail: bres.TotalFail,
		Warn: bres.TotalWarn,
	}

	curRisk := "low"

	timestamp_ns := uint64(time.Now().UnixNano())

	for _, section := range bres.Tests {

		output_section := &kubeOutputSection {
			Section: section.Section,
			Total: section.Pass + section.Fail + section.Warn,
			Pass: section.Pass,
			Fail: section.Fail,
			Warn: section.Warn,
		}

		metrics_prefix := fmt.Sprintf("compliance.k8s-bench.%v.%v", section.Section, strings.ToLower(strings.Replace(section.Desc, " ", "-", -1)))
		metrics = append(metrics, fmt.Sprintf("%v.tests_fail:%d|g", metrics_prefix, output_section.Fail))
		metrics = append(metrics, fmt.Sprintf("%v.tests_warn:%d|g", metrics_prefix, output_section.Warn))
		metrics = append(metrics, fmt.Sprintf("%v.tests_pass:%d|g", metrics_prefix, output_section.Pass))
		metrics = append(metrics, fmt.Sprintf("%v.tests_total:%d|g", metrics_prefix, output_section.Total))
		metrics = append(metrics, fmt.Sprintf("%v.pass_pct:%f|g", metrics_prefix, (100.0*float64(output_section.Pass)) / float64(output_section.Total)))

		for _, result := range section.Results {

			curRisk = impl.AssignRisk(result.TestNumber, result.Status, curRisk)

			if result.Status != "PASS" {

				fields := map[string]string{
					"Task": moduleName,
					"SectionDesc": section.Desc,
					"TestId": result.TestNumber,
					"TestDesc": result.TestDesc,
					"TestResult": result.Status,
					"falco.rule": "compliance_modules",
				}
				tmplstr := "Compliance task \"{{.Task}}\" test {{.SectionDesc}}/{{.TestId}} ({{.TestDesc}}) result: {{.TestResult}}."
				tmpl, err := template.New("test").Parse(tmplstr)
				if err != nil {
					log.Errorf("Could not format output string: %v", err.Error())
					return err
				}
				var outputString bytes.Buffer
				err = tmpl.Execute(&outputString, fields)
				if err != nil {
					log.Errorf("Could not format output string: %v", err.Error())
					return err
				}

				// XXX/mstemm this needs to change pending expanded event stream work.
				if false {
					cevt := &draiosproto.CompEvent{
						TimestampNs: proto.Uint64(timestamp_ns),
						TaskName: proto.String(*task.Name),
						Output: proto.String(outputString.String()),
						OutputFields: fields,
					};

					cevts.Events = append(cevts.Events, cevt);
				}

				if result.Status == "WARN" {
					output_section.WarnTestIds = append(output_section.WarnTestIds, result.TestNumber)
				} else {
					output_section.FailTestIds = append(output_section.FailTestIds, result.TestNumber)
				}
			} else {
				output_section.PassTestIds = append(output_section.PassTestIds, result.TestNumber)
			}
		}
		output_fields.Tests = append(output_fields.Tests, *output_section)
	}

	ofbytes, err := json.Marshal(output_fields); if err != nil {
		log.Errorf("Could not serialize output fields: %v", err.Error())
		return err
	}

	result := &draiosproto.CompResult{
		TimestampNs: proto.Uint64(timestamp_ns),
		TaskName: proto.String(*task.Name),
		TestsRun: proto.Uint32(uint32(output_fields.Pass + output_fields.Fail)),
		TestsPassed: proto.Uint32(uint32(output_fields.Pass)),
		OutputFields: proto.String(string(ofbytes[:])),
		Risk: proto.String(curRisk),
	};

	results.Results = append(results.Results, result)

	evt.Events = cevts
	evt.Results = results

	log.Debugf("Sending kube-bench comp_evt: %v", evt)
	evtsChannel <- evt

	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_pass:%d|g", output_fields.Pass))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_fail:%d|g", output_fields.Fail))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_warn:%d|g", output_fields.Warn))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.tests_total:%d|g", output_fields.Total))
	metrics = append(metrics, fmt.Sprintf("compliance.k8s-bench.pass_pct:%f|g", (100.0*float64(output_fields.Pass)) / float64(output_fields.Total)))

	for _, metric := range metrics {
		log.Debugf("Sending kube-bench metric: %v", metric)
		metricsChannel <- metric
	}

	return nil
}

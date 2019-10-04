package converter

import (
	"bytes"

	"fmt"

	"encoding/json"

	log "github.com/sirupsen/logrus"
	"github.com/ghodss/yaml"

	"k8s.io/api/extensions/v1beta1"

	"strconv"
	"strings"

	"text/template"

	v1 "k8s.io/api/core/v1"
)

type Converter struct{
	pspTmpl *template.Template
}

func joinProcMountTypes(procMountTypes []v1.ProcMountType) string {
	var sb strings.Builder

	for  idx, procMountType := range procMountTypes {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(procMountType))
	}

	return sb.String()
}

func joinCapabilities(capabilities []v1.Capability) string {
	var sb strings.Builder

	for  idx, cap := range capabilities {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(cap))
	}

	return sb.String()
}

func joinFSTypes(fsTypes []v1beta1.FSType) string {
	var sb strings.Builder

	for  idx, fsType := range fsTypes {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(fsType))
	}

	return sb.String()
}

func joinIDRanges(ranges []v1beta1.IDRange) string {

	var sb strings.Builder

	for idx, idRange := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("\"")
		sb.WriteString(strconv.Itoa(int(idRange.Min)))
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(int(idRange.Max)))
		sb.WriteString("\"")
	}

	return sb.String()
}

func joinHostPortRanges(ranges []v1beta1.HostPortRange) string {

	var sb strings.Builder

	for  idx, portRange := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("\"")
		sb.WriteString(strconv.Itoa(int(portRange.Min)))
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(int(portRange.Max)))
		sb.WriteString("\"")
	}

	return sb.String()
}

func joinHostPaths(ranges []v1beta1.AllowedHostPath) string {

	var sb strings.Builder

	for  idx, path := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(path.PathPrefix)
	}

	return sb.String()
}

func joinFlexvolumes(ranges []v1beta1.AllowedFlexVolume) string {

	var sb strings.Builder

	for  idx, path := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(path.Driver)
	}

	return sb.String()
}

func allowPrivilegeEscalation(spec v1beta1.PodSecurityPolicySpec) bool {
	if spec.AllowPrivilegeEscalation != nil {
		return *spec.AllowPrivilegeEscalation
	}

	return true
}

func NewConverter() (*Converter, error) {

	tmpl := template.New("pspRules")

	tmpl = tmpl.Funcs(template.FuncMap{
		"JoinProcMountTypes": joinProcMountTypes,
		"JoinCapabilities": joinCapabilities,
		"JoinFSTypes": joinFSTypes,
		"JoinIDRanges": joinIDRanges,
		"JoinHostPortRanges": joinHostPortRanges,
		"JoinHostPaths": joinHostPaths,
		"JoinFlexvolumes": joinFlexvolumes,
		"AllowPrivilegeEscalation": allowPrivilegeEscalation,
	})

	tmpl, err := tmpl.Parse(K8sPspRulesTemplate)

	if err != nil {
		return nil, fmt.Errorf("Could not create rules template: %v", err)
	}

	return &Converter{
		pspTmpl: tmpl,
	}, nil
}

func (c *Converter) GenerateRules(pspString string) (string, error) {

	psp := v1beta1.PodSecurityPolicy{}

	log.Debugf("GenerateRules() pspString=%s", pspString)

	pspJson, err := yaml.YAMLToJSON([]byte(pspString)); if err != nil {
		return "", fmt.Errorf("Could not convert generic yaml document to json: %v", err)
	}

	err = json.Unmarshal(pspJson, &psp)

	log.Debugf("PSP Object: %v", psp)

	// The generated rules need a set of images for which
	// to scope the rules. A annotation with the key
	// "falco-rules-psp-images" provides the list of images.
	if _, ok := psp.Annotations["falco-rules-psp-images"]; !ok {
		return "", fmt.Errorf("PSP Yaml Document does not have an annotation \"falco-rules-psp-images\" that lists the images for which the generated rules should apply");
	}

	log.Debugf("Images %v", psp.Annotations["falco-rules-psp-images"])

	var rulesB bytes.Buffer

	err = c.pspTmpl.Execute(&rulesB, psp)

	if err != nil {
		return "", fmt.Errorf("Could not convert PSP to Falco Rules: %v", err)
	}

	log.Debugf("Resulting rules: %s", rulesB.String())

	return rulesB.String(), nil
}

package main

import (
	"flag"
	"io/ioutil"

	"github.com/falcosecurity/falco/psp_conv/converter"
	log "github.com/sirupsen/logrus"
	"os"
)

func main() {

	pspPath := flag.String("psp", "", "Path to PSP as yaml file")
	rulesPath := flag.String("rules", "./psp_falco_rules.yaml", "Write converted rules to this file")
	logLevel := flag.String("level", "info", "Log level")

	flag.Parse()

	if *pspPath == "" || *rulesPath == "" {
		flag.PrintDefaults()
		return
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	lvl, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatal(err)
	}

	log.SetLevel(lvl)

	pspFile, err := os.Open(*pspPath)
	if err != nil {
		log.Fatal(err)
	}
	defer pspFile.Close()

	log.Debugf("Reading PSP from %s", *pspPath)

	psp, err := ioutil.ReadAll(pspFile)

	conv, err := converter.NewConverter()

	if err != nil {
		log.Fatalf("Could not create converter: %v", err)
	}

	rules, err := conv.GenerateRules(string(psp))
	if err != nil {
		log.Fatalf("Could not convert psp file to falco rules: %v", err)
	}

	err = ioutil.WriteFile(*rulesPath, []byte(rules), 0644)

	log.Debugf("Wrote rules to %s", *rulesPath)
}

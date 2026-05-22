package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

func parseFlags() (string, string) {
	ip := flag.String("ip", "", "Target IP")
	ports := flag.String("ports", "", "Target port")
	flag.Parse()
	return *ip, *ports
}
func watch(ip, ports string) (*nmap.Scanner, error) {
	return nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(ports),
		nmap.WithServiceInfo(),
		nmap.WithOSDetection(),
		nmap.WithScripts("vuln", "vulners", "http-enum", "dns-brute", "exploit", "auth"),
	)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ip, ports := parseFlags()

	scanner, err := watch(ip, ports)
	if err != nil {
		log.Fatalf("creating scanner: %v", err)
	}
	result, err := scanner.Run(ctx)
	if err != nil {
		log.Fatalf("running network scan: %v", err)
	}

	err = result.ToFile("scanner.xml")
	if err != nil {
		log.Fatalf("failed %v", err)
	}

	warnings := result.Warnings()
	if len(warnings) > 0 {
		log.Printf("warning: %v\n", warnings)
	}
	scan := fmt.Sprintf("report-%s.html", time.Now().Format("2006-01-02 15:04:05"))
	cmd := exec.Command("xsltproc", "-o", scan, "nmap-bootstrap.xsl", "scanner.xml")
	err = cmd.Run()
	if err != nil {
		log.Printf("xlstproc failed %v", err)
	}

	cmd2 := exec.Command("xdg-open", scan)
	err = cmd2.Run()
	if err != nil {
		log.Printf("error opening report %v", err)
	}
}

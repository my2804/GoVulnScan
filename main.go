// Usage:
//   go run . scan   -ip <target> [-ports <ports>] [-depth quick|normal|deep] [-timeout <duration>]

//
// Examples:
//   go run . scan -ip 10.189.98.80 -depth deep -timeout 30m
//   go run . scan -ip 10.176.8.51 -depth deep -ports 53 -timeout 5m
//   go run . scan -ip 192.168.1.0/24 -depth quick

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v4"
)

type depthConfig struct {
	scripts          []string
	timing           int
	versionIntensity int
	fullPortRange    bool
	retryFiltered    bool
	description      string
}

var depthPresets = map[string]depthConfig{
	"quick": {
		scripts:          []string{"default"},
		timing:           3,
		versionIntensity: 5,
		fullPortRange:    false,
		retryFiltered:    false,
		description:      "default scripts, default port range, no retries",
	},
	"normal": {
		scripts:          []string{"default", "vuln"},
		timing:           3,
		versionIntensity: 7,
		fullPortRange:    false,
		retryFiltered:    true,
		description:      "default+vuln scripts, default port range, retries ambiguous ports",
	},
	"deep": {
		scripts:          []string{"vuln", "vulners", "http-enum", "dns-brute", "exploit", "auth"},
		timing:           2,
		versionIntensity: 9,
		fullPortRange:    true,
		retryFiltered:    true,
		description:      "full script set, ALL 65535 ports, max version intensity, retries filtered ports",
	},
}

func validDepths() string {
	names := make([]string, 0, len(depthPresets))
	for k := range depthPresets {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

var portListRe = regexp.MustCompile(`^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$`)

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if ip := net.ParseIP(target); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}
	if strings.ContainsAny(target, " \t\n;|&$`<>()") {
		return fmt.Errorf("invalid target %q: contains disallowed characters", target)
	}
	if _, err := net.LookupHost(target); err != nil {
		return fmt.Errorf("invalid target %q: not an IP/CIDR and does not resolve: %w", target, err)
	}
	return nil
}

func validatePorts(ports string) error {
	if ports == "" {
		return nil
	}
	if !portListRe.MatchString(ports) {
		return fmt.Errorf("invalid port spec %q: expected e.g. \"80\", \"80,443\", or \"1-1000\"", ports)
	}
	for _, part := range strings.Split(ports, ",") {
		bounds := strings.SplitN(part, "-", 2)
		var lo, hi int
		if _, err := fmt.Sscanf(bounds[0], "%d", &lo); err != nil || lo < 1 || lo > 65535 {
			return fmt.Errorf("invalid port value %q: must be between 1 and 65535", bounds[0])
		}
		hi = lo
		if len(bounds) == 2 {
			if _, err := fmt.Sscanf(bounds[1], "%d", &hi); err != nil || hi < 1 || hi > 65535 {
				return fmt.Errorf("invalid port value %q: must be between 1 and 65535", bounds[1])
			}
			if hi < lo {
				return fmt.Errorf("invalid port range %q: end must be >= start", part)
			}
		}
	}
	return nil
}

func validateDepth(depth string) error {
	if _, ok := depthPresets[depth]; !ok {
		return fmt.Errorf("invalid depth %q: must be one of [%s]", depth, validDepths())
	}
	return nil
}

func validateTimeout(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("timeout must be positive, got %s", d)
	}
	if d < 30*time.Second {
		return fmt.Errorf("timeout %s is unreasonably short for a network scan (min 30s)", d)
	}
	return nil
}

func requireBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("required binary %q not found in PATH: %w", name, err)
	}
	return nil
}

func buildScanner(ip, ports string, cfg depthConfig) (*nmap.Scanner, error) {
	opts := []nmap.Option{
		nmap.WithTargets(ip),
		nmap.WithServiceInfo(),
		nmap.WithVersionIntensity(int16(cfg.versionIntensity)),
		nmap.WithOSDetection(),
		nmap.WithTimingTemplate(nmap.Timing(cfg.timing)),
		nmap.WithScripts(cfg.scripts...),
	}

	switch {
	case ports != "":
		opts = append(opts, nmap.WithPorts(ports))
	case cfg.fullPortRange:
		opts = append(opts, nmap.WithPorts("1-65535"))
	}

	return nmap.NewScanner(opts...)
}

func retryFilteredPorts(ctx context.Context, ip string, result *nmap.Run) {
	var suspect []string
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "filtered" && strings.Contains(port.State.Reason, "no-response") {
				suspect = append(suspect, fmt.Sprintf("%d", port.ID))
			}
		}
	}
	if len(suspect) == 0 {
		return
	}

	log.Printf("retry: %d port(s) came back filtered/no-response, re-probing at slower timing: %s",
		len(suspect), strings.Join(suspect, ","))

	retryScanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(strings.Join(suspect, ",")),
		nmap.WithTimingTemplate(nmap.Timing(1)),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		log.Printf("retry: failed to build retry scanner: %v", err)
		return
	}

	retryResult, err := retryScanner.Run(ctx)
	if err != nil {
		log.Printf("retry: re-scan failed: %v", err)
		return
	}

	for _, host := range retryResult.Hosts {
		for _, port := range host.Ports {
			log.Printf("retry result: port %d/%s -> %s (%s) service=%s",
				port.ID, port.Protocol, port.State.State, port.State.Reason, port.Service.Name)
		}
	}
	log.Printf("retry: results above are informational only — main report reflects the initial pass")
}

func runScan(ip, ports, depth, xmlOut string, timeout time.Duration) error {
	if err := validateTarget(ip); err != nil {
		return err
	}
	if err := validatePorts(ports); err != nil {
		return err
	}
	if err := validateDepth(depth); err != nil {
		return err
	}
	if err := validateTimeout(timeout); err != nil {
		return err
	}

	cfg := depthPresets[depth]
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	scanner, err := buildScanner(ip, ports, cfg)
	if err != nil {
		return fmt.Errorf("creating scanner: %w", err)
	}

	portDesc := "default nmap port range"
	switch {
	case ports != "":
		portDesc = fmt.Sprintf("ports %s (user-specified)", ports)
	case cfg.fullPortRange:
		portDesc = "all 65535 ports"
	}

	log.Printf("scanning %s (depth=%s, scripts=%v, timing=T%d, version-intensity=%d, %s)",
		ip, depth, cfg.scripts, cfg.timing, cfg.versionIntensity, portDesc)

	result, err := scanner.Run(ctx)
	if err != nil {
		return fmt.Errorf("running network scan: %w", err)
	}

	if warnings := result.Warnings(); len(warnings) > 0 {
		log.Printf("warnings: %v", warnings)
	}

	if cfg.retryFiltered {
		retryFilteredPorts(ctx, ip, result)
	}

	if err := result.ToFile(xmlOut); err != nil {
		return fmt.Errorf("writing xml output: %w", err)
	}

	fmt.Printf("scan complete: %s\n", xmlOut)
	return nil
}

func generateReport(xmlPath, xslPath string, open bool) (string, error) {
	if _, err := os.Stat(xmlPath); err != nil {
		return "", fmt.Errorf("xml input %q not found: %w", xmlPath, err)
	}
	if _, err := os.Stat(xslPath); err != nil {
		return "", fmt.Errorf("xsl stylesheet %q not found: %w", xslPath, err)
	}
	if err := requireBinary("xsltproc"); err != nil {
		return "", err
	}

	out := fmt.Sprintf("report-%s.html", time.Now().Format("2006-01-02T15-04-05"))
	cmd := exec.Command("xsltproc", "-o", out, xslPath, xmlPath)
	if combinedOutput, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("xsltproc failed: %w (output: %s)", err, strings.TrimSpace(string(combinedOutput)))
	}

	if open {
		if err := requireBinary("xdg-open"); err != nil {
			log.Printf("report generated but could not auto-open: %v", err)
			return out, nil
		}
		if err := exec.Command("xdg-open", out).Run(); err != nil {
			log.Printf("error opening report: %v", err)
		}
	}

	return out, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  %s scan   -ip <target> [-ports <ports>] [-depth quick|normal|deep] [-timeout <duration>]
  %s report -xml <file> [-xsl <file>] [-open]

Subcommands:
  scan    Run an nmap scan and generate an HTML report
  report  Regenerate an HTML report from an existing scan XML file

Depth presets:
`, os.Args[0], os.Args[0])
	for name, cfg := range depthPresets {
		fmt.Fprintf(os.Stderr, "  %-8s %s\n", name, cfg.description)
	}
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	ip := fs.String("ip", "", "Target IP, CIDR, or hostname (required)")
	ports := fs.String("ports", "", "Target ports, e.g. \"80,443\" or \"1-1000\" (overrides depth's port range if set)")
	depth := fs.String("depth", "normal", "Scan depth: "+validDepths())
	xslPath := fs.String("xsl", "nmap-bootstrap.xsl", "Path to XSL stylesheet for HTML report")
	timeout := fs.Duration("timeout", 5*time.Minute, "Scan timeout (deep scans should use longer, e.g. 30m)")
	open := fs.Bool("open", true, "Open the HTML report when done")
	fs.Parse(args)

	if *ip == "" {
		fs.Usage()
		return fmt.Errorf("-ip is required")
	}

	xmlOut := "scanner.xml"
	if err := runScan(*ip, *ports, *depth, xmlOut, *timeout); err != nil {
		return err
	}

	report, err := generateReport(xmlOut, *xslPath, *open)
	if err != nil {
		return err
	}
	fmt.Printf("report written to %s\n", report)
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	xmlPath := fs.String("xml", "scanner.xml", "Path to existing scan XML file")
	xslPath := fs.String("xsl", "nmap-bootstrap.xsl", "Path to XSL stylesheet")
	open := fs.Bool("open", true, "Open the HTML report when done")
	fs.Parse(args)

	report, err := generateReport(*xmlPath, *xslPath, *open)
	if err != nil {
		return err
	}
	fmt.Printf("report written to %s\n", report)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

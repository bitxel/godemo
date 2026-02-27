package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var verbose bool

type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func logInfo(format string, args ...any) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, ts+" [godemo] "+format+"\n", args...)
}

func logError(format string, args ...any) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, ts+" [godemo] ERROR "+format+"\n", args...)
}

func logWarn(format string, args ...any) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, ts+" [godemo] WARN "+format+"\n", args...)
}

func logDebug(format string, args ...any) {
	if verbose {
		ts := time.Now().Format("15:04:05")
		fmt.Fprintf(os.Stderr, ts+" [godemo] DEBUG "+format+"\n", args...)
	}
}

const defaultGatewayURL = "https://godemo.0x0f.me"

func main() {
	gatewayFlag := flag.String("gateway", "", "Gateway URL (default: $GODEMO_GATEWAY_URL or "+defaultGatewayURL+")")
	flag.StringVar(gatewayFlag, "g", "", "Gateway URL (shorthand)")
	hostFlag := flag.String("host", "127.0.0.1", "Local bind host")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	flag.BoolVar(verboseFlag, "v", false, "Enable verbose logging (shorthand)")
	var allowPaths multiFlag
	flag.Var(&allowPaths, "allow-path", "Only allow requests to this path prefix (repeatable)")


	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: godemo-client [flags] <port>\n\n")
		fmt.Fprintf(os.Stderr, "Expose a local port to the internet via Godemo gateway.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	verbose = *verboseFlag

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: port argument is required")
		flag.Usage()
		os.Exit(1)
	}

	port, err := strconv.Atoi(flag.Arg(0))
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Error: invalid port %q\n", flag.Arg(0))
		os.Exit(1)
	}

	gatewayURL := *gatewayFlag
	if gatewayURL == "" {
		gatewayURL = os.Getenv("GODEMO_GATEWAY_URL")
	}
	if gatewayURL == "" {
		gatewayURL = defaultGatewayURL
	}
	gatewayURL = strings.TrimRight(gatewayURL, "/")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t := newTunnel(gatewayURL, *hostFlag, port)
	if len(allowPaths) > 0 {
		t.allowedPaths = allowPaths
	}

	if err := t.createSession(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := t.connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		t.deleteSession()
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "\n  godemo tunnel active\n\n")
	fmt.Fprintf(os.Stdout, "  Public URL:  %s\n", t.publicURL)
	fmt.Fprintf(os.Stdout, "  Forwarding:  %s:%d\n", *hostFlag, port)
	if len(allowPaths) > 0 {
		fmt.Fprintf(os.Stdout, "  Allowed:     %s\n", strings.Join(allowPaths, ", "))
	}
	fmt.Fprintf(os.Stdout, "\n  Press Ctrl+C to stop.\n\n")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	doneCh := make(chan struct{})
	go func() {
		t.runWithReconnect(ctx)
		close(doneCh)
	}()

	select {
	case <-sigCh:
		fmt.Fprintln(os.Stdout, "\n  Shutting down...")
		cancel()
		t.close()
	case <-doneCh:
		t.close()
	}
}

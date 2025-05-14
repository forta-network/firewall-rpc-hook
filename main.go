package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/forta-network/forta-core-go/domain"
	"github.com/forta-network/forta-core-go/ethereum"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

// Config holds all configuration for the application
type Config struct {
	Port         string        `envconfig:"PORT" default:"8080"`
	SequencerURL string        `envconfig:"SEQUENCER_RPC_URL" required:"true"`
	TraceURL     string        `envconfig:"TRACE_RPC_URL"`
	FirewallURL  string        `envconfig:"FIREWALL_API_URL" required:"true"`
	Timeout      time.Duration `envconfig:"TIMEOUT" default:"30s"`
	LogLevel     string        `envconfig:"LOG_LEVEL" default:"info"`
}

// RPCHook holds the application state and dependencies
type RPCHook struct {
	cfg         *Config
	sequencer   ethereum.Client
	traceClient ethereum.Client
}

// NewRPCHook creates a new application instance with initialized clients
func NewRPCHook(cfg *Config) (*RPCHook, error) {
	// Initialize sequencer client
	sequencer, err := ethereum.NewStreamEthClient(context.Background(), "sequencer", cfg.SequencerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create sequencer client: %v", err)
	}

	// Initialize trace client (use sequencer URL if trace URL is not set)
	traceURL := cfg.TraceURL
	if traceURL == "" {
		traceURL = cfg.SequencerURL
	}
	traceClient, err := ethereum.NewStreamEthClient(context.Background(), "trace", traceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace client: %v", err)
	}

	return &RPCHook{
		cfg:         cfg,
		sequencer:   sequencer,
		traceClient: traceClient,
	}, nil
}

// JSONRPCRequest models a generic JSON-RPC request
type JSONRPCRequest struct {
	Method string          `json:"method"`
	Params []string        `json:"params"`
	ID     json.RawMessage `json:"id"`
}

type TracedCall struct {
	From     common.Address  `json:"from"`
	To       common.Address  `json:"to"`
	CallType string          `json:"type"`
	GasUsed  *hexutil.Big    `json:"gasUsed"`
	Input    string          `json:"input"`
	Output   string          `json:"output"`
	Error    string          `json:"error"`
	Calls    []*TracedCall   `json:"calls"`
	Logs     []*TracedLog    `json:"logs"`
	Raw      json.RawMessage `json:"-"`
	Value    *hexutil.Big    `json:"value"`
}

type TracedLog struct {
	Index   int            `json:"index"`
	Address common.Address `json:"address"`
	Topics  []string       `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

// ScreenRequest represents the payload sent to the Firewall API
type ScreenRequest struct {
	RawTransaction string      `json:"rawTransaction"`
	BlockNumber    uint64      `json:"blockNumber"`
	Traces         *TracedCall `json:"traces,omitempty"`
}

// doDebugTraceCall simulates calling `debug_traceCall` with a callTracer
func (hook *RPCHook) doDebugTraceCall(ctx context.Context, tx *types.Transaction) (json.RawMessage, uint64, error) {
	// Get latest block number
	blockNumber, err := hook.traceClient.BlockNumber(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get block number: %v", err)
	}

	// always non-nil but in case of legacy tx it will be 0
	chainId := tx.ChainId()
	if chainId.Cmp(big.NewInt(0)) == 0 {
		return nil, 0, fmt.Errorf("failed to get chain id")
	}

	signer := types.NewLondonSigner(chainId)
	from, err := signer.Sender(tx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get sender: %v", err)
	}

	var value hexutil.Big
	if tx.Value() != nil {
		value = hexutil.Big(*tx.Value())
	}

	var result json.RawMessage

	err = hook.traceClient.DebugTraceCall(ctx,
		&domain.TraceCallTransaction{
			From:  from.String(),
			To:    tx.To().String(),
			Data:  hexutil.Encode(tx.Data()),
			Value: &value,
		},
		"latest",
		domain.TraceCallConfig{
			Tracer: "callTracer",
			TracerConfig: &domain.TracerConfig{
				WithLog: true,
			},
		}, &result)

	return result, blockNumber.Uint64(), err
}

// screenWithFortaAPI sends the transaction data + traces to Firewall API
// Returns (true, nil) if screening is 200 OK, otherwise (false, error).
func screenWithFortaAPI(ctx context.Context, rawTransaction string, traceData json.RawMessage, blockNumber uint64, firewallURL string) (bool, error) {
	// Parse the trace data into TracedCall
	var tracedCall TracedCall
	if err := json.Unmarshal(traceData, &tracedCall); err != nil {
		return false, fmt.Errorf("failed to unmarshal trace data: %v", err)
	}

	// Build the request structure
	payload := ScreenRequest{
		RawTransaction: rawTransaction,
		BlockNumber:    blockNumber,
		Traces:         &tracedCall,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", firewallURL, bytes.NewReader(b))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	logrus.Warnf("Forta screening returned status %d: %s", resp.StatusCode, string(bodyBytes))
	return false, nil
}

// forwardAndRespond forwards the raw JSON-RPC request to sequencer
// and writes the response back to the client.
func (hook *RPCHook) forwardAndRespond(ctx context.Context, w http.ResponseWriter, requestBody []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.cfg.SequencerURL, bytes.NewReader(requestBody))
	if err != nil {
		logrus.Errorf("Error creating request to sequencer: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Error forwarding request to sequencer: %v", err)
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handler returns an HTTP handler for the application
func (hook *RPCHook) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), hook.cfg.Timeout)
		defer cancel()

		// Read the body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			logrus.Errorf("Error reading request body: %v", err)
			http.Error(w, "Cannot read request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Parse the JSON-RPC request
		var rpcReq JSONRPCRequest
		if err := json.Unmarshal(body, &rpcReq); err != nil {
			logrus.Errorf("Error unmarshaling request body into JSONRPCRequest: %v", err)
			http.Error(w, "Invalid JSON-RPC", http.StatusBadRequest)
			return
		}

		// If it's not eth_sendRawTransaction, you might choose to forward it directly
		if rpcReq.Method != "eth_sendRawTransaction" {
			logrus.Debug("Forwarding non-eth_sendRawTransaction request to sequencer")
			hook.forwardAndRespond(ctx, w, body)
			return
		}

		if len(rpcReq.Params) != 1 {
			http.Error(w, "Invalid JSON-RPC", http.StatusBadRequest)
			return
		}

		logrus.Debug("Intercepted eth_sendRawTransaction")

		rawTransaction := rpcReq.Params[0]
		// Decode the transaction parameters
		txBytes, err := hexutil.Decode(rawTransaction)
		if err != nil {
			http.Error(w, "Invalid JSON-RPC", http.StatusBadRequest)
			return
		}

		tx := &types.Transaction{}
		err = tx.UnmarshalBinary(txBytes)
		if err != nil {
			http.Error(w, "Invalid JSON-RPC", http.StatusBadRequest)
			return
		}

		// 1) Do debug_traceCall to get call traces
		traceData, blockNumber, err := hook.doDebugTraceCall(ctx, tx)
		if err != nil {
			logrus.Errorf("Error calling debug_traceCall: %v", err)
			http.Error(w, "Failed to get traces", http.StatusInternalServerError)
			return
		}

		// 2) Send request (raw transaction data + traces) to Firewall API
		ok, err := screenWithFortaAPI(ctx, rawTransaction, traceData, blockNumber, hook.cfg.FirewallURL)
		if err != nil {
			logrus.Errorf("Error screening with Forta API: %v", err)
			http.Error(w, "Failed to screen transaction", http.StatusInternalServerError)
			return
		}

		// If Firewall API doesn't return 200, stop here (or handle as you like)
		if !ok {
			logrus.Warn("Forta screening did not return 200. Blocking transaction.")
			// Return an error, or custom JSON-RPC response
			http.Error(w, "Transaction blocked by screening", http.StatusForbidden)
			return
		}

		// If everything is good, forward the original request to sequencer
		logrus.Info("Forta screening returned 200. Forwarding transaction to sequencer.")
		hook.forwardAndRespond(ctx, w, body)
	}
}

func main() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		logrus.Debug("No .env file found, using environment variables")
	}

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		logrus.Fatalf("Failed to process config: %v", err)
	}

	// Configure logrus
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.Fatalf("Invalid log level: %v", err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Initialize application
	rpcHook, err := NewRPCHook(&cfg)
	if err != nil {
		logrus.Fatalf("Failed to initialize application: %v", err)
	}

	http.HandleFunc("/", rpcHook.handler())
	logrus.Infof("Listening on :%s", cfg.Port)
	logrus.Fatal(http.ListenAndServe(":"+cfg.Port, nil))
}

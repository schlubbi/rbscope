package collector

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// SimBPF generates realistic Ruby profiling events without actual eBPF.
// It simulates what a real BPF collector would produce: stack samples from
// a Rails-like application with known function names and realistic timing.
type SimBPF struct {
	mu        sync.Mutex
	running   bool
	pid       uint32
	freq      int
	stopCh    chan struct{}
	eventBuf  chan []byte
	startTime time.Time
}

// NewSimBPF creates a simulated BPF program generating events at the given frequency.
func NewSimBPF(freqHz int) *SimBPF {
	return &SimBPF{
		freq:     freqHz,
		eventBuf: make(chan []byte, 4096),
	}
}

// Load initializes the simulated BPF program.
func (s *SimBPF) Load() error {
	s.startTime = time.Now()
	return nil
}

// AttachPID begins generating simulated events for the given PID.
func (s *SimBPF) AttachPID(pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}
	s.pid = pid
	s.running = true
	s.stopCh = make(chan struct{})
	go s.generateLoop()
	return nil
}

// DetachPID stops generating events for the given PID.
func (s *SimBPF) DetachPID(_ uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	close(s.stopCh)
	s.running = false
	return nil
}

// ReadRingBuffer reads the next simulated event into buf.
func (s *SimBPF) ReadRingBuffer(buf []byte) (int, error) {
	select {
	case data := <-s.eventBuf:
		n := copy(buf, data)
		return n, nil
	case <-time.After(50 * time.Millisecond):
		return 0, nil
	}
}

// Close stops event generation and releases resources.
// KtimeOffsetNs returns 0 for SimBPF since simulated events already use wall clock.
func (s *SimBPF) KtimeOffsetNs() int64 { return 0 }

func (s *SimBPF) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
	}
	return nil
}

// simStack represents a simulated Ruby call stack with weighted probability.
type simStack struct {
	weight uint32 // relative probability
	id     uint32 // unique stack ID
}

// Simulated stacks representing a Rails-like application.
// Stack IDs map to function names in the SimBPF's symbol table.
var simStacks = []simStack{
	{weight: 30, id: 1}, // hot: ActiveRecord query
	{weight: 20, id: 2}, // hot: view rendering
	{weight: 15, id: 3}, // warm: JSON serialization
	{weight: 10, id: 4}, // warm: middleware chain
	{weight: 8, id: 5},  // cool: cache lookup
	{weight: 5, id: 6},  // cool: HTTP client
	{weight: 5, id: 7},  // cool: background job dispatch
	{weight: 4, id: 8},  // cold: GC marking
	{weight: 2, id: 9},  // cold: config reload
	{weight: 1, id: 10}, // rare: migration check
}

// SimStackNames maps stack IDs to human-readable Ruby function names.
// Exported so the exporter can build proper pprof profiles with named frames.
var SimStackNames = map[uint32][]string{
	1: {
		"ActiveRecord::ConnectionAdapters::TrilogyAdapter#exec_query",
		"ActiveRecord::ConnectionAdapters::AbstractMysqlAdapter#execute_and_free",
		"ActiveRecord::Base.find",
		"PostsController#show",
		"ActionController::Instrumentation#process_action",
	},
	2: {
		"ActionView::Template#render",
		"ActionView::Renderer#render_template",
		"ActionView::PartialRenderer#render",
		"PostsController#show",
		"ActionController::Instrumentation#process_action",
	},
	3: {
		"ActiveSupport::JSON::Encoding::JSONGemEncoder#encode",
		"ActiveModel::Serializers::JSON#as_json",
		"Api::V1::PostsController#index",
		"ActionController::Instrumentation#process_action",
	},
	4: {
		"Rack::Runtime#call",
		"ActionDispatch::RequestId#call",
		"Rails::Rack::Logger#call",
		"ActionDispatch::Executor#call",
		"Puma::ThreadPool#spawn_thread",
	},
	5: {
		"ActiveSupport::Cache::RedisCacheStore#read_entry",
		"ActiveSupport::Cache::Strategy::LocalCache#read_entry",
		"PostsController#show",
		"ActionController::Instrumentation#process_action",
	},
	6: {
		"Net::HTTP#transport_request",
		"Net::HTTP#request",
		"Faraday::Adapter::NetHttp#perform_request",
		"WebhookService#deliver",
		"ActionController::Instrumentation#process_action",
	},
	7: {
		"ActiveJob::QueueAdapters::SidekiqAdapter#enqueue",
		"ActiveJob::Base#enqueue",
		"NotificationMailer.deliver_later",
		"PostsController#create",
		"ActionController::Instrumentation#process_action",
	},
	8: {
		"<internal:gc>#mark",
		"<internal:gc>#sweep",
		"GC.start",
	},
	9: {
		"Rails::Application::Configuration#reload_classes_only_on_change",
		"ActiveSupport::FileUpdateChecker#execute",
		"ActionDispatch::Executor#call",
	},
	10: {
		"ActiveRecord::Migration.check_pending!",
		"ActiveRecord::Migration::CheckPending#call",
		"ActionDispatch::Executor#call",
	},
}

var totalWeight uint32

func init() {
	for _, s := range simStacks {
		totalWeight += s.weight
	}
}

func (s *SimBPF) generateLoop() {
	interval := time.Duration(float64(time.Second) / float64(s.freq))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- simulation only
	ioCounter := 0

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Generate a stack sample every tick
			stack := pickStack(rng)
			event := s.buildSampleEvent(stack, rng)
			select {
			case s.eventBuf <- event:
			default:
			}

			// Generate an IO event every ~5th tick
			ioCounter++
			if ioCounter%5 == 0 {
				ioEvent := s.buildIOEvent(rng)
				select {
				case s.eventBuf <- ioEvent:
				default:
				}
			}
		}
	}
}

func pickStack(rng *rand.Rand) simStack {
	r := rng.Uint32() % totalWeight
	var cumulative uint32
	for _, s := range simStacks {
		cumulative += s.weight
		if r < cumulative {
			return s
		}
	}
	return simStacks[0]
}

func (s *SimBPF) buildSampleEvent(stack simStack, rng *rand.Rand) []byte {
	frames := SimStackNames[stack.id]

	// Build inline format v2 stack data:
	// version(1) + num_frames(2) + for each frame: label_len(2) + label + path_len(2) + path + line(4)
	var stackData []byte
	stackData = append(stackData, 2)                                             // version = 2
	stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(frames))) // #nosec G115

	for i, name := range frames {
		// label = method name
		stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(name))) // #nosec G115
		stackData = append(stackData, name...)
		// path = synthetic file path
		path := fmt.Sprintf("app/models/%s.rb", name[:min(len(name), 20)])
		stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(path))) // #nosec G115
		stackData = append(stackData, path...)
		// line number
		stackData = binary.LittleEndian.AppendUint32(stackData, uint32(10+i*5)) // #nosec G115
	}

	// 40-byte header: type(4) + pid(4) + tid(4) + weight(4) + timestamp(8) + thread_id(8) + stack_data_len(4) + pad(4)
	buf := make([]byte, rubySampleHeaderSize+len(stackData))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(EventRubySample)) // #nosec G115
	binary.LittleEndian.PutUint32(buf[4:8], s.pid)
	tid := s.pid + uint32(rng.Intn(8)) // #nosec G115
	binary.LittleEndian.PutUint32(buf[8:12], tid)
	binary.LittleEndian.PutUint32(buf[12:16], 1)                                             // weight = 1
	binary.LittleEndian.PutUint64(buf[16:24], uint64(time.Since(s.startTime).Nanoseconds())) // #nosec G115
	binary.LittleEndian.PutUint64(buf[24:32], uint64(tid))
	binary.LittleEndian.PutUint32(buf[32:36], uint32(len(stackData))) // #nosec G115
	// pad at 36:40

	copy(buf[rubySampleHeaderSize:], stackData)
	return buf
}

// simIOTarget represents a simulated connection target for IO events.
type simIOTarget struct {
	weight     uint32
	op         uint32 // IO_OP_*
	fdType     uint8  // FD_TYPE_*
	localPort  uint16
	remotePort uint16
	remoteAddr uint32 // IPv4, network byte order
	srttUs     uint32 // simulated RTT
	latencyNs  uint64 // simulated I/O latency
}

// Simulated IO targets representing a Rails app talking to MySQL, Redis, etc.
var simIOTargets = []simIOTarget{
	{weight: 40, op: IoOpRead, fdType: 2, localPort: 54321, remotePort: 3306,
		remoteAddr: 0x0100000A, srttUs: 500, latencyNs: 2_000_000}, // MySQL read, RTT=0.5ms
	{weight: 20, op: IoOpWrite, fdType: 2, localPort: 54321, remotePort: 3306,
		remoteAddr: 0x0100000A, srttUs: 500, latencyNs: 500_000}, // MySQL write
	{weight: 15, op: IoOpRead, fdType: 2, localPort: 54322, remotePort: 6379,
		remoteAddr: 0x0200000A, srttUs: 100, latencyNs: 200_000}, // Redis read, RTT=0.1ms
	{weight: 10, op: IoOpRead, fdType: 1, localPort: 0, remotePort: 0,
		remoteAddr: 0, srttUs: 0, latencyNs: 50_000}, // file read
	{weight: 10, op: IoOpWrite, fdType: 5, localPort: 0, remotePort: 0,
		remoteAddr: 0, srttUs: 0, latencyNs: 10_000}, // pipe write (log)
	{weight: 5, op: IoOpConnect, fdType: 2, localPort: 54323, remotePort: 443,
		remoteAddr: 0x01010101, srttUs: 15000, latencyNs: 30_000_000}, // HTTPS connect, RTT=15ms
}

var totalIOWeight uint32

func init() {
	for _, t := range simIOTargets {
		totalIOWeight += t.weight
	}
}

func pickIOTarget(rng *rand.Rand) simIOTarget {
	r := rng.Uint32() % totalIOWeight
	var cumulative uint32
	for _, t := range simIOTargets {
		cumulative += t.weight
		if r < cumulative {
			return t
		}
	}
	return simIOTargets[0]
}

func (s *SimBPF) buildIOEvent(rng *rand.Rand) []byte {
	target := pickIOTarget(rng)

	// Build enriched IO event (112 bytes, matching ioEventEnrichedSize)
	buf := make([]byte, ioEventEnrichedSize)

	tid := s.pid + uint32(rng.Intn(8)) // #nosec G115

	// Header (24 bytes)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(EventIO))
	binary.LittleEndian.PutUint32(buf[4:8], s.pid)
	binary.LittleEndian.PutUint32(buf[8:12], tid)
	// pad at 12:16
	binary.LittleEndian.PutUint64(buf[16:24], uint64(time.Since(s.startTime).Nanoseconds())) // #nosec G115

	// IO fields (24 bytes)
	binary.LittleEndian.PutUint32(buf[24:28], target.op)
	binary.LittleEndian.PutUint32(buf[28:32], uint32(rng.Intn(100)+3)) // #nosec G115 -- fd number
	// bytes (s64) at 32:40 — add jitter to latency
	jitter := int64(float64(target.latencyNs) * (0.5 + rng.Float64()))
	binary.LittleEndian.PutUint64(buf[32:40], uint64(1024+rng.Intn(8192))) // #nosec G115 -- bytes transferred
	binary.LittleEndian.PutUint64(buf[40:48], uint64(jitter))              // #nosec G115 -- latency

	// Socket enrichment (16 bytes)
	buf[48] = target.fdType
	buf[49] = 1 // TCP_ESTABLISHED
	binary.LittleEndian.PutUint16(buf[50:52], target.localPort)
	binary.LittleEndian.PutUint16(buf[52:54], target.remotePort)
	// pad at 54:56
	binary.LittleEndian.PutUint32(buf[56:60], 0x6400A8C0) // 192.168.0.100 (local)
	binary.LittleEndian.PutUint32(buf[60:64], target.remoteAddr)

	// TCP stats (48 bytes, only for TCP sockets)
	if target.fdType == 2 { // FD_TYPE_TCP
		binary.LittleEndian.PutUint32(buf[64:68], target.srttUs)
		binary.LittleEndian.PutUint32(buf[68:72], 10+uint32(rng.Intn(20)))    // #nosec G115 -- sim
		binary.LittleEndian.PutUint32(buf[72:76], uint32(rng.Intn(5)))        // #nosec G115 -- sim
		binary.LittleEndian.PutUint32(buf[76:80], uint32(rng.Intn(8)))        // #nosec G115 -- sim
		binary.LittleEndian.PutUint32(buf[80:84], uint32(rng.Intn(2)))        // #nosec G115 -- sim
		binary.LittleEndian.PutUint32(buf[84:88], 0)                          // lost_out
		binary.LittleEndian.PutUint32(buf[88:92], 65535)                      // rcv_wnd
		binary.LittleEndian.PutUint64(buf[96:104], uint64(rng.Intn(100000)))  // #nosec G115 -- sim
		binary.LittleEndian.PutUint64(buf[104:112], uint64(rng.Intn(500000))) // #nosec G115 -- sim
	}

	return buf
}

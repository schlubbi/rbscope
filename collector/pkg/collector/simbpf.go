package collector

import (
	"encoding/binary"
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

func (s *SimBPF) Load() error {
	s.startTime = time.Now()
	return nil
}

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

func (s *SimBPF) ReadRingBuffer(buf []byte) (int, error) {
	select {
	case data := <-s.eventBuf:
		n := copy(buf, data)
		return n, nil
	case <-time.After(50 * time.Millisecond):
		return 0, nil
	}
}

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
	{weight: 30, id: 1},  // hot: ActiveRecord query
	{weight: 20, id: 2},  // hot: view rendering
	{weight: 15, id: 3},  // warm: JSON serialization
	{weight: 10, id: 4},  // warm: middleware chain
	{weight: 8, id: 5},   // cool: cache lookup
	{weight: 5, id: 6},   // cool: HTTP client
	{weight: 5, id: 7},   // cool: background job dispatch
	{weight: 4, id: 8},   // cold: GC marking
	{weight: 2, id: 9},   // cold: config reload
	{weight: 1, id: 10},  // rare: migration check
}

// SimStackNames maps stack IDs to human-readable Ruby function names.
// Exported so the exporter can build proper pprof profiles with named frames.
var SimStackNames = map[uint32][]string{
	1: {
		"ActiveRecord::ConnectionAdapters::Mysql2Adapter#exec_query",
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

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			stack := pickStack(rng)
			event := s.buildSampleEvent(stack, rng)
			select {
			case s.eventBuf <- event:
			default:
				// drop if buffer full
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
	// Header(24) + stackID(4) + stackLen(4) + traceID(16) + spanID(8) + threadID(8) + frames(N*8)
	size := eventHeaderSize + 4 + 4 + 16 + 8 + 8 + len(frames)*8
	buf := make([]byte, size)

	// Header
	binary.LittleEndian.PutUint32(buf[0:4], uint32(EventRubySample))
	binary.LittleEndian.PutUint32(buf[4:8], s.pid)
	binary.LittleEndian.PutUint32(buf[8:12], s.pid+uint32(rng.Intn(8))) // tid
	binary.LittleEndian.PutUint64(buf[12:20], uint64(time.Since(s.startTime).Nanoseconds()))
	binary.LittleEndian.PutUint32(buf[20:24], uint32(rng.Intn(4))) // cpu

	off := eventHeaderSize
	binary.LittleEndian.PutUint32(buf[off:], stack.id)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], uint32(len(frames)))
	off += 4
	// traceID — random
	for i := 0; i < 16; i++ {
		buf[off+i] = byte(rng.Intn(256))
	}
	off += 16
	// spanID — random
	for i := 0; i < 8; i++ {
		buf[off+i] = byte(rng.Intn(256))
	}
	off += 8
	// threadID
	binary.LittleEndian.PutUint64(buf[off:], uint64(s.pid)*1000+uint64(rng.Intn(8)))
	off += 8
	// Frames — use stack.id * 1000 + index as pseudo-addresses
	for i := range frames {
		binary.LittleEndian.PutUint64(buf[off:], uint64(stack.id)*1000+uint64(i))
		off += 8
	}
	return buf
}

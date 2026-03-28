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

	// Build inline format v2 stack data:
	// version(1) + num_frames(2) + for each frame: label_len(2) + label + path_len(2) + path + line(4)
	var stackData []byte
	stackData = append(stackData, 2) // version = 2
	stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(frames)))

	for i, name := range frames {
		// label = method name
		stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(name)))
		stackData = append(stackData, name...)
		// path = synthetic file path
		path := fmt.Sprintf("app/models/%s.rb", name[:min(len(name), 20)])
		stackData = binary.LittleEndian.AppendUint16(stackData, uint16(len(path)))
		stackData = append(stackData, path...)
		// line number
		stackData = binary.LittleEndian.AppendUint32(stackData, uint32(10+i*5))
	}

	// 40-byte header: type(4) + pid(4) + tid(4) + pad(4) + timestamp(8) + thread_id(8) + stack_data_len(4) + pad(4)
	buf := make([]byte, rubySampleHeaderSize+len(stackData))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(EventRubySample))
	binary.LittleEndian.PutUint32(buf[4:8], s.pid)
	tid := s.pid + uint32(rng.Intn(8))
	binary.LittleEndian.PutUint32(buf[8:12], tid)
	// pad at 12:16
	binary.LittleEndian.PutUint64(buf[16:24], uint64(time.Since(s.startTime).Nanoseconds()))
	binary.LittleEndian.PutUint64(buf[24:32], uint64(tid))
	binary.LittleEndian.PutUint32(buf[32:36], uint32(len(stackData)))
	// pad at 36:40

	copy(buf[rubySampleHeaderSize:], stackData)
	return buf
}

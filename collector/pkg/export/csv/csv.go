// Package csv exports rbscope Capture data as CSV files for ad-hoc
// analysis with DuckDB. Inspired by 0xtools/xCapture's flat-file
// approach: no backend needed, just `duckdb` + SQL.
//
// Output structure:
//
//	rbscope_samples.csv  — one row per stack sample (timestamp, tid, method, state, ...)
//	rbscope_io.csv       — one row per I/O event (syscall, latency, connection, ...)
//	rbscope_sched.csv    — one row per off-CPU period (duration, reason, ...)
package csv

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	pb "github.com/schlubbi/rbscope/collector/pkg/proto/rbscopepb"
)

// Export writes a Capture as CSV files into the given directory.
func Export(capture *pb.Capture, dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil { // #nosec G301
		return fmt.Errorf("create csv dir: %w", err)
	}

	if err := writeSamples(capture, dir); err != nil {
		return fmt.Errorf("write samples csv: %w", err)
	}
	if err := writeIO(capture, dir); err != nil {
		return fmt.Errorf("write io csv: %w", err)
	}
	if err := writeSched(capture, dir); err != nil {
		return fmt.Errorf("write sched csv: %w", err)
	}
	if err := writeGVL(capture, dir); err != nil {
		return fmt.Errorf("write gvl csv: %w", err)
	}

	return nil
}

func writeSamples(capture *pb.Capture, dir string) error {
	path := filepath.Join(dir, "rbscope_samples.csv")
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"timestamp_ns", "pid", "tid", "weight",
		"leaf_method", "leaf_file", "leaf_line",
		"full_stack",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, tl := range capture.Threads {
		for _, s := range tl.Samples {
			leafMethod, leafFile, leafLine := resolveLeafFrame(capture, s.FrameIds)
			fullStack := formatStack(capture, s.FrameIds)

			weight := s.Weight
			if weight == 0 {
				weight = 1
			}

			row := []string{
				strconv.FormatUint(s.TimestampNs, 10),
				u32(capture.Header.Pid),
				u32(tl.ThreadId),
				u32(weight),
				leafMethod,
				leafFile,
				leafLine,
				fullStack,
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeIO(capture *pb.Capture, dir string) error {
	path := filepath.Join(dir, "rbscope_io.csv")
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"timestamp_ns", "pid", "tid",
		"syscall", "fd", "fd_type", "connection",
		"bytes", "latency_ns",
		"local_port", "remote_port",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, tl := range capture.Threads {
		for _, io := range tl.IoEvents {
			syscall := lookupStr(capture.StringTable, io.SyscallIdx)
			fdInfo := lookupStr(capture.StringTable, io.FdInfoIdx)
			fdType := io.FdType.String()

			row := []string{
				strconv.FormatUint(io.TimestampNs, 10),
				u32(capture.Header.Pid),
				u32(tl.ThreadId),
				syscall,
				i32(io.Fd),
				fdType,
				fdInfo,
				strconv.FormatUint(io.Bytes, 10),
				strconv.FormatUint(io.LatencyNs, 10),
				u32(io.LocalPort),
				u32(io.RemotePort),
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeSched(capture *pb.Capture, dir string) error {
	path := filepath.Join(dir, "rbscope_sched.csv")
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"timestamp_ns", "pid", "tid",
		"off_cpu_ns", "reason",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, tl := range capture.Threads {
		for _, sched := range tl.SchedEvents {
			row := []string{
				strconv.FormatUint(sched.TimestampNs, 10),
				u32(capture.Header.Pid),
				u32(tl.ThreadId),
				strconv.FormatUint(sched.OffCpuNs, 10),
				sched.Reason.String(),
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeGVL(capture *pb.Capture, dir string) error {
	path := filepath.Join(dir, "rbscope_gvl.csv")
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"start_ns", "end_ns", "pid", "tid",
		"state", "duration_ns",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, tl := range capture.Threads {
		// Prefer state intervals if available (new format)
		if len(tl.GvlIntervals) > 0 {
			for _, iv := range tl.GvlIntervals {
				row := []string{
					strconv.FormatUint(iv.StartNs, 10),
					strconv.FormatUint(iv.EndNs, 10),
					u32(capture.Header.Pid),
					u32(tl.ThreadId),
					gvlStateName(iv.State),
					strconv.FormatUint(iv.EndNs-iv.StartNs, 10),
				}
				if err := w.Write(row); err != nil {
					return err
				}
			}
		} else {
			// Fallback: legacy GVL wait events
			for _, gvl := range tl.GvlEvents {
				startNs := gvl.TimestampNs - gvl.WaitNs
				row := []string{
					strconv.FormatUint(startNs, 10),
					strconv.FormatUint(gvl.TimestampNs, 10),
					u32(capture.Header.Pid),
					u32(tl.ThreadId),
					"stalled",
					strconv.FormatUint(gvl.WaitNs, 10),
				}
				if err := w.Write(row); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func gvlStateName(s pb.GVLState) string {
	switch s {
	case pb.GVLState_GVL_STATE_RUNNING:
		return "running"
	case pb.GVLState_GVL_STATE_STALLED:
		return "stalled"
	case pb.GVLState_GVL_STATE_SUSPENDED:
		return "suspended"
	default:
		return "unknown"
	}
}

// --- Helpers ---

func resolveLeafFrame(capture *pb.Capture, frameIDs []uint32) (method, file, line string) {
	if len(frameIDs) == 0 {
		return "", "", ""
	}
	// frameIDs are leaf-first
	fid := frameIDs[0]
	if int(fid) >= len(capture.FrameTable) {
		return "", "", ""
	}
	frame := capture.FrameTable[fid]
	method = lookupStr(capture.StringTable, frame.FunctionNameIdx)
	file = lookupStr(capture.StringTable, frame.FileNameIdx)
	if frame.LineNumber > 0 {
		line = strconv.FormatUint(uint64(frame.LineNumber), 10)
	}
	return
}

func formatStack(capture *pb.Capture, frameIDs []uint32) string {
	if len(frameIDs) == 0 {
		return ""
	}
	// Build semicolon-separated stack (root first for flame graph compat)
	var stack string
	for i := len(frameIDs) - 1; i >= 0; i-- {
		fid := frameIDs[i]
		if int(fid) >= len(capture.FrameTable) {
			continue
		}
		frame := capture.FrameTable[fid]
		name := lookupStr(capture.StringTable, frame.FunctionNameIdx)
		if name == "" {
			name = "???"
		}
		if stack != "" {
			stack += ";"
		}
		stack += name
	}
	return stack
}

func lookupStr(table []string, idx uint32) string {
	if int(idx) < len(table) {
		return table[idx]
	}
	return ""
}

func u32(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

func i32(v int32) string {
	return strconv.FormatInt(int64(v), 10)
}

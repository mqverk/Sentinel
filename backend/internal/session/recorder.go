package session

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type frame struct {
	OffsetMillis int64  `json:"offsetMillis"`
	Stream       string `json:"stream"`
	Payload      string `json:"payload"`
}

type Recorder struct {
	baseDir string
}

func NewRecorder(baseDir string) *Recorder {
	return &Recorder{baseDir: baseDir}
}

func (r *Recorder) EnsureDir() error {
	if err := os.MkdirAll(r.baseDir, 0o750); err != nil {
		return fmt.Errorf("create recording directory: %w", err)
	}
	return nil
}

func (r *Recorder) PathForSession(sessionID string) string {
	return filepath.Join(r.baseDir, sessionID+".jsonl")
}

func (r *Recorder) AppendFrame(path string, start time.Time, stream string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open recording file: %w", err)
	}
	defer file.Close()

	record := frame{
		OffsetMillis: time.Since(start).Milliseconds(),
		Stream:       stream,
		Payload:      base64.StdEncoding.EncodeToString(payload),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

func (r *Recorder) ReadFrames(path string) ([]ReplayFrame, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recording file: %w", err)
	}
	defer file.Close()

	frames := make([]ReplayFrame, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var raw frame
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			return nil, fmt.Errorf("decode replay frame: %w", err)
		}
		payload, err := base64.StdEncoding.DecodeString(raw.Payload)
		if err != nil {
			return nil, fmt.Errorf("decode frame payload: %w", err)
		}
		frames = append(frames, ReplayFrame{OffsetMillis: raw.OffsetMillis, Stream: raw.Stream, Payload: string(payload)})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan replay frames: %w", err)
	}
	return frames, nil
}

type ReplayFrame struct {
	OffsetMillis int64  `json:"offsetMillis"`
	Stream       string `json:"stream"`
	Payload      string `json:"payload"`
}

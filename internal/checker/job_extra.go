package checker

// Snapshot helpers for API (keep locking inside engine).
func (j *Job) Snapshot() []Result {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Result, len(j.Results))
	copy(out, j.Results)
	return out
}

func (j *Job) Progress() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Done
}

func (j *Job) IsFinished() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Finished
}

func (j *Job) SavedFiles() []SavedFile {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]SavedFile, len(j.Saved))
	copy(out, j.Saved)
	return out
}

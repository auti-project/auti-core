package hashmap

import "sync"

// HashMap is the struct for storing the key-value pairs of names and their hashes
type HashMap struct {
	data   sync.Map
	revert sync.Map
}

// Get returns the hash of a name
func (m *HashMap) Get(name string) ([]byte, bool) {
	val, ok := m.data.Load(name)
	if ok {
		return []byte(val.(string)), true
	}
	return nil, false
}

// Set sets the hash of a name, and accordingly set the
func (m *HashMap) Set(name string, hash []byte) {
	hashStr := string(hash)
	m.data.Store(name, hashStr)
	m.revert.Store(hashStr, name)
}

// Delete deletes the hash of a name, and accordingly deletes the name of the hash
func (m *HashMap) Delete(key string) {
	val, ok := m.data.Load(key)
	if ok {
		m.revert.Delete(val.(string))
		m.data.Delete(key)
	}
}

// FindName returns the name of a hash
func (m *HashMap) FindName(hash []byte) (string, bool) {
	val, ok := m.revert.Load(string(hash))
	if ok {
		return val.(string), true
	}
	return "", false
}

// Drop drops the whole map and revert map
func (m *HashMap) Drop() {
	m.data = sync.Map{}
	m.revert = sync.Map{}
}

package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketAlerts    = []byte("alerts")
	bucketDecisions = []byte("decisions")
)

// OfflineQueue persists uploads when the manager is unreachable.
type OfflineQueue struct {
	db *bolt.DB
}

func Open(path string) (*OfflineQueue, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketAlerts, bucketDecisions} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &OfflineQueue{db: db}, nil
}

func (q *OfflineQueue) Close() error {
	if q.db == nil {
		return nil
	}
	return q.db.Close()
}

type queuedItem struct {
	Payload json.RawMessage `json:"payload"`
	TS      time.Time       `json:"ts"`
}

func (q *OfflineQueue) EnqueueAlerts(payload json.RawMessage) error {
	return q.enqueue(bucketAlerts, payload)
}

func (q *OfflineQueue) EnqueueDecisions(payload json.RawMessage) error {
	return q.enqueue(bucketDecisions, payload)
}

func (q *OfflineQueue) enqueue(bucket []byte, payload json.RawMessage) error {
	return q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		key := []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
		item, _ := json.Marshal(queuedItem{Payload: payload, TS: time.Now().UTC()})
		return b.Put(key, item)
	})
}

func (q *OfflineQueue) DrainAlerts() ([][]byte, error) {
	return q.drain(bucketAlerts)
}

func (q *OfflineQueue) DrainDecisions() ([][]byte, error) {
	return q.drain(bucketDecisions)
}

func (q *OfflineQueue) drain(bucket []byte) ([][]byte, error) {
	var out [][]byte
	err := q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var item queuedItem
			if err := json.Unmarshal(v, &item); err != nil {
				continue
			}
			out = append(out, item.Payload)
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (q *OfflineQueue) Count() (int, error) {
	n := 0
	err := q.db.View(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketAlerts, bucketDecisions} {
			stats := tx.Bucket(b).Stats()
			n += stats.KeyN
		}
		return nil
	})
	return n, err
}

package iocbus

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/Sasi3011/CyberSec/enterprise/manager/internal/domain"
)

// Publisher broadcasts IOC updates to agents via Redis pub/sub.
type Publisher struct {
	client *redis.Client
}

func NewPublisher(client *redis.Client) *Publisher {
	return &Publisher{client: client}
}

type IOCEvent struct {
	OrganizationID string             `json:"organization_id"`
	Version        int64              `json:"version"`
	IOCs           []domain.ThreatIOC `json:"iocs"`
}

func (p *Publisher) Publish(ctx context.Context, orgID string, version int64, iocs []domain.ThreatIOC) error {
	if p.client == nil || len(iocs) == 0 {
		return nil
	}
	payload, err := json.Marshal(IOCEvent{
		OrganizationID: orgID,
		Version:        version,
		IOCs:           iocs,
	})
	if err != nil {
		return err
	}
	channel := fmt.Sprintf("cybersec:org:%s:ioc", orgID)
	return p.client.Publish(ctx, channel, payload).Err()
}

func OpenRedis(url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}
	return client, nil
}

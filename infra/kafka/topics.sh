#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# Phantex — Create Kafka Topics
#
# Usage:
#   ./topics.sh [create|delete|list|describe]
#
# Requires: Docker running with phantex-kafka container.
# Topics follow the pattern: phantex.events.{tenant_id}
#
# Default topics created:
#   phantex.events.default-tenant  — matches the dev auth token mapping
#
# Each topic has:
#   - 6 partitions (allows 6 parallel consumers in each consumer group)
#   - Replication factor 1 (dev); change to 3 for production
#   - 7-day retention (raw events; permanent storage goes to PostgreSQL)

set -euo pipefail

KAFKA_CONTAINER="phantex-kafka"
BOOTSTRAP="localhost:9092"
KAFKA_BIN="/opt/kafka/bin"

# Default tenant from gateway config
DEFAULT_TOPICS=(
    "phantex.events.default-tenant"
)

# Consumer groups that will read from these topics
CONSUMER_GROUPS=(
    "storage-writer"
    "rule-engine"
    "api-realtime"
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

kafka_cmd() {
    docker exec "$KAFKA_CONTAINER" "$KAFKA_BIN/$1" "${@:2}"
}

wait_for_kafka() {
    log_info "Waiting for Kafka to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if kafka_cmd kafka-broker-api-versions.sh --bootstrap-server "$BOOTSTRAP" &>/dev/null; then
            log_info "Kafka is ready"
            return 0
        fi
        retries=$((retries - 1))
        sleep 2
    done
    log_error "Kafka not ready after 60s"
    return 1
}

create_topic() {
    local topic="$1"
    local partitions="${2:-6}"
    local replication="${3:-1}"
    local retention_ms="${4:-604800000}"  # 7 days in ms

    log_info "Creating topic: $topic (partitions=$partitions, replication=$replication, retention=7d)"

    if kafka_cmd kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
        --describe --topic "$topic" &>/dev/null 2>&1; then
        log_warn "Topic $topic already exists — skipping"
        return 0
    fi

    kafka_cmd kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
        --create \
        --topic "$topic" \
        --partitions "$partitions" \
        --replication-factor "$replication" \
        --config retention.ms="$retention_ms" \
        --config cleanup.policy=delete \
        --config compression.type=lz4 \
        --config max.message.bytes=16777216

    log_info "Topic $topic created successfully"
}

delete_topic() {
    local topic="$1"
    log_warn "Deleting topic: $topic"
    kafka_cmd kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
        --delete --topic "$topic" 2>/dev/null || true
}

cmd_create() {
    wait_for_kafka

    for topic in "${DEFAULT_TOPICS[@]}"; do
        create_topic "$topic"
    done

    # Create additional tenant topics if specified
    if [ $# -gt 0 ]; then
        for tenant in "$@"; do
            create_topic "phantex.events.$tenant"
        done
    fi

    log_info "All topics created. Run '$0 list' to verify."
}

cmd_delete() {
    for topic in "${DEFAULT_TOPICS[@]}"; do
        delete_topic "$topic"
    done
    if [ $# -gt 0 ]; then
        for tenant in "$@"; do
            delete_topic "phantex.events.$tenant"
        done
    fi
    log_info "Topics deleted."
}

cmd_list() {
    log_info "Listing all topics:"
    kafka_cmd kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list
}

cmd_describe() {
    local topic="${1:-phantex.events.default-tenant}"
    log_info "Describing topic: $topic"
    kafka_cmd kafka-topics.sh --bootstrap-server "$BOOTSTRAP" \
        --describe --topic "$topic"
}

cmd_consume() {
    local topic="${1:-phantex.events.default-tenant}"
    local group="${2:-phantex-debug}"
    log_info "Consuming from $topic (group=$group, Ctrl-C to stop)..."
    kafka_cmd kafka-console-consumer.sh --bootstrap-server "$BOOTSTRAP" \
        --topic "$topic" \
        --group "$group" \
        --from-beginning \
        --property print.key=true \
        --property print.timestamp=true
}

cmd_status() {
    log_info "Kafka cluster status:"
    kafka_cmd kafka-broker-api-versions.sh --bootstrap-server "$BOOTSTRAP" 2>/dev/null | head -5

    echo ""
    log_info "Topics:"
    kafka_cmd kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --list 2>/dev/null

    echo ""
    log_info "Consumer groups:"
    kafka_cmd kafka-consumer-groups.sh --bootstrap-server "$BOOTSTRAP" --list 2>/dev/null || echo "(none)"
}

# ── Main ──────────────────────────────────────────────────────────────────────

case "${1:-create}" in
    create)
        shift || true
        cmd_create "$@"
        ;;
    delete)
        shift || true
        cmd_delete "$@"
        ;;
    list)
        cmd_list
        ;;
    describe)
        shift || true
        cmd_describe "$@"
        ;;
    consume)
        shift || true
        cmd_consume "$@"
        ;;
    status)
        cmd_status
        ;;
    *)
        echo "Usage: $0 {create|delete|list|describe|consume|status} [tenant_id...]"
        echo ""
        echo "Commands:"
        echo "  create [tenant...]   Create default + optional tenant topics"
        echo "  delete [tenant...]   Delete default + optional tenant topics"
        echo "  list                 List all topics"
        echo "  describe [topic]     Describe a topic (default: phantex.events.default-tenant)"
        echo "  consume [topic]      Consume messages (for debugging)"
        echo "  status               Show cluster status"
        exit 1
        ;;
esac

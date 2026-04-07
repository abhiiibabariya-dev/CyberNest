"""
CyberNest Indexer — Consumes parsed events and alerts from Kafka,
bulk-indexes them into Elasticsearch with proper index templates
and ILM (Index Lifecycle Management) policies.
"""

import asyncio
import os
import time
from datetime import datetime, timezone

import orjson
import structlog
from aiokafka import AIOKafkaConsumer
from elasticsearch import AsyncElasticsearch, helpers

logger = structlog.get_logger()

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "indexer-group")
ES_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")

TOPICS = ["cybernest.parsed.events", "cybernest.alerts"]

# Index name patterns
TOPIC_INDEX_MAP = {
    "cybernest.parsed.events": "cybernest-events",
    "cybernest.alerts": "cybernest-alerts",
}

# ECS index template
ECS_MAPPINGS = {
    "properties": {
        "@timestamp": {"type": "date"},
        "raw": {"type": "text", "index": False},
        "message": {"type": "text"},
        "tags": {"type": "keyword"},
        "event": {
            "properties": {
                "module": {"type": "keyword"},
                "category": {"type": "keyword"},
                "action": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "kind": {"type": "keyword"},
                "severity": {"type": "integer"},
            }
        },
        "agent": {
            "properties": {
                "id": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "os": {"type": "keyword"},
                "version": {"type": "keyword"},
            }
        },
        "source": {
            "properties": {
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "domain": {"type": "keyword"},
                "geo": {
                    "properties": {
                        "country_iso_code": {"type": "keyword"},
                        "country_name": {"type": "keyword"},
                        "city_name": {"type": "keyword"},
                        "latitude": {"type": "float"},
                        "longitude": {"type": "float"},
                    }
                },
            }
        },
        "destination": {
            "properties": {
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "domain": {"type": "keyword"},
            }
        },
        "user": {
            "properties": {
                "name": {"type": "keyword"},
                "domain": {"type": "keyword"},
                "id": {"type": "keyword"},
            }
        },
        "process": {
            "properties": {
                "name": {"type": "keyword"},
                "pid": {"type": "integer"},
                "command_line": {"type": "text"},
            }
        },
        "host": {
            "properties": {
                "hostname": {"type": "keyword"},
                "ip": {"type": "ip"},
            }
        },
        "network": {
            "properties": {
                "protocol": {"type": "keyword"},
                "direction": {"type": "keyword"},
                "bytes_in": {"type": "long"},
                "bytes_out": {"type": "long"},
            }
        },
        "rule": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "level": {"type": "integer"},
            }
        },
        "dns": {
            "properties": {
                "question": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "type": {"type": "keyword"},
                    }
                }
            }
        },
        "url": {
            "properties": {
                "original": {"type": "keyword"},
                "path": {"type": "keyword"},
            }
        },
        "http": {
            "properties": {
                "request": {
                    "properties": {
                        "method": {"type": "keyword"},
                    }
                },
                "response": {
                    "properties": {
                        "status_code": {"type": "integer"},
                        "bytes": {"type": "long"},
                    }
                },
            }
        },
        "cloud": {
            "properties": {
                "provider": {"type": "keyword"},
                "region": {"type": "keyword"},
                "account": {"properties": {"id": {"type": "keyword"}}},
            }
        },
        "observer": {
            "properties": {
                "vendor": {"type": "keyword"},
                "product": {"type": "keyword"},
                "version": {"type": "keyword"},
            }
        },
        # Alert-specific
        "severity": {"type": "keyword"},
        "status": {"type": "keyword"},
        "rule_id": {"type": "keyword"},
        "rule_name": {"type": "keyword"},
        "mitre_tactics": {"type": "keyword"},
        "mitre_techniques": {"type": "keyword"},
        "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
    }
}

# ILM policy
ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {
                    "rollover": {"max_age": "1d", "max_primary_shard_size": "50gb"},
                    "set_priority": {"priority": 100},
                }
            },
            "warm": {
                "min_age": "7d",
                "actions": {
                    "shrink": {"number_of_shards": 1},
                    "forcemerge": {"max_num_segments": 1},
                    "set_priority": {"priority": 50},
                }
            },
            "cold": {
                "min_age": "30d",
                "actions": {
                    "set_priority": {"priority": 0},
                }
            },
            "delete": {
                "min_age": "365d",
                "actions": {"delete": {}},
            }
        }
    }
}


async def setup_elasticsearch(es: AsyncElasticsearch):
    """Create index templates and ILM policies."""
    # ILM policy
    try:
        await es.ilm.put_lifecycle(name="cybernest-ilm", body=ILM_POLICY)
        logger.info("ILM policy created")
    except Exception as e:
        logger.warning("ILM setup failed (may already exist)", error=str(e))

    # Index templates
    for prefix in ["cybernest-events", "cybernest-alerts"]:
        template = {
            "index_patterns": [f"{prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 2,
                    "number_of_replicas": 0,
                    "index.lifecycle.name": "cybernest-ilm",
                    "index.lifecycle.rollover_alias": prefix,
                },
                "mappings": ECS_MAPPINGS,
            },
        }
        try:
            await es.indices.put_index_template(name=f"{prefix}-template", body=template)
            logger.info("Index template created", prefix=prefix)
        except Exception as e:
            logger.warning("Template setup failed", prefix=prefix, error=str(e))

    # Create initial indices if not exist
    for prefix in ["cybernest-events", "cybernest-alerts"]:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        index_name = f"{prefix}-{today}"
        if not await es.indices.exists(index=index_name):
            try:
                await es.indices.create(index=index_name)
                logger.info("Initial index created", index=index_name)
            except Exception:
                pass


async def run():
    logger.info("Starting CyberNest Indexer Service")

    es = AsyncElasticsearch(
        hosts=[ES_URL],
        request_timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )

    await setup_elasticsearch(es)

    consumer = AIOKafkaConsumer(
        *TOPICS,
        bootstrap_servers=KAFKA_SERVERS,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda v: orjson.loads(v),
        auto_offset_reset="latest",
        enable_auto_commit=True,
        max_poll_records=500,
    )
    await consumer.start()
    logger.info("Indexer consumer started")

    batch: list[dict] = []
    batch_size = 200
    flush_interval = 2.0
    last_flush = time.monotonic()
    total_indexed = 0

    try:
        async for msg in consumer:
            try:
                doc = msg.value
                if not doc:
                    continue

                # Determine index
                prefix = TOPIC_INDEX_MAP.get(msg.topic, "cybernest-events")
                today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
                index_name = f"{prefix}-{today}"

                # Ensure timestamp
                if "@timestamp" not in doc:
                    doc["@timestamp"] = datetime.now(timezone.utc).isoformat()

                batch.append({
                    "_index": index_name,
                    "_source": doc,
                })

                # Flush batch
                now = time.monotonic()
                if len(batch) >= batch_size or (now - last_flush) >= flush_interval:
                    if batch:
                        try:
                            success, errors = await helpers.async_bulk(
                                es, batch, raise_on_error=False,
                            )
                            total_indexed += success
                            if errors:
                                logger.warning("Bulk index errors", count=len(errors))
                        except Exception as e:
                            logger.error("Bulk index failed", error=str(e))
                        batch.clear()
                        last_flush = now

                    if total_indexed % 5000 == 0 and total_indexed > 0:
                        logger.info("Indexer progress", total_indexed=total_indexed)

            except Exception as e:
                logger.error("Indexer message error", error=str(e))

    except asyncio.CancelledError:
        pass
    finally:
        # Flush remaining
        if batch:
            try:
                await helpers.async_bulk(es, batch, raise_on_error=False)
            except Exception:
                pass
        await consumer.stop()
        await es.close()
        logger.info("Indexer stopped", total_indexed=total_indexed)


if __name__ == "__main__":
    asyncio.run(run())

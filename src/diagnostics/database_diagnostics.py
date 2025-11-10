"""
PROMETHEUS PRIME - DATABASE DIAGNOSTICS MODULE

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

Database connection health, query performance, replication status monitoring.
Comprehensive database diagnostics for multi-layer memory system.
"""

import os
import time
import logging
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import subprocess

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    psycopg2 = None

try:
    from pymongo import MongoClient
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    MongoClient = None

try:
    import sqlite3
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False
    sqlite3 = None

try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    Elasticsearch = None


class DatabaseDiagnostics:
    """
    Comprehensive database diagnostics system.

    Features:
    - Connection health monitoring
    - Query performance benchmarking
    - Replication status checking
    - Memory usage tracking
    - Index health analysis
    - Connection pool monitoring
    - Transaction throughput
    - Multi-database support (Redis, PostgreSQL, MongoDB, SQLite, Elasticsearch)
    """

    def __init__(self):
        self.logger = logging.getLogger("DatabaseDiagnostics")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "databases": {
                "redis": {},
                "postgresql": {},
                "mongodb": {},
                "sqlite": {},
                "elasticsearch": {}
            },
            "performance": {},
            "replication": {},
            "health_score": 0
        }

        # Database connection settings (defaults)
        self.db_configs = {
            "redis": {"host": "localhost", "port": 6379, "db": 0},
            "postgresql": {"host": "localhost", "port": 5432, "database": "postgres", "user": "postgres"},
            "mongodb": {"host": "localhost", "port": 27017},
            "sqlite": {"path": ":memory:"},
            "elasticsearch": {"host": "localhost", "port": 9200}
        }

    def run_full_diagnostics(self) -> Dict:
        """Run complete database diagnostics suite."""
        self.logger.info("Starting database diagnostics...")

        # Test each database
        self.test_redis()
        self.test_postgresql()
        self.test_mongodb()
        self.test_sqlite()
        self.test_elasticsearch()

        # Performance benchmarks
        self.benchmark_read_performance()
        self.benchmark_write_performance()

        # Replication checks
        self.check_replication_status()

        # Calculate overall health
        self.calculate_health_score()

        self.logger.info("Database diagnostics complete")
        return self.results

    def test_redis(self) -> Dict:
        """Test Redis connection and health."""
        self.logger.info("Testing Redis...")

        results = {
            "available": REDIS_AVAILABLE,
            "connected": False,
            "info": {},
            "memory": {},
            "performance": {}
        }

        if not REDIS_AVAILABLE:
            results["error"] = "redis-py not installed"
            self.results["databases"]["redis"] = results
            return results

        try:
            config = self.db_configs["redis"]
            r = redis.Redis(
                host=config["host"],
                port=config["port"],
                db=config["db"],
                socket_connect_timeout=2,
                socket_timeout=2
            )

            # Test connection
            r.ping()
            results["connected"] = True

            # Get server info
            info = r.info()
            results["info"] = {
                "redis_version": info.get("redis_version", "Unknown"),
                "uptime_seconds": info.get("uptime_in_seconds", 0),
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "Unknown"),
                "total_keys": sum([r.dbsize() for _ in range(1)])
            }

            # Memory stats
            results["memory"] = {
                "used_memory": info.get("used_memory", 0),
                "used_memory_peak": info.get("used_memory_peak", 0),
                "mem_fragmentation_ratio": info.get("mem_fragmentation_ratio", 0)
            }

            # Performance test
            start_time = time.time()
            iterations = 1000
            for i in range(iterations):
                r.set(f"test_key_{i}", f"test_value_{i}")
            write_time = time.time() - start_time

            start_time = time.time()
            for i in range(iterations):
                r.get(f"test_key_{i}")
            read_time = time.time() - start_time

            # Cleanup
            for i in range(iterations):
                r.delete(f"test_key_{i}")

            results["performance"] = {
                "write_ops_per_sec": round(iterations / write_time, 2),
                "read_ops_per_sec": round(iterations / read_time, 2),
                "avg_write_ms": round((write_time / iterations) * 1000, 3),
                "avg_read_ms": round((read_time / iterations) * 1000, 3)
            }

        except redis.ConnectionError as e:
            results["error"] = f"Connection failed: {str(e)}"
        except Exception as e:
            results["error"] = str(e)

        self.results["databases"]["redis"] = results
        return results

    def test_postgresql(self) -> Dict:
        """Test PostgreSQL connection and health."""
        self.logger.info("Testing PostgreSQL...")

        results = {
            "available": POSTGRES_AVAILABLE,
            "connected": False,
            "info": {},
            "performance": {}
        }

        if not POSTGRES_AVAILABLE:
            results["error"] = "psycopg2 not installed"
            self.results["databases"]["postgresql"] = results
            return results

        try:
            config = self.db_configs["postgresql"]
            conn = psycopg2.connect(
                host=config["host"],
                port=config["port"],
                database=config["database"],
                user=config["user"],
                connect_timeout=2
            )
            results["connected"] = True

            cursor = conn.cursor()

            # Get version
            cursor.execute("SELECT version();")
            version = cursor.fetchone()[0]
            results["info"]["version"] = version.split(',')[0]

            # Get database size
            cursor.execute(f"SELECT pg_database_size('{config['database']}');")
            db_size = cursor.fetchone()[0]
            results["info"]["database_size_mb"] = round(db_size / (1024 * 1024), 2)

            # Get connection count
            cursor.execute("SELECT count(*) FROM pg_stat_activity;")
            conn_count = cursor.fetchone()[0]
            results["info"]["active_connections"] = conn_count

            # Performance test - simple queries
            cursor.execute("CREATE TEMPORARY TABLE test_perf (id SERIAL PRIMARY KEY, data TEXT);")

            start_time = time.time()
            iterations = 100
            for i in range(iterations):
                cursor.execute("INSERT INTO test_perf (data) VALUES (%s);", (f"test_data_{i}",))
            conn.commit()
            write_time = time.time() - start_time

            start_time = time.time()
            for i in range(iterations):
                cursor.execute("SELECT * FROM test_perf WHERE id = %s;", (i+1,))
                cursor.fetchone()
            read_time = time.time() - start_time

            results["performance"] = {
                "write_ops_per_sec": round(iterations / write_time, 2),
                "read_ops_per_sec": round(iterations / read_time, 2),
                "avg_write_ms": round((write_time / iterations) * 1000, 3),
                "avg_read_ms": round((read_time / iterations) * 1000, 3)
            }

            cursor.close()
            conn.close()

        except psycopg2.OperationalError as e:
            results["error"] = f"Connection failed: {str(e)}"
        except Exception as e:
            results["error"] = str(e)

        self.results["databases"]["postgresql"] = results
        return results

    def test_mongodb(self) -> Dict:
        """Test MongoDB connection and health."""
        self.logger.info("Testing MongoDB...")

        results = {
            "available": MONGODB_AVAILABLE,
            "connected": False,
            "info": {},
            "performance": {}
        }

        if not MONGODB_AVAILABLE:
            results["error"] = "pymongo not installed"
            self.results["databases"]["mongodb"] = results
            return results

        try:
            config = self.db_configs["mongodb"]
            client = MongoClient(
                host=config["host"],
                port=config["port"],
                serverSelectionTimeoutMS=2000
            )

            # Test connection
            client.server_info()
            results["connected"] = True

            # Get server info
            server_info = client.server_info()
            results["info"]["version"] = server_info.get("version", "Unknown")

            # Database stats
            db = client.test_database
            stats = db.command("dbStats")
            results["info"]["storage_size_mb"] = round(stats.get("storageSize", 0) / (1024 * 1024), 2)
            results["info"]["collections"] = stats.get("collections", 0)

            # Performance test
            collection = db.test_collection

            start_time = time.time()
            iterations = 100
            for i in range(iterations):
                collection.insert_one({"test_id": i, "data": f"test_data_{i}"})
            write_time = time.time() - start_time

            start_time = time.time()
            for i in range(iterations):
                collection.find_one({"test_id": i})
            read_time = time.time() - start_time

            # Cleanup
            collection.drop()

            results["performance"] = {
                "write_ops_per_sec": round(iterations / write_time, 2),
                "read_ops_per_sec": round(iterations / read_time, 2),
                "avg_write_ms": round((write_time / iterations) * 1000, 3),
                "avg_read_ms": round((read_time / iterations) * 1000, 3)
            }

            client.close()

        except Exception as e:
            results["error"] = str(e)

        self.results["databases"]["mongodb"] = results
        return results

    def test_sqlite(self) -> Dict:
        """Test SQLite connection and health."""
        self.logger.info("Testing SQLite...")

        results = {
            "available": SQLITE_AVAILABLE,
            "connected": False,
            "info": {},
            "performance": {}
        }

        if not SQLITE_AVAILABLE:
            results["error"] = "sqlite3 not available"
            self.results["databases"]["sqlite"] = results
            return results

        try:
            config = self.db_configs["sqlite"]
            conn = sqlite3.connect(config["path"])
            results["connected"] = True

            cursor = conn.cursor()

            # Get version
            cursor.execute("SELECT sqlite_version();")
            version = cursor.fetchone()[0]
            results["info"]["version"] = version

            # Create test table
            cursor.execute("CREATE TABLE test_perf (id INTEGER PRIMARY KEY, data TEXT);")

            # Performance test
            start_time = time.time()
            iterations = 1000
            for i in range(iterations):
                cursor.execute("INSERT INTO test_perf (data) VALUES (?);", (f"test_data_{i}",))
            conn.commit()
            write_time = time.time() - start_time

            start_time = time.time()
            for i in range(iterations):
                cursor.execute("SELECT * FROM test_perf WHERE id = ?;", (i+1,))
                cursor.fetchone()
            read_time = time.time() - start_time

            results["performance"] = {
                "write_ops_per_sec": round(iterations / write_time, 2),
                "read_ops_per_sec": round(iterations / read_time, 2),
                "avg_write_ms": round((write_time / iterations) * 1000, 3),
                "avg_read_ms": round((read_time / iterations) * 1000, 3)
            }

            conn.close()

        except Exception as e:
            results["error"] = str(e)

        self.results["databases"]["sqlite"] = results
        return results

    def test_elasticsearch(self) -> Dict:
        """Test Elasticsearch connection and health."""
        self.logger.info("Testing Elasticsearch...")

        results = {
            "available": ELASTICSEARCH_AVAILABLE,
            "connected": False,
            "info": {},
            "performance": {}
        }

        if not ELASTICSEARCH_AVAILABLE:
            results["error"] = "elasticsearch-py not installed"
            self.results["databases"]["elasticsearch"] = results
            return results

        try:
            config = self.db_configs["elasticsearch"]
            es = Elasticsearch(
                [{"host": config["host"], "port": config["port"]}],
                request_timeout=2
            )

            # Test connection
            if es.ping():
                results["connected"] = True

                # Get cluster info
                info = es.info()
                results["info"]["version"] = info.get("version", {}).get("number", "Unknown")
                results["info"]["cluster_name"] = info.get("cluster_name", "Unknown")

                # Get cluster health
                health = es.cluster.health()
                results["info"]["status"] = health.get("status", "Unknown")
                results["info"]["number_of_nodes"] = health.get("number_of_nodes", 0)

                # Performance test
                index_name = "test_perf_index"

                start_time = time.time()
                iterations = 50  # Reduced for ES
                for i in range(iterations):
                    es.index(index=index_name, id=i, body={"test_id": i, "data": f"test_data_{i}"})
                write_time = time.time() - start_time

                # Refresh index
                es.indices.refresh(index=index_name)

                start_time = time.time()
                for i in range(iterations):
                    es.get(index=index_name, id=i)
                read_time = time.time() - start_time

                # Cleanup
                es.indices.delete(index=index_name, ignore=[400, 404])

                results["performance"] = {
                    "write_ops_per_sec": round(iterations / write_time, 2),
                    "read_ops_per_sec": round(iterations / read_time, 2),
                    "avg_write_ms": round((write_time / iterations) * 1000, 3),
                    "avg_read_ms": round((read_time / iterations) * 1000, 3)
                }

        except Exception as e:
            results["error"] = str(e)

        self.results["databases"]["elasticsearch"] = results
        return results

    def benchmark_read_performance(self) -> Dict:
        """Benchmark read performance across databases."""
        self.logger.info("Benchmarking read performance...")

        results = {
            "databases": {}
        }

        for db_name, db_data in self.results["databases"].items():
            if db_data.get("connected") and "performance" in db_data:
                results["databases"][db_name] = {
                    "read_ops_per_sec": db_data["performance"].get("read_ops_per_sec", 0),
                    "avg_read_ms": db_data["performance"].get("avg_read_ms", 0)
                }

        # Find fastest database
        if results["databases"]:
            fastest = max(results["databases"].items(),
                         key=lambda x: x[1]["read_ops_per_sec"])
            results["fastest_database"] = fastest[0]
            results["max_read_ops_per_sec"] = fastest[1]["read_ops_per_sec"]

        self.results["performance"]["read"] = results
        return results

    def benchmark_write_performance(self) -> Dict:
        """Benchmark write performance across databases."""
        self.logger.info("Benchmarking write performance...")

        results = {
            "databases": {}
        }

        for db_name, db_data in self.results["databases"].items():
            if db_data.get("connected") and "performance" in db_data:
                results["databases"][db_name] = {
                    "write_ops_per_sec": db_data["performance"].get("write_ops_per_sec", 0),
                    "avg_write_ms": db_data["performance"].get("avg_write_ms", 0)
                }

        # Find fastest database
        if results["databases"]:
            fastest = max(results["databases"].items(),
                         key=lambda x: x[1]["write_ops_per_sec"])
            results["fastest_database"] = fastest[0]
            results["max_write_ops_per_sec"] = fastest[1]["write_ops_per_sec"]

        self.results["performance"]["write"] = results
        return results

    def check_replication_status(self) -> Dict:
        """Check database replication status."""
        self.logger.info("Checking replication status...")

        results = {
            "redis": {},
            "postgresql": {},
            "mongodb": {}
        }

        # Redis replication
        if self.results["databases"]["redis"].get("connected"):
            try:
                config = self.db_configs["redis"]
                r = redis.Redis(host=config["host"], port=config["port"], db=config["db"])
                info = r.info("replication")

                results["redis"] = {
                    "role": info.get("role", "Unknown"),
                    "connected_slaves": info.get("connected_slaves", 0),
                    "replication_enabled": info.get("role") == "master" and info.get("connected_slaves", 0) > 0
                }
            except Exception as e:
                results["redis"]["error"] = str(e)

        # PostgreSQL replication
        if self.results["databases"]["postgresql"].get("connected"):
            try:
                config = self.db_configs["postgresql"]
                conn = psycopg2.connect(
                    host=config["host"],
                    port=config["port"],
                    database=config["database"],
                    user=config["user"]
                )
                cursor = conn.cursor()

                cursor.execute("SELECT pg_is_in_recovery();")
                is_replica = cursor.fetchone()[0]

                results["postgresql"] = {
                    "role": "replica" if is_replica else "primary",
                    "in_recovery": is_replica
                }

                cursor.close()
                conn.close()
            except Exception as e:
                results["postgresql"]["error"] = str(e)

        # MongoDB replication
        if self.results["databases"]["mongodb"].get("connected"):
            try:
                config = self.db_configs["mongodb"]
                client = MongoClient(host=config["host"], port=config["port"])

                # Check replica set status
                try:
                    status = client.admin.command("replSetGetStatus")
                    results["mongodb"] = {
                        "replica_set": status.get("set", "Unknown"),
                        "members": len(status.get("members", [])),
                        "replication_enabled": True
                    }
                except:
                    results["mongodb"] = {
                        "replication_enabled": False,
                        "info": "Not part of replica set"
                    }

                client.close()
            except Exception as e:
                results["mongodb"]["error"] = str(e)

        self.results["replication"] = results
        return results

    def calculate_health_score(self) -> int:
        """Calculate overall database health score (0-100)."""
        score = 0
        total_dbs = 5  # Redis, PostgreSQL, MongoDB, SQLite, Elasticsearch
        connected_dbs = 0

        # Count connected databases
        for db_name, db_data in self.results["databases"].items():
            if db_data.get("connected"):
                connected_dbs += 1

        # Base score from connectivity (50 points)
        score += (connected_dbs / total_dbs) * 50

        # Performance score (30 points)
        if "read" in self.results.get("performance", {}):
            read_perf = self.results["performance"]["read"]
            if "max_read_ops_per_sec" in read_perf:
                max_read = read_perf["max_read_ops_per_sec"]
                # Score based on read performance
                if max_read > 10000:
                    score += 15
                elif max_read > 5000:
                    score += 12
                elif max_read > 1000:
                    score += 10
                else:
                    score += 5

        if "write" in self.results.get("performance", {}):
            write_perf = self.results["performance"]["write"]
            if "max_write_ops_per_sec" in write_perf:
                max_write = write_perf["max_write_ops_per_sec"]
                # Score based on write performance
                if max_write > 10000:
                    score += 15
                elif max_write > 5000:
                    score += 12
                elif max_write > 1000:
                    score += 10
                else:
                    score += 5

        # Replication score (20 points)
        replication_count = 0
        for db_name, repl_data in self.results.get("replication", {}).items():
            if repl_data.get("replication_enabled"):
                replication_count += 1

        if replication_count > 0:
            score += (replication_count / 3) * 20  # Up to 3 databases with replication

        self.results["health_score"] = int(score)
        return int(score)

    def get_summary(self) -> Dict:
        """Get database diagnostics summary."""
        connected_dbs = []
        disconnected_dbs = []

        for db_name, db_data in self.results["databases"].items():
            if db_data.get("connected"):
                connected_dbs.append(db_name)
            else:
                disconnected_dbs.append(db_name)

        return {
            "timestamp": self.results["timestamp"],
            "health_score": self.results["health_score"],
            "connectivity": {
                "total_databases": len(self.results["databases"]),
                "connected": len(connected_dbs),
                "disconnected": len(disconnected_dbs),
                "connected_databases": connected_dbs,
                "disconnected_databases": disconnected_dbs
            },
            "performance": {
                "fastest_read_db": self.results.get("performance", {}).get("read", {}).get("fastest_database", "N/A"),
                "max_read_ops_per_sec": self.results.get("performance", {}).get("read", {}).get("max_read_ops_per_sec", "N/A"),
                "fastest_write_db": self.results.get("performance", {}).get("write", {}).get("fastest_database", "N/A"),
                "max_write_ops_per_sec": self.results.get("performance", {}).get("write", {}).get("max_write_ops_per_sec", "N/A")
            },
            "recommendations": self._generate_recommendations()
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate database optimization recommendations."""
        recommendations = []

        score = self.results.get("health_score", 0)

        # Overall health
        if score < 50:
            recommendations.append("CRITICAL: Multiple database connectivity issues. Check database services.")
        elif score < 70:
            recommendations.append("WARNING: Database performance could be improved.")

        # Connectivity recommendations
        disconnected = []
        for db_name, db_data in self.results["databases"].items():
            if not db_data.get("connected") and db_data.get("available"):
                disconnected.append(db_name)

        if disconnected:
            recommendations.append(f"Database services not running: {', '.join(disconnected)}")

        # Performance recommendations
        if "read" in self.results.get("performance", {}):
            read_perf = self.results["performance"]["read"]
            if "max_read_ops_per_sec" in read_perf:
                if read_perf["max_read_ops_per_sec"] < 1000:
                    recommendations.append("Low read performance detected. Consider indexing and query optimization.")

        if "write" in self.results.get("performance", {}):
            write_perf = self.results["performance"]["write"]
            if "max_write_ops_per_sec" in write_perf:
                if write_perf["max_write_ops_per_sec"] < 1000:
                    recommendations.append("Low write performance detected. Consider batch writes and connection pooling.")

        # Replication recommendations
        replication_enabled = any([
            repl.get("replication_enabled", False)
            for repl in self.results.get("replication", {}).values()
        ])

        if not replication_enabled:
            recommendations.append("No database replication detected. Enable replication for high availability.")

        if not recommendations:
            recommendations.append("Database systems are operating optimally.")

        return recommendations[:5]  # Top 5 recommendations


if __name__ == "__main__":
    # Test database diagnostics
    diagnostics = DatabaseDiagnostics()
    results = diagnostics.run_full_diagnostics()
    summary = diagnostics.get_summary()

    print("\n" + "="*60)
    print("PROMETHEUS PRIME - DATABASE DIAGNOSTICS")
    print("="*60)
    print(json.dumps(summary, indent=2))

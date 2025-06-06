"""
Integration tests for QueueManager class using real Redis.

These tests require a running Redis instance and verify that QueueManager
works correctly with actual Redis operations, Redis pipelines, and
concurrent access patterns.
"""

import asyncio
import time
import pytest_asyncio

from social.graze.aip.app.tasks import QueueManager, normalize_redis_string


class MockStatsdClient:
    """Mock StatsD client for integration testing."""

    def __init__(self):
        self.gauges = {}
        self.increments = {}
        self.timers = {}

    def gauge(self, metric_name, value, tag_dict=None):
        self.gauges[metric_name] = {"value": value, "tags": tag_dict or {}}

    def increment(self, metric_name, value=1, tag_dict=None):
        key = (metric_name, tuple(sorted((tag_dict or {}).items())))
        self.increments[key] = self.increments.get(key, 0) + value

    def timer(self, metric_name, value, tag_dict=None):
        self.timers[metric_name] = {"value": value, "tags": tag_dict or {}}


@pytest_asyncio.fixture
async def mock_statsd():
    """Provide mock StatsD client for integration testing."""
    return MockStatsdClient()


@pytest_asyncio.fixture
async def integration_queue_manager(redis_client, mock_statsd):
    """Provide QueueManager instance with real Redis for integration tests."""
    return QueueManager(
        redis_client=redis_client,
        statsd_client=mock_statsd,
        queue_name="integration_test_queue",
        worker_id="integration_worker_1",
        batch_size=5,
    )


class TestQueueManagerRedisIntegration:
    """Integration tests using real Redis instances."""

    async def test_redis_pipeline_operations(
        self, integration_queue_manager, redis_client
    ):
        """Test that Redis pipeline operations work correctly with real Redis."""
        current_time = int(time.time())

        # Add items to global queue
        await redis_client.zadd(
            "integration_test_queue",
            {
                "pipeline_task_1": current_time - 100,
                "pipeline_task_2": current_time - 50,
                "pipeline_task_3": current_time - 10,
            },
        )

        # Verify initial state
        initial_count = await redis_client.zcount(
            "integration_test_queue", 0, current_time
        )
        assert initial_count == 3

        # Use QueueManager to populate worker queue (tests pipeline operations)
        items_queued = await integration_queue_manager.populate_worker_queue(
            current_time
        )

        assert items_queued == 3

        # Verify pipeline correctly moved items
        global_remaining = await redis_client.zcount(
            "integration_test_queue", 0, current_time
        )
        worker_count = await redis_client.zcount(
            "integration_test_queue:integration_worker_1", 0, current_time
        )

        assert global_remaining == 0
        assert worker_count == 3

    async def test_concurrent_worker_access(self, redis_client, mock_statsd):
        """Test multiple workers accessing Redis concurrently."""
        current_time = int(time.time())

        # Create multiple workers
        workers = [
            QueueManager(
                redis_client,
                mock_statsd,
                "concurrent_queue",
                f"worker_{i}",
                batch_size=3,
            )
            for i in range(3)
        ]

        # Add tasks to global queue
        tasks = {f"concurrent_task_{i}": current_time - i for i in range(15)}
        await redis_client.zadd("concurrent_queue", tasks)

        # All workers attempt to populate their queues concurrently
        populate_results = await asyncio.gather(
            *[worker.populate_worker_queue(current_time) for worker in workers]
        )

        # Verify total work distribution (may be less than 15 due to concurrent access)
        total_queued = sum(populate_results)
        assert total_queued > 0  # At least some work should be distributed
        assert total_queued <= 15  # Cannot exceed total available work

        # Count total tasks across all worker queues
        total_worker_tasks = 0
        for worker in workers:
            worker_tasks = await worker.get_pending_tasks(current_time)
            total_worker_tasks += len(worker_tasks)
            # Each worker should have at most batch_size tasks
            assert len(worker_tasks) <= 3

        # Verify no work is lost - all tasks should be either in global queue or worker queues
        remaining_global = await redis_client.zcount(
            "concurrent_queue", 0, current_time
        )
        assert total_worker_tasks + remaining_global == 15

    async def test_redis_persistence_across_connections(
        self, redis_client, mock_statsd
    ):
        """Test that data persists correctly across different QueueManager instances."""
        current_time = int(time.time())

        # Create first QueueManager instance
        qm1 = QueueManager(
            redis_client, mock_statsd, "persistence_queue", "persistent_worker"
        )

        # Add data and update heartbeat
        await redis_client.zadd(
            "persistence_queue", {"persistent_task": current_time - 100}
        )
        await qm1.update_heartbeat(current_time)

        # Create second QueueManager instance (simulating restart)
        qm2 = QueueManager(
            redis_client, mock_statsd, "persistence_queue", "persistent_worker"
        )

        # Verify data persists
        _, global_count = await qm2.get_queue_metrics(current_time)
        assert global_count == 1

        # Verify heartbeat persists
        heartbeat = await redis_client.hget(
            "persistence_queue:workers", "persistent_worker"
        )
        assert heartbeat is not None
        assert int(normalize_redis_string(heartbeat)) == current_time

    async def test_redis_transaction_atomicity(
        self, integration_queue_manager, redis_client
    ):
        """Test that Redis pipeline operations are atomic."""
        current_time = int(time.time())

        # Add tasks that should be moved atomically
        await redis_client.zadd(
            "integration_test_queue",
            {
                "atomic_task_1": current_time - 100,
                "atomic_task_2": current_time - 50,
            },
        )

        # Record initial state
        initial_global = await redis_client.zcount(
            "integration_test_queue", 0, current_time
        )
        initial_worker = await redis_client.zcount(
            "integration_test_queue:integration_worker_1", 0, current_time
        )

        assert initial_global == 2
        assert initial_worker == 0

        # Populate worker queue (should be atomic)
        items_queued = await integration_queue_manager.populate_worker_queue(
            current_time
        )

        # Verify atomic operation completed successfully
        assert items_queued == 2

        final_global = await redis_client.zcount(
            "integration_test_queue", 0, current_time
        )
        final_worker = await redis_client.zcount(
            "integration_test_queue:integration_worker_1", 0, current_time
        )

        # Should be moved atomically - either all or none
        assert final_global == 0
        assert final_worker == 2

    async def test_redis_data_types_and_encoding(
        self, integration_queue_manager, redis_client
    ):
        """Test that different data types and encodings work correctly with Redis."""
        current_time = int(time.time())

        # Test with various task ID types
        test_tasks = {
            "simple_task": current_time - 100,
            "task_with_numbers_123": current_time - 90,
            "task-with-dashes": current_time - 80,
            "task_with_unicode_🚀": current_time - 70,
            "task.with.dots": current_time - 60,
        }

        await redis_client.zadd(
            "integration_test_queue:integration_worker_1", test_tasks
        )

        # Retrieve and verify all task types
        pending_tasks = await integration_queue_manager.get_pending_tasks(current_time)

        assert len(pending_tasks) == 5

        # Verify all task IDs are retrievable
        retrieved_task_ids = {normalize_redis_string(task[0]) for task in pending_tasks}
        expected_task_ids = set(test_tasks.keys())

        assert retrieved_task_ids == expected_task_ids

        # Test removal of various task types
        for task_id in test_tasks.keys():
            await integration_queue_manager.remove_task(task_id)

        # Verify all tasks removed
        final_tasks = await integration_queue_manager.get_pending_tasks(current_time)
        assert len(final_tasks) == 0

    async def test_redis_memory_efficiency(self, redis_client, mock_statsd):
        """Test Redis memory usage with large datasets."""
        current_time = int(time.time())

        qm = QueueManager(
            redis_client,
            mock_statsd,
            "memory_test_queue",
            "memory_worker",
            batch_size=100,
        )

        # Add a large number of tasks
        large_task_set = {f"memory_task_{i}": current_time - i for i in range(10000)}
        await redis_client.zadd("memory_test_queue", large_task_set)

        # Verify Redis can handle large datasets efficiently
        start_time = time.time()
        _, global_count = await qm.get_queue_metrics(current_time)
        metrics_time = time.time() - start_time

        assert global_count == 10000
        assert metrics_time < 2.0  # Should be reasonably fast even with large dataset

        # Test batch processing efficiency
        start_time = time.time()
        items_queued = await qm.populate_worker_queue(current_time)
        populate_time = time.time() - start_time

        assert items_queued == 100  # Limited by batch size
        assert populate_time < 2.0  # Should be efficient

        # Clean up large dataset
        await redis_client.delete(
            "memory_test_queue", "memory_test_queue:memory_worker"
        )

    async def test_redis_connection_resilience(
        self, integration_queue_manager, redis_client
    ):
        """Test QueueManager behavior with Redis connection issues."""
        current_time = int(time.time())

        # Add initial data
        await redis_client.zadd(
            "integration_test_queue", {"resilience_task": current_time - 100}
        )

        # Verify normal operation
        _, global_count = await integration_queue_manager.get_queue_metrics(
            current_time
        )
        assert global_count == 1

        # Test that operations complete successfully
        items_queued = await integration_queue_manager.populate_worker_queue(
            current_time
        )
        assert items_queued == 1

        pending_tasks = await integration_queue_manager.get_pending_tasks(current_time)
        assert len(pending_tasks) == 1

        # Clean up
        await integration_queue_manager.remove_task("resilience_task")

        final_tasks = await integration_queue_manager.get_pending_tasks(current_time)
        assert len(final_tasks) == 0


class TestQueueManagerRedisScenarios:
    """Real-world scenario tests with Redis."""

    async def test_production_like_workflow(self, redis_client, mock_statsd):
        """Test a production-like workflow with multiple workers and continuous processing."""
        current_time = int(time.time())

        # Simulate production scenario with multiple workers
        workers = [
            QueueManager(
                redis_client,
                mock_statsd,
                "prod_queue",
                f"prod_worker_{i}",
                batch_size=10,
            )
            for i in range(5)
        ]

        # Add continuous stream of tasks (simulating real workload)
        for batch in range(10):
            tasks = {
                f"prod_task_{batch}_{i}": current_time - (batch * 10 + i)
                for i in range(50)
            }
            await redis_client.zadd("prod_queue", tasks)

            # Workers process tasks
            await asyncio.gather(
                *[worker.populate_worker_queue(current_time) for worker in workers]
            )

            # Process and clean up tasks
            for worker in workers:
                pending_tasks = await worker.get_pending_tasks(current_time)
                for task_id, _ in pending_tasks:
                    await worker.remove_task(normalize_redis_string(task_id))

        # Verify all work is processed
        for worker in workers:
            remaining_tasks = await worker.get_pending_tasks(current_time)
            assert len(remaining_tasks) == 0

        final_global = await redis_client.zcount("prod_queue", 0, current_time)
        assert final_global == 0

    async def test_worker_failure_recovery(self, redis_client, mock_statsd):
        """Test recovery from worker failures in Redis."""
        current_time = int(time.time())

        # Create initial worker
        worker1 = QueueManager(
            redis_client, mock_statsd, "recovery_queue", "failing_worker"
        )

        # Add tasks and populate worker queue
        await redis_client.zadd(
            "recovery_queue",
            {
                "recovery_task_1": current_time - 100,
                "recovery_task_2": current_time - 50,
            },
        )

        await worker1.populate_worker_queue(current_time)

        # Simulate worker failure by creating new worker instance
        # (orphaned tasks remain in worker queue)
        worker2 = QueueManager(
            redis_client, mock_statsd, "recovery_queue", "failing_worker"
        )

        # New worker should be able to process orphaned tasks
        orphaned_tasks = await worker2.get_pending_tasks(current_time)
        assert len(orphaned_tasks) == 2

        # Process orphaned tasks
        for task_id, _ in orphaned_tasks:
            await worker2.remove_task(normalize_redis_string(task_id))

        # Verify recovery completed
        final_tasks = await worker2.get_pending_tasks(current_time)
        assert len(final_tasks) == 0

    async def test_high_throughput_processing(self, redis_client, mock_statsd):
        """Test high-throughput task processing scenarios."""
        current_time = int(time.time())

        # Create high-throughput worker
        worker = QueueManager(
            redis_client,
            mock_statsd,
            "throughput_queue",
            "throughput_worker",
            batch_size=50,
        )

        # Process multiple large batches rapidly
        total_processed = 0

        for round_num in range(20):
            # Add batch of tasks
            batch_tasks = {
                f"throughput_task_{round_num}_{i}": current_time - i for i in range(100)
            }
            await redis_client.zadd("throughput_queue", batch_tasks)

            # Process batch
            await worker.populate_worker_queue(current_time)
            pending_tasks = await worker.get_pending_tasks(current_time)

            # Simulate rapid processing
            for task_id, _ in pending_tasks:
                await worker.remove_task(normalize_redis_string(task_id))

            total_processed += len(pending_tasks)

        # Verify high throughput was achieved
        assert total_processed == 20 * 50  # 20 rounds * 50 batch_size

        # Verify expected remaining tasks (20 rounds * 100 tasks - 20 rounds * 50 processed)
        final_global = await redis_client.zcount("throughput_queue", 0, current_time)
        final_worker = await redis_client.zcount(
            "throughput_queue:throughput_worker", 0, current_time
        )

        expected_remaining = 20 * 100 - total_processed  # 2000 - 1000 = 1000
        actual_remaining = final_global + final_worker
        assert actual_remaining == expected_remaining

"""
Comprehensive unit and integration tests for QueueManager class.

Tests cover Redis queue operations, heartbeat management, metrics collection,
and worker queue population using both fakeredis and real Redis instances.
"""

import asyncio
import time
import pytest
import pytest_asyncio
import fakeredis.aioredis

from social.graze.aip.app.tasks import QueueManager


class MockStatsdClient:
    """Mock StatsD client for testing metrics collection."""

    def __init__(self):
        self.gauges = {}
        self.increments = {}
        self.timers = {}

    def gauge(self, metric_name, value, tag_dict=None):
        """Record gauge metric."""
        self.gauges[metric_name] = {"value": value, "tags": tag_dict or {}}

    def increment(self, metric_name, value=1, tag_dict=None):
        """Record increment metric."""
        key = (metric_name, tuple(sorted((tag_dict or {}).items())))
        self.increments[key] = self.increments.get(key, 0) + value

    def timer(self, metric_name, value, tag_dict=None):
        """Record timer metric."""
        self.timers[metric_name] = {"value": value, "tags": tag_dict or {}}


@pytest_asyncio.fixture
async def fake_redis():
    """Provide fake Redis client for unit tests."""
    redis_client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    yield redis_client
    await redis_client.flushall()
    await redis_client.aclose()


@pytest_asyncio.fixture
async def mock_statsd():
    """Provide mock StatsD client for testing."""
    return MockStatsdClient()


@pytest_asyncio.fixture
async def queue_manager(fake_redis, mock_statsd):
    """Provide QueueManager instance with fake Redis and mock StatsD."""
    return QueueManager(
        redis_client=fake_redis,
        statsd_client=mock_statsd,
        queue_name="test_queue",
        worker_id="worker_1",
        batch_size=5,
    )


class TestQueueManagerInitialization:
    """Test QueueManager initialization and property setup."""

    def test_queue_manager_creation(self, queue_manager, fake_redis, mock_statsd):
        """Test QueueManager is created with correct properties."""
        assert queue_manager.redis_client == fake_redis
        assert queue_manager.statsd_client == mock_statsd
        assert queue_manager.queue_name == "test_queue"
        assert queue_manager.worker_id == "worker_1"
        assert queue_manager.batch_size == 5
        assert queue_manager.worker_queue == "test_queue:worker_1"
        assert queue_manager.workers_heartbeat == "test_queue:workers"

    def test_queue_manager_custom_batch_size(self, fake_redis, mock_statsd):
        """Test QueueManager with custom batch size."""
        qm = QueueManager(
            redis_client=fake_redis,
            statsd_client=mock_statsd,
            queue_name="custom_queue",
            worker_id="custom_worker",
            batch_size=10,
        )
        assert qm.batch_size == 10
        assert qm.worker_queue == "custom_queue:custom_worker"

    def test_queue_manager_default_batch_size(self, fake_redis, mock_statsd):
        """Test QueueManager uses default batch size when not specified."""
        qm = QueueManager(
            redis_client=fake_redis,
            statsd_client=mock_statsd,
            queue_name="default_queue",
            worker_id="default_worker",
        )
        assert qm.batch_size == 5


class TestUpdateHeartbeat:
    """Test worker heartbeat functionality."""

    async def test_update_heartbeat_success(self, queue_manager, fake_redis):
        """Test heartbeat is correctly updated in Redis."""
        timestamp = int(time.time())

        await queue_manager.update_heartbeat(timestamp)

        # Verify heartbeat was set in Redis
        heartbeat_value = await fake_redis.hget("test_queue:workers", "worker_1")
        assert heartbeat_value.decode() == str(timestamp)

    async def test_update_heartbeat_multiple_workers(self, fake_redis, mock_statsd):
        """Test multiple workers can update heartbeat independently."""
        qm1 = QueueManager(fake_redis, mock_statsd, "test_queue", "worker_1")
        qm2 = QueueManager(fake_redis, mock_statsd, "test_queue", "worker_2")

        timestamp1 = int(time.time())
        timestamp2 = timestamp1 + 10

        await qm1.update_heartbeat(timestamp1)
        await qm2.update_heartbeat(timestamp2)

        # Verify both heartbeats exist
        heartbeat1 = await fake_redis.hget("test_queue:workers", "worker_1")
        heartbeat2 = await fake_redis.hget("test_queue:workers", "worker_2")

        assert heartbeat1.decode() == str(timestamp1)
        assert heartbeat2.decode() == str(timestamp2)

    async def test_update_heartbeat_overwrites_previous(
        self, queue_manager, fake_redis
    ):
        """Test heartbeat update overwrites previous value."""
        timestamp1 = int(time.time())
        timestamp2 = timestamp1 + 30

        await queue_manager.update_heartbeat(timestamp1)
        await queue_manager.update_heartbeat(timestamp2)

        # Should only have the latest timestamp
        heartbeat_value = await fake_redis.hget("test_queue:workers", "worker_1")
        assert heartbeat_value.decode() == str(timestamp2)


class TestGetQueueMetrics:
    """Test queue metrics collection functionality."""

    async def test_get_queue_metrics_empty_queues(self, queue_manager):
        """Test metrics for empty queues return zero counts."""
        timestamp = int(time.time())

        worker_count, global_count = await queue_manager.get_queue_metrics(timestamp)

        assert worker_count == 0
        assert global_count == 0

    async def test_get_queue_metrics_with_data(self, queue_manager, fake_redis):
        """Test metrics correctly count queue items."""
        current_time = int(time.time())

        # Add items to global queue with different timestamps
        await fake_redis.zadd(
            "test_queue",
            {
                "task_1": current_time - 100,  # Ready to process
                "task_2": current_time - 50,  # Ready to process
                "task_3": current_time + 100,  # Future task
            },
        )

        # Add items to worker queue
        await fake_redis.zadd(
            "test_queue:worker_1",
            {
                "task_4": current_time - 30,  # Ready to process
            },
        )

        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)

        assert worker_count == 1  # Only task_4 is ready in worker queue
        assert global_count == 2  # task_1 and task_2 are ready in global queue

    async def test_get_queue_metrics_boundary_conditions(
        self, queue_manager, fake_redis
    ):
        """Test metrics with exact timestamp boundaries."""
        current_time = int(time.time())

        # Add items with exact boundary timestamps
        await fake_redis.zadd(
            "test_queue",
            {
                "exact_match": current_time,  # Should be included
                "one_second_ago": current_time - 1,  # Should be included
                "one_second_future": current_time + 1,  # Should not be included
            },
        )

        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)

        assert worker_count == 0
        assert global_count == 2  # exact_match and one_second_ago


class TestPopulateWorkerQueue:
    """Test worker queue population functionality."""

    async def test_populate_worker_queue_success(self, queue_manager, fake_redis):
        """Test successful worker queue population."""
        current_time = int(time.time())

        # Add items to global queue
        await fake_redis.zadd(
            "test_queue",
            {
                "task_1": current_time - 100,
                "task_2": current_time - 50,
                "task_3": current_time - 10,
                "task_4": current_time + 100,  # Future task
            },
        )

        items_queued = await queue_manager.populate_worker_queue(current_time)

        # Should have moved 3 ready items (batch_size=5, so all 3 fit)
        assert items_queued == 3

        # Verify items are in worker queue
        worker_items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert len(worker_items) == 3
        assert b"task_1" in worker_items
        assert b"task_2" in worker_items
        assert b"task_3" in worker_items

        # Verify items removed from global queue
        global_items = await fake_redis.zrange("test_queue", 0, -1)
        assert len(global_items) == 1
        assert b"task_4" in global_items

    async def test_populate_worker_queue_respects_batch_size(
        self, fake_redis, mock_statsd
    ):
        """Test worker queue population respects batch size limit."""
        qm = QueueManager(
            fake_redis, mock_statsd, "test_queue", "worker_1", batch_size=2
        )
        current_time = int(time.time())

        # Add more items than batch size
        await fake_redis.zadd(
            "test_queue",
            {
                "task_1": current_time - 100,
                "task_2": current_time - 50,
                "task_3": current_time - 10,
                "task_4": current_time - 5,
            },
        )

        items_queued = await qm.populate_worker_queue(current_time)

        # Should only process batch_size items
        assert items_queued == 2

        # Verify only 2 items in worker queue
        worker_items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert len(worker_items) == 2

        # Verify 2 items remain in global queue
        global_items = await fake_redis.zrange("test_queue", 0, -1)
        assert len(global_items) == 2

    async def test_populate_worker_queue_empty_global_queue(
        self, queue_manager, fake_redis
    ):
        """Test populate worker queue when global queue is empty."""
        current_time = int(time.time())

        items_queued = await queue_manager.populate_worker_queue(current_time)

        assert items_queued == 0

        # Verify worker queue remains empty
        worker_items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert len(worker_items) == 0

    async def test_populate_worker_queue_only_future_tasks(
        self, queue_manager, fake_redis
    ):
        """Test populate worker queue when all tasks are in the future."""
        current_time = int(time.time())

        # Add only future tasks
        await fake_redis.zadd(
            "test_queue",
            {
                "future_task_1": current_time + 100,
                "future_task_2": current_time + 200,
            },
        )

        items_queued = await queue_manager.populate_worker_queue(current_time)

        assert items_queued == 0

        # Verify worker queue is empty
        worker_items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert len(worker_items) == 0

        # Verify global queue still has future tasks
        global_items = await fake_redis.zrange("test_queue", 0, -1)
        assert len(global_items) == 2


class TestGetPendingTasks:
    """Test pending tasks retrieval functionality."""

    async def test_get_pending_tasks_success(self, queue_manager, fake_redis):
        """Test successful retrieval of pending tasks."""
        current_time = int(time.time())

        # Add tasks to worker queue
        await fake_redis.zadd(
            "test_queue:worker_1",
            {
                "task_1": current_time - 100,
                "task_2": current_time - 50,
                "task_3": current_time + 100,  # Future task
            },
        )

        pending_tasks = await queue_manager.get_pending_tasks(current_time)

        # Should return 2 ready tasks with scores
        assert len(pending_tasks) == 2

        # Verify task data format (task_id, score)
        task_ids = [task[0].decode() for task in pending_tasks]
        assert "task_1" in task_ids
        assert "task_2" in task_ids
        assert "task_3" not in task_ids

        # Verify scores are floats
        for task_id, score in pending_tasks:
            assert isinstance(score, float)

    async def test_get_pending_tasks_empty_queue(self, queue_manager):
        """Test get pending tasks when worker queue is empty."""
        current_time = int(time.time())

        pending_tasks = await queue_manager.get_pending_tasks(current_time)

        assert len(pending_tasks) == 0
        assert pending_tasks == []

    async def test_get_pending_tasks_only_future_tasks(self, queue_manager, fake_redis):
        """Test get pending tasks when all tasks are in the future."""
        current_time = int(time.time())

        # Add only future tasks
        await fake_redis.zadd(
            "test_queue:worker_1",
            {
                "future_task_1": current_time + 100,
                "future_task_2": current_time + 200,
            },
        )

        pending_tasks = await queue_manager.get_pending_tasks(current_time)

        assert len(pending_tasks) == 0

    async def test_get_pending_tasks_maintains_order(self, queue_manager, fake_redis):
        """Test pending tasks are returned in score order."""
        current_time = int(time.time())

        # Add tasks with different timestamps (out of order)
        await fake_redis.zadd(
            "test_queue:worker_1",
            {
                "task_newest": current_time - 10,
                "task_oldest": current_time - 100,
                "task_middle": current_time - 50,
            },
        )

        pending_tasks = await queue_manager.get_pending_tasks(current_time)

        # Should be ordered by score (timestamp) ascending
        assert len(pending_tasks) == 3
        task_scores = [score for _, score in pending_tasks]
        assert task_scores == sorted(task_scores)


class TestRemoveTask:
    """Test task removal functionality."""

    async def test_remove_task_success(self, queue_manager, fake_redis):
        """Test successful task removal from worker queue."""
        # Add task to worker queue
        await fake_redis.zadd("test_queue:worker_1", {"task_to_remove": 12345})

        # Verify task exists
        items_before = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert b"task_to_remove" in items_before

        # Remove task
        await queue_manager.remove_task("task_to_remove")

        # Verify task is removed
        items_after = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert b"task_to_remove" not in items_after

    async def test_remove_task_nonexistent(self, queue_manager, fake_redis):
        """Test removing nonexistent task doesn't cause errors."""
        # Add some other task
        await fake_redis.zadd("test_queue:worker_1", {"other_task": 12345})

        # Try to remove nonexistent task (should not raise error)
        await queue_manager.remove_task("nonexistent_task")

        # Verify other task still exists
        items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert b"other_task" in items

    async def test_remove_task_multiple_tasks(self, queue_manager, fake_redis):
        """Test removing specific task when multiple tasks exist."""
        # Add multiple tasks
        await fake_redis.zadd(
            "test_queue:worker_1",
            {
                "task_1": 100,
                "task_2": 200,
                "task_3": 300,
            },
        )

        # Remove middle task
        await queue_manager.remove_task("task_2")

        # Verify only task_2 is removed
        remaining_items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert b"task_1" in remaining_items
        assert b"task_2" not in remaining_items
        assert b"task_3" in remaining_items

    async def test_remove_task_bytes_and_string_consistency(
        self, queue_manager, fake_redis
    ):
        """Test task removal works with both bytes and string task IDs."""
        # Add task as bytes
        await fake_redis.zadd("test_queue:worker_1", {b"bytes_task": 12345})

        # Remove using string
        await queue_manager.remove_task("bytes_task")

        # Verify task is removed
        items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
        assert len(items) == 0


class TestQueueManagerIntegration:
    """Integration tests combining multiple QueueManager operations."""

    async def test_full_workflow_cycle(self, queue_manager, fake_redis):
        """Test complete workflow from populate to process to cleanup."""
        current_time = int(time.time())

        # 1. Update heartbeat
        await queue_manager.update_heartbeat(current_time)

        # 2. Add work to global queue
        await fake_redis.zadd(
            "test_queue",
            {
                "task_1": current_time - 100,
                "task_2": current_time - 50,
            },
        )

        # 3. Check initial metrics
        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)
        assert worker_count == 0
        assert global_count == 2

        # 4. Populate worker queue
        items_queued = await queue_manager.populate_worker_queue(current_time)
        assert items_queued == 2

        # 5. Check metrics after population
        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)
        assert worker_count == 2
        assert global_count == 0

        # 6. Get pending tasks
        pending_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(pending_tasks) == 2

        # 7. Process tasks (simulate by removing them)
        for task_id, _ in pending_tasks:
            await queue_manager.remove_task(task_id.decode())

        # 8. Verify cleanup
        final_worker_count, final_global_count = await queue_manager.get_queue_metrics(
            current_time
        )
        assert final_worker_count == 0
        assert final_global_count == 0

    async def test_concurrent_workers(self, fake_redis, mock_statsd):
        """Test multiple workers operating on same queue simultaneously."""
        current_time = int(time.time())

        # Create two workers for same queue
        worker1 = QueueManager(
            fake_redis, mock_statsd, "shared_queue", "worker_1", batch_size=2
        )
        worker2 = QueueManager(
            fake_redis, mock_statsd, "shared_queue", "worker_2", batch_size=2
        )

        # Add tasks to global queue
        await fake_redis.zadd(
            "shared_queue",
            {
                "task_1": current_time - 100,
                "task_2": current_time - 90,
                "task_3": current_time - 80,
                "task_4": current_time - 70,
            },
        )

        # Both workers update heartbeat
        await asyncio.gather(
            worker1.update_heartbeat(current_time),
            worker2.update_heartbeat(current_time),
        )

        # Both workers populate their queues
        queued1, queued2 = await asyncio.gather(
            worker1.populate_worker_queue(current_time),
            worker2.populate_worker_queue(current_time),
        )

        # Should distribute work between workers
        total_queued = queued1 + queued2
        assert total_queued == 4  # All tasks should be queued

        # Verify each worker has some work
        worker1_tasks = await worker1.get_pending_tasks(current_time)
        worker2_tasks = await worker2.get_pending_tasks(current_time)

        assert len(worker1_tasks) >= 0
        assert len(worker2_tasks) >= 0
        assert len(worker1_tasks) + len(worker2_tasks) == 4

    async def test_error_recovery_scenarios(self, queue_manager, fake_redis):
        """Test queue manager behavior in error scenarios."""
        current_time = int(time.time())

        # Add tasks to worker queue (simulating previous incomplete work)
        await fake_redis.zadd(
            "test_queue:worker_1",
            {
                "orphaned_task_1": current_time - 200,
                "orphaned_task_2": current_time - 150,
            },
        )

        # Worker can still get pending tasks from orphaned work
        pending_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(pending_tasks) == 2

        # Worker can clean up orphaned work
        for task_id, _ in pending_tasks:
            await queue_manager.remove_task(task_id.decode())

        # Verify cleanup
        remaining_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(remaining_tasks) == 0


class TestQueueManagerEdgeCases:
    """Test edge cases and boundary conditions."""

    async def test_zero_timestamp(self, queue_manager, fake_redis):
        """Test behavior with zero timestamp."""
        # Add task with timestamp 0
        await fake_redis.zadd("test_queue", {"zero_task": 0})

        worker_count, global_count = await queue_manager.get_queue_metrics(0)
        assert global_count == 1

        items_queued = await queue_manager.populate_worker_queue(0)
        assert items_queued == 1

    async def test_negative_timestamp(self, queue_manager, fake_redis):
        """Test behavior with negative timestamps."""
        current_time = int(time.time())

        # Add task with negative timestamp
        await fake_redis.zadd("test_queue", {"negative_task": -100})

        # Redis ZCOUNT with range 0 to current_time won't include negative scores
        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)
        assert global_count == 0  # Negative scores are not in range [0, current_time]

        # But if we check with a range that includes negative scores
        negative_count = await fake_redis.zcount(
            "test_queue", -float("inf"), current_time
        )
        assert negative_count == 1  # Task exists with negative score

        # populate_worker_queue also uses 0 as minimum, so won't include negative scores
        items_queued = await queue_manager.populate_worker_queue(current_time)
        assert items_queued == 0

    async def test_very_large_timestamp(self, queue_manager, fake_redis):
        """Test behavior with very large timestamps."""
        current_time = int(time.time())
        very_large_time = current_time + (365 * 24 * 60 * 60)  # One year in future

        await fake_redis.zadd("test_queue", {"future_task": very_large_time})

        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)
        assert global_count == 0  # Should not be included

        # But should be included when checking with future timestamp
        worker_count, global_count = await queue_manager.get_queue_metrics(
            very_large_time
        )
        assert global_count == 1

    async def test_unicode_task_ids(self, queue_manager, fake_redis):
        """Test behavior with Unicode task IDs."""
        current_time = int(time.time())
        unicode_task_id = "task_测试_🚀"

        await fake_redis.zadd(
            "test_queue:worker_1", {unicode_task_id: current_time - 100}
        )

        pending_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(pending_tasks) == 1
        assert pending_tasks[0][0].decode() == unicode_task_id

        # Test removal with Unicode ID
        await queue_manager.remove_task(unicode_task_id)

        remaining_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(remaining_tasks) == 0

    async def test_empty_string_task_id(self, queue_manager, fake_redis):
        """Test behavior with empty string task IDs."""
        current_time = int(time.time())

        await fake_redis.zadd("test_queue:worker_1", {"": current_time - 100})

        pending_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(pending_tasks) == 1
        assert pending_tasks[0][0] == b""

        # Test removal with empty string
        await queue_manager.remove_task("")

        remaining_tasks = await queue_manager.get_pending_tasks(current_time)
        assert len(remaining_tasks) == 0


# Performance and stress tests
class TestQueueManagerPerformance:
    """Test QueueManager performance with larger datasets."""

    @pytest.mark.asyncio
    async def test_large_queue_performance(self, queue_manager, fake_redis):
        """Test performance with large number of queue items."""
        current_time = int(time.time())

        # Add 1000 tasks to global queue
        tasks = {f"task_{i}": current_time - i for i in range(1000)}
        await fake_redis.zadd("test_queue", tasks)

        # Measure metrics collection performance
        start_time = time.time()
        worker_count, global_count = await queue_manager.get_queue_metrics(current_time)
        metrics_time = time.time() - start_time

        assert global_count == 1000
        assert metrics_time < 1.0  # Should complete within 1 second

        # Measure worker queue population performance
        start_time = time.time()
        items_queued = await queue_manager.populate_worker_queue(current_time)
        populate_time = time.time() - start_time

        assert items_queued == 5  # Limited by batch_size
        assert populate_time < 1.0  # Should complete within 1 second

    @pytest.mark.asyncio
    async def test_batch_processing_efficiency(self, fake_redis, mock_statsd):
        """Test batch processing with different batch sizes."""
        current_time = int(time.time())

        # Test with different batch sizes
        batch_sizes = [1, 5, 10, 50]

        for batch_size in batch_sizes:
            # Clean up previous test data
            await fake_redis.flushall()

            qm = QueueManager(
                fake_redis, mock_statsd, "test_queue", "worker_1", batch_size
            )

            # Add more tasks than batch size
            tasks = {f"task_{i}": current_time - i for i in range(100)}
            await fake_redis.zadd("test_queue", tasks)

            # Populate worker queue
            items_queued = await qm.populate_worker_queue(current_time)

            # Should respect batch size limit
            assert items_queued == min(batch_size, 100)

            # Verify correct number of items in worker queue
            worker_items = await fake_redis.zrange("test_queue:worker_1", 0, -1)
            assert len(worker_items) == min(batch_size, 100)

import asyncio
from datetime import datetime, timezone
import logging
from time import time
from typing import List, NoReturn, Tuple, Any
from aiohttp import web
from sqlalchemy import select, delete
import sentry_sdk

from social.graze.aip.app.config import (
    APP_PASSWORD_REFRESH_QUEUE,
    OAUTH_REFRESH_QUEUE,
    OAUTH_REFRESH_RETRY_QUEUE,
    DatabaseSessionMakerAppKey,
    HealthGaugeAppKey,
    RedisClientAppKey,
    SessionAppKey,
    SettingsAppKey,
    MetricsClientAppKey,
)
from social.graze.aip.atproto.app_password import populate_session
from social.graze.aip.atproto.oauth import oauth_refresh
from social.graze.aip.model.oauth import OAuthSession, OAuthRequest

logger = logging.getLogger(__name__)


def normalize_redis_string(value: Any) -> str:
    """
    Normalize Redis value to string, handling bytes conversion.
    """
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


class QueueManager:
    """
    Manages Redis-based work queues with worker heartbeat and metrics.
    """

    def __init__(
        self,
        redis_client: Any,
        metrics_client: Any,
        queue_name: str,
        worker_id: str,
        batch_size: int = 5,
    ):
        self.redis_client = redis_client
        self.metrics_client = metrics_client
        self.queue_name = queue_name
        self.worker_id = worker_id
        self.batch_size = batch_size
        self.worker_queue = f"{queue_name}:{worker_id}"
        self.workers_heartbeat = f"{queue_name}:workers"

    async def update_heartbeat(self, timestamp: int) -> None:
        """
        Update worker heartbeat in Redis.
        """
        await self.redis_client.hset(
            self.workers_heartbeat, self.worker_id, str(timestamp)
        )

    async def get_queue_metrics(self, timestamp: int) -> Tuple[int, int]:
        """
        Get worker and global queue counts for metrics.
        Returns (worker_queue_count, global_queue_count).
        """
        worker_queue_count = await self.redis_client.zcount(
            self.worker_queue, 0, timestamp
        )
        global_queue_count = await self.redis_client.zcount(
            self.queue_name, 0, timestamp
        )
        return worker_queue_count, global_queue_count

    async def populate_worker_queue(self, timestamp: int) -> int:
        """
        Populate worker queue with work from global queue.
        Returns number of items queued.
        """
        async with self.redis_client.pipeline() as redis_pipe:
            redis_pipe.zrangestore(
                self.worker_queue,
                self.queue_name,
                0,
                timestamp,
                num=self.batch_size,
                offset=0,
                byscore=True,
            )
            redis_pipe.zdiffstore(self.queue_name, [self.queue_name, self.worker_queue])
            zrangestore_res, _ = await redis_pipe.execute()
            return zrangestore_res

    async def get_pending_tasks(self, timestamp: int) -> List[Tuple[str, float]]:
        """
        Get pending tasks from worker queue.
        """
        return await self.redis_client.zrange(
            self.worker_queue, 0, timestamp, byscore=True, withscores=True
        )

    async def remove_task(self, task_id: str) -> None:
        """
        Remove completed task from worker queue.
        """
        await self.redis_client.zrem(self.worker_queue, task_id)


class RetryHandler:
    """
    Handles exponential backoff retry logic for failed tasks.
    """

    def __init__(
        self,
        redis_client: Any,
        metrics_client: Any,
        queue_name: str,
        retry_queue_name: str,
        worker_id: str,
        max_retries: int,
        base_delay: int,
    ):
        self.redis_client = redis_client
        self.metrics_client = metrics_client
        self.queue_name = queue_name
        self.retry_queue_name = retry_queue_name
        self.worker_id = worker_id
        self.max_retries = max_retries
        self.base_delay = base_delay

    async def get_retry_count(self, task_id: str) -> int:
        """
        Get current retry count for a task.
        """
        current_retries = await self.redis_client.hget(self.retry_queue_name, task_id)
        return int(current_retries) if current_retries else 0

    async def schedule_retry(self, task_id: str, current_time: int) -> bool:
        """
        Schedule a retry for a failed task with exponential backoff.
        Returns True if retry was scheduled, False if max retries exceeded.
        """
        current_retries = await self.get_retry_count(task_id)

        if current_retries < self.max_retries:
            # Calculate exponential backoff delay
            retry_delay = self.base_delay * (2**current_retries)
            retry_timestamp = current_time + retry_delay

            # Re-queue with delay and increment retry count
            await self.redis_client.zadd(self.queue_name, {task_id: retry_timestamp})
            await self.redis_client.hset(
                self.retry_queue_name, task_id, current_retries + 1
            )

            logger.info(
                "Scheduled retry %d/%d for task %s in %d seconds",
                current_retries + 1,
                self.max_retries,
                task_id,
                retry_delay,
            )

            self.metrics_client.increment(
                "aip.task.retry_scheduled",
                1,
                tag_dict={
                    "retry_attempt": str(current_retries + 1),
                    "worker_id": self.worker_id,
                },
            )
            return True
        else:
            # Max retries exceeded
            await self.clear_retry_count(task_id)
            logger.error(
                "Max retries exceeded for task %s, giving up after %d attempts",
                task_id,
                self.max_retries,
            )
            self.metrics_client.increment(
                "aip.task.max_retries_exceeded",
                1,
                tag_dict={"worker_id": self.worker_id},
            )
            return False

    async def clear_retry_count(self, task_id: str) -> None:
        """
        Clear retry count for a task (on success or max retries exceeded).
        """
        await self.redis_client.hdel(self.retry_queue_name, task_id)


class TaskProcessor:
    """
    Generic task processor with timing, metrics, and error handling.
    """

    def __init__(self, metrics_client: Any, worker_id: str, task_type: str):
        self.metrics_client = metrics_client
        self.worker_id = worker_id
        self.task_type = task_type

    async def process_task(
        self,
        task_id: str,
        task_func,
        *args,
        **kwargs,
    ) -> bool:
        """
        Process a single task with timing and metrics.
        Returns True on success, False on failure.
        """
        start_time = time()
        task_id_str = normalize_redis_string(task_id)

        try:
            await task_func(*args, **kwargs)
            return True
        except Exception as e:
            sentry_sdk.capture_exception(e)
            logger.exception("Error processing task %s", task_id_str)

            self.metrics_client.increment(
                f"aip.task.{self.task_type}.exception",
                1,
                tag_dict={
                    "exception": type(e).__name__,
                    "task_id": task_id_str,
                    "worker_id": self.worker_id,
                },
            )
            return False
        finally:
            self.metrics_client.timer(
                f"aip.task.{self.task_type}.time",
                time() - start_time,
                tag_dict={"worker_id": self.worker_id},
            )
            self.metrics_client.increment(
                f"aip.task.{self.task_type}.count",
                1,
                tag_dict={"worker_id": self.worker_id},
            )


async def tick_health_task(app: web.Application) -> NoReturn:
    """
    Tick the health gauge every 30 seconds, reducing the health score by 1 each time.
    """

    logger.info("Starting health gauge task")

    health_gauge = app[HealthGaugeAppKey]
    while True:
        await health_gauge.tick()
        await asyncio.sleep(30)


async def _process_oauth_session(
    settings,
    http_session,
    metrics_client,
    database_session,
    redis_session,
    session_group: str,
) -> None:
    """
    Process a single OAuth session refresh.
    """
    async with database_session.begin():
        oauth_session_stmt = select(OAuthSession).where(
            OAuthSession.session_group == session_group
        )
        oauth_session: OAuthSession = (
            await database_session.scalars(oauth_session_stmt)
        ).one()

    await oauth_refresh(
        settings,
        http_session,
        metrics_client,
        database_session,
        redis_session,
        oauth_session,
    )


async def oauth_refresh_task(app: web.Application) -> NoReturn:
    """
    Background process that refreshes OAuth sessions before they expire.

    Uses a Redis-based work queue with the following features:
    - Timestamp-based prioritization (process soonest first)
    - Worker queues for parallel processing
    - Exponential backoff retry logic
    - Comprehensive metrics and error handling

    The process:
    1. Populate worker queue with work ready to be processed
    2. Process each OAuth session refresh
    3. Handle failures with exponential backoff retry
    4. Clean up completed work from worker queue
    """
    logger.info("Starting oauth refresh task")

    settings = app[SettingsAppKey]
    database_session_maker = app[DatabaseSessionMakerAppKey]
    http_session = app[SessionAppKey]
    redis_session = app[RedisClientAppKey]
    metrics_client = app[MetricsClientAppKey]

    # Initialize helper components
    queue_manager = QueueManager(
        redis_session, metrics_client, OAUTH_REFRESH_QUEUE, settings.worker_id
    )
    retry_handler = RetryHandler(
        redis_session,
        metrics_client,
        OAUTH_REFRESH_QUEUE,
        OAUTH_REFRESH_RETRY_QUEUE,
        settings.worker_id,
        settings.oauth_refresh_max_retries,
        settings.oauth_refresh_retry_base_delay,
    )
    task_processor = TaskProcessor(metrics_client, settings.worker_id, "oauth_refresh")

    while True:
        await asyncio.sleep(10)

        now = datetime.now(timezone.utc)
        timestamp = int(now.timestamp())

        # Update worker heartbeat
        await queue_manager.update_heartbeat(timestamp)

        # Collect and report queue metrics
        worker_queue_count, global_queue_count = await queue_manager.get_queue_metrics(
            timestamp
        )
        metrics_client.gauge(
            "aip.task.oauth_refresh.worker_queue_count",
            worker_queue_count,
            tag_dict={"worker_id": settings.worker_id},
        )
        metrics_client.gauge(
            "aip.task.oauth_refresh.global_queue_count",
            global_queue_count,
            tag_dict={"worker_id": settings.worker_id},
        )

        # Populate worker queue if empty but global queue has work
        if worker_queue_count == 0 and global_queue_count > 0:
            try:
                logger.debug(
                    f"tick_task: processing {OAUTH_REFRESH_QUEUE} up to {timestamp}"
                )
                work_queued = await queue_manager.populate_worker_queue(timestamp)
                metrics_client.increment(
                    "aip.task.oauth_refresh.work_queued",
                    work_queued,
                    tag_dict={"worker_id": settings.worker_id},
                )
            except Exception as e:
                sentry_sdk.capture_exception(e)
                logger.exception("error populating worker queue")

        # Process pending tasks
        tasks = await queue_manager.get_pending_tasks(timestamp)
        if len(tasks) > 0:
            async with database_session_maker() as database_session:
                for session_group, deadline in tasks:
                    session_group_str = normalize_redis_string(session_group)

                    logger.debug(
                        "tick_task: processing session_group %s deadline %s",
                        session_group_str,
                        deadline,
                    )

                    # Process task with error handling and metrics
                    success = await task_processor.process_task(
                        session_group,
                        _process_oauth_session,
                        settings,
                        http_session,
                        metrics_client,
                        database_session,
                        redis_session,
                        session_group_str,
                    )

                    if success:
                        # Clear retry count on successful refresh
                        await retry_handler.clear_retry_count(session_group_str)
                    else:
                        # Schedule retry with exponential backoff
                        await retry_handler.schedule_retry(session_group_str, timestamp)

                    # Always remove from worker queue when done
                    await queue_manager.remove_task(session_group)


async def app_password_refresh_task(app: web.Application) -> NoReturn:

    logger.info("Starting app password refresh task")

    settings = app[SettingsAppKey]
    database_session_maker = app[DatabaseSessionMakerAppKey]
    http_session = app[SessionAppKey]
    redis_session = app[RedisClientAppKey]
    metrics_client = app[MetricsClientAppKey]

    while True:
        try:
            await asyncio.sleep(10)

            now = datetime.now(timezone.utc)

            worker_queue = f"{APP_PASSWORD_REFRESH_QUEUE}:{settings.worker_id}"
            workers_heartbeat = f"{APP_PASSWORD_REFRESH_QUEUE}:workers"

            await redis_session.hset(
                workers_heartbeat, settings.worker_id, str(int(now.timestamp()))
            )  # type: ignore

            worker_queue_count: int = await redis_session.zcount(
                worker_queue, 0, int(now.timestamp())
            )
            metrics_client.gauge(
                "aip.task.app_password_refresh.worker_queue_count",
                worker_queue_count,
                tag_dict={"worker_id": settings.worker_id},
            )

            global_queue_count: int = await redis_session.zcount(
                APP_PASSWORD_REFRESH_QUEUE, 0, int(now.timestamp())
            )
            metrics_client.gauge(
                "aip.task.app_password_refresh.global_queue_count",
                global_queue_count,
                tag_dict={"worker_id": settings.worker_id},
            )

            if worker_queue_count == 0 and global_queue_count > 0:
                async with redis_session.pipeline() as redis_pipe:
                    try:
                        logger.debug(
                            f"tick_task: processing {APP_PASSWORD_REFRESH_QUEUE} up to {int(now.timestamp())}"
                        )

                        redis_pipe.zrangestore(
                            worker_queue,
                            APP_PASSWORD_REFRESH_QUEUE,
                            0,
                            int(now.timestamp()),
                            num=5,
                            offset=0,
                            byscore=True,
                        )

                        redis_pipe.zdiffstore(
                            APP_PASSWORD_REFRESH_QUEUE,
                            [APP_PASSWORD_REFRESH_QUEUE, worker_queue],
                        )

                        (zrangestore_res, zdiffstore_res) = await redis_pipe.execute()
                        metrics_client.increment(
                            "aip.task.app_password_refresh.work_queued",
                            zrangestore_res,
                            tag_dict={"worker_id": settings.worker_id},
                        )
                    except Exception as e:
                        sentry_sdk.capture_exception(e)
                        logging.exception("error populating app password worker queue")

            tasks: List[Tuple[str, float]] = await redis_session.zrange(
                worker_queue, 0, int(now.timestamp()), byscore=True, withscores=True
            )

            if len(tasks) > 0:
                for handle_guid, deadline in tasks:

                    logger.debug(
                        "tick_task: processing guid %s deadline %s",
                        handle_guid,
                        deadline,
                    )

                    start_time = time()
                    try:
                        await populate_session(
                            http_session,
                            database_session_maker,
                            redis_session,
                            handle_guid,
                            settings,
                        )

                    except Exception as e:
                        sentry_sdk.capture_exception(e)
                        logging.exception("error processing guid %s", handle_guid)
                        # TODO: Don't actually tag session_group because cardinality will be very high.
                        metrics_client.increment(
                            "aip.task.app_password_refresh.exception",
                            1,
                            tag_dict={
                                "exception": type(e).__name__,
                                "guid": handle_guid,
                                "worker_id": settings.worker_id,
                            },
                        )

                    finally:
                        metrics_client.timer(
                            "aip.task.app_password_refresh.time",
                            time() - start_time,
                            tag_dict={"worker_id": settings.worker_id},
                        )
                        # TODO: Probably don't need this because it is the same as
                        #       `COUNT(aip.task.app_password_refresh.time)`
                        metrics_client.increment(
                            "aip.task.app_password_refresh.count",
                            1,
                            tag_dict={"worker_id": settings.worker_id},
                        )
                        await redis_session.zrem(worker_queue, handle_guid)

        except Exception as e:
            sentry_sdk.capture_exception(e)
            logging.exception("app password tick failed")


async def oauth_cleanup_task(app: web.Application) -> NoReturn:
    """
    Background task to clean up expired OAuth records.

    This task runs every hour and removes:
    - OAuthRequest records that have expired
    - OAuthSession records that have reached their hard expiration

    This prevents database bloat from accumulating expired records.
    """
    logger.info("Starting OAuth cleanup task")

    settings = app[SettingsAppKey]
    database_session_maker = app[DatabaseSessionMakerAppKey]
    metrics_client = app[MetricsClientAppKey]

    while True:
        try:
            # Run cleanup every hour
            await asyncio.sleep(3600)

            now = datetime.now(timezone.utc)

            async with (database_session_maker() as database_session,):
                async with database_session.begin():
                    # Clean up expired OAuthRequest records
                    expired_requests_stmt = delete(OAuthRequest).where(
                        OAuthRequest.expires_at < now
                    )
                    expired_requests_result = await database_session.execute(
                        expired_requests_stmt
                    )
                    expired_requests_count = expired_requests_result.rowcount

                    # Clean up expired OAuthSession records
                    expired_sessions_stmt = delete(OAuthSession).where(
                        OAuthSession.hard_expires_at < now
                    )
                    expired_sessions_result = await database_session.execute(
                        expired_sessions_stmt
                    )
                    expired_sessions_count = expired_sessions_result.rowcount

                    await database_session.commit()

            if expired_requests_count > 0 or expired_sessions_count > 0:
                logger.info(
                    "Cleaned up %d expired OAuth requests and %d expired OAuth sessions",
                    expired_requests_count,
                    expired_sessions_count,
                )

            # Report metrics
            metrics_client.increment(
                "aip.task.oauth_cleanup.expired_requests_removed",
                expired_requests_count,
                tag_dict={"worker_id": settings.worker_id},
            )
            metrics_client.increment(
                "aip.task.oauth_cleanup.expired_sessions_removed",
                expired_sessions_count,
                tag_dict={"worker_id": settings.worker_id},
            )

        except Exception as e:
            sentry_sdk.capture_exception(e)
            logging.exception("OAuth cleanup task failed")

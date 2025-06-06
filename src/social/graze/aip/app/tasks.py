import asyncio
from datetime import datetime, timezone
import logging
from time import time
from typing import List, NoReturn, Tuple
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
    TelegrafStatsdClientAppKey,
)
from social.graze.aip.atproto.app_password import populate_session
from social.graze.aip.atproto.oauth import oauth_refresh
from social.graze.aip.model.oauth import OAuthSession, OAuthRequest

logger = logging.getLogger(__name__)


async def tick_health_task(app: web.Application) -> NoReturn:
    """
    Tick the health gauge every 30 seconds, reducing the health score by 1 each time.
    """

    logger.info("Starting health gauge task")

    health_gauge = app[HealthGaugeAppKey]
    while True:
        await health_gauge.tick()
        await asyncio.sleep(30)


async def oauth_refresh_task(app: web.Application) -> NoReturn:
    """
    oauth_refresh_task is a background process that refreshes OAuth sessions immediately before they expire.

    The process is as follows:

    Given the queue name is "auth_refresh"
    Given the worker id is "worker1"
    Given `now = datetime.datetime.now(datetime.timezone.utc)`

    1. In a redis pipeline, get some work.
       * Populate the worker queue with work. This stores a range of things from the begining of time to "now" into a
         new queue.
         ZRANGESTORE "auth_refresh_worker1" "auth_refresh" 1 {now} LIMIT 5

       * Get the work that we just populated.
         ZRANGE "auth_refresh_worker1" 0 -1

       * Store the difference between the worker queue and the main queue to remove the pulled work from the main
         queue.
         ZDIFFSTORE "auth_refresh" 2 "auth_refresh" "auth_refresh_worker1"

    2. For the work that we just got, process it all and remove each from the worker queue.
       ZREM "auth_refresh_worker1" {work_id}

    3. Sleep 15-30 seconds and repeat.

    This does a few things that are important to note.

    1. Work is queued up and indexed (redis zindex) against the time that it needs to be processed, not when
       it was queued. This lets the queue be lazily evaluated and also pull work that needs to be processed
       soonest.

    2. Work is batched into a worker queue outside of app instances, so it can be processed in parallel. If
       we need to scale up workers, we can do so by adjusting the deployment replica count.

    3. Work is grabbed in batches that don't need to be uniform, so there is no arbitrary delay. Workers
       don't have to wait for 5 jobs to be ready before taking them.

    4. If a worker dies, we have the temporary worker queue to recover the work that was in progress. If
       needed, we can create a watchdog worker that looks at orphaned worker queues and adds the work back to
       the main queue.
    """

    logger.info("Starting oauth refresh task")

    settings = app[SettingsAppKey]
    database_session_maker = app[DatabaseSessionMakerAppKey]
    http_session = app[SessionAppKey]

    redis_session = app[RedisClientAppKey]
    statsd_client = app[TelegrafStatsdClientAppKey]

    while True:

        await asyncio.sleep(10)

        now = datetime.now(timezone.utc)

        worker_queue = f"{OAUTH_REFRESH_QUEUE}:{settings.worker_id}"
        workers_heartbeat = f"{OAUTH_REFRESH_QUEUE}:workers"

        await redis_session.hset(
            workers_heartbeat, settings.worker_id, str(int(now.timestamp()))
        )  # type: ignore

        worker_queue_count: int = await redis_session.zcount(
            worker_queue, 0, int(now.timestamp())
        )
        statsd_client.gauge(
            "aip.task.oauth_refresh.worker_queue_count",
            worker_queue_count,
            tag_dict={"worker_id": settings.worker_id},
        )

        global_queue_count: int = await redis_session.zcount(
            OAUTH_REFRESH_QUEUE, 0, int(now.timestamp())
        )
        statsd_client.gauge(
            "aip.task.oauth_refresh.global_queue_count",
            global_queue_count,
            tag_dict={"worker_id": settings.worker_id},
        )

        if worker_queue_count == 0 and global_queue_count > 0:
            async with redis_session.pipeline() as redis_pipe:
                try:
                    logger.debug(
                        f"tick_task: processing {OAUTH_REFRESH_QUEUE} up to {int(now.timestamp())}"
                    )
                    redis_pipe.zrangestore(
                        worker_queue,
                        OAUTH_REFRESH_QUEUE,
                        0,
                        int(now.timestamp()),
                        num=5,
                        offset=0,
                        byscore=True,
                    )

                    redis_pipe.zdiffstore(
                        OAUTH_REFRESH_QUEUE, [OAUTH_REFRESH_QUEUE, worker_queue]
                    )
                    (zrangestore_res, zdiffstore_res) = await redis_pipe.execute()
                    statsd_client.increment(
                        "aip.task.oauth_refresh.work_queued",
                        zrangestore_res,
                        tag_dict={"worker_id": settings.worker_id},
                    )
                except Exception as e:
                    sentry_sdk.capture_exception(e)
                    logging.exception("error populating worker queue")

        tasks: List[Tuple[str, float]] = await redis_session.zrange(
            worker_queue, 0, int(now.timestamp()), byscore=True, withscores=True
        )
        if len(tasks) > 0:
            async with (database_session_maker() as database_session,):
                for session_group, deadline in tasks:

                    logger.debug(
                        "tick_task: processing session_group %s deadline %s",
                        session_group,
                        deadline,
                    )

                    start_time = time()

                    try:
                        async with database_session.begin():
                            if isinstance(session_group, bytes):
                                session_group = session_group.decode()
                            oauth_session_stmt = select(OAuthSession).where(
                                OAuthSession.session_group == session_group
                            )
                            oauth_session: OAuthSession = (
                                await database_session.scalars(oauth_session_stmt)
                            ).one()

                        await oauth_refresh(
                            settings,
                            http_session,
                            statsd_client,
                            database_session,
                            redis_session,
                            oauth_session,
                        )

                        # Clear retry count on successful refresh
                        session_group_str = (
                            session_group.decode()
                            if isinstance(session_group, bytes)
                            else session_group
                        )
                        await redis_session.hdel(
                            OAUTH_REFRESH_RETRY_QUEUE, session_group_str
                        )

                    except Exception as e:
                        sentry_sdk.capture_exception(e)
                        logging.exception(
                            "error processing session group %s", session_group
                        )

                        # Implement retry logic with exponential backoff
                        session_group_str = (
                            session_group.decode()
                            if isinstance(session_group, bytes)
                            else session_group
                        )
                        current_retries = await redis_session.hget(
                            OAUTH_REFRESH_RETRY_QUEUE, session_group_str
                        )
                        current_retries = int(current_retries) if current_retries else 0

                        if current_retries < settings.oauth_refresh_max_retries:
                            # Calculate exponential backoff delay
                            retry_delay = settings.oauth_refresh_retry_base_delay * (
                                2**current_retries
                            )
                            retry_timestamp = int(now.timestamp()) + retry_delay

                            # Re-queue with delay and increment retry count
                            await redis_session.zadd(
                                OAUTH_REFRESH_QUEUE,
                                {session_group_str: retry_timestamp},
                            )
                            await redis_session.hset(
                                OAUTH_REFRESH_RETRY_QUEUE,
                                session_group_str,
                                current_retries + 1,
                            )

                            logging.info(
                                "Scheduled retry %d/%d for session_group %s in %d seconds",
                                current_retries + 1,
                                settings.oauth_refresh_max_retries,
                                session_group_str,
                                retry_delay,
                            )

                            statsd_client.increment(
                                "aip.task.oauth_refresh.retry_scheduled",
                                1,
                                tag_dict={
                                    "retry_attempt": str(current_retries + 1),
                                    "worker_id": settings.worker_id,
                                },
                            )
                        else:
                            # Max retries exceeded, give up and clean up retry tracking
                            await redis_session.hdel(
                                OAUTH_REFRESH_RETRY_QUEUE, session_group_str
                            )

                            logging.error(
                                "Max retries exceeded for session_group %s, giving up after %d attempts",
                                session_group_str,
                                settings.oauth_refresh_max_retries,
                            )

                            statsd_client.increment(
                                "aip.task.oauth_refresh.max_retries_exceeded",
                                1,
                                tag_dict={"worker_id": settings.worker_id},
                            )

                        # TODO: Don't actually tag session_group because cardinality will be very high.
                        statsd_client.increment(
                            "aip.task.oauth_refresh.exception",
                            1,
                            tag_dict={
                                "exception": type(e).__name__,
                                "session_group": session_group,
                                "worker_id": settings.worker_id,
                            },
                        )

                    finally:
                        statsd_client.timer(
                            "aip.task.oauth_refresh.time",
                            time() - start_time,
                            tag_dict={"worker_id": settings.worker_id},
                        )
                        # TODO: Probably don't need this because it is the same as `COUNT(aip.task.oauth_refresh.time)`
                        statsd_client.increment(
                            "aip.task.oauth_refresh.count",
                            1,
                            tag_dict={"worker_id": settings.worker_id},
                        )
                        await redis_session.zrem(worker_queue, session_group)


async def app_password_refresh_task(app: web.Application) -> NoReturn:

    logger.info("Starting app password refresh task")

    settings = app[SettingsAppKey]
    database_session_maker = app[DatabaseSessionMakerAppKey]
    http_session = app[SessionAppKey]
    redis_session = app[RedisClientAppKey]
    statsd_client = app[TelegrafStatsdClientAppKey]

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
            statsd_client.gauge(
                "aip.task.app_password_refresh.worker_queue_count",
                worker_queue_count,
                tag_dict={"worker_id": settings.worker_id},
            )

            global_queue_count: int = await redis_session.zcount(
                APP_PASSWORD_REFRESH_QUEUE, 0, int(now.timestamp())
            )
            statsd_client.gauge(
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
                        statsd_client.increment(
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
                        statsd_client.increment(
                            "aip.task.app_password_refresh.exception",
                            1,
                            tag_dict={
                                "exception": type(e).__name__,
                                "guid": handle_guid,
                                "worker_id": settings.worker_id,
                            },
                        )

                    finally:
                        statsd_client.timer(
                            "aip.task.app_password_refresh.time",
                            time() - start_time,
                            tag_dict={"worker_id": settings.worker_id},
                        )
                        # TODO: Probably don't need this because it is the same as
                        #       `COUNT(aip.task.app_password_refresh.time)`
                        statsd_client.increment(
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
    statsd_client = app[TelegrafStatsdClientAppKey]

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
            statsd_client.increment(
                "aip.task.oauth_cleanup.expired_requests_removed",
                expired_requests_count,
                tag_dict={"worker_id": settings.worker_id},
            )
            statsd_client.increment(
                "aip.task.oauth_cleanup.expired_sessions_removed",
                expired_sessions_count,
                tag_dict={"worker_id": settings.worker_id},
            )

        except Exception as e:
            sentry_sdk.capture_exception(e)
            logging.exception("OAuth cleanup task failed")

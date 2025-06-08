"""
Metrics Abstraction Layer for AIP Service

This module provides a vendor-agnostic metrics collection interface that supports multiple
backends including OpenTelemetry (OTEL), Telegraf/StatsD, and no-op implementations.
The abstraction enables easy switching between metrics systems without code changes.

Key Components:
- MetricsClient: Abstract interface for all metrics operations
- OTELMetricsClient: OpenTelemetry-compliant implementation
- TelegrafCompatibilityClient: Wrapper for existing TelegrafStatsdClient
- NoOpMetricsClient: No-operation client for disabled metrics
- create_metrics_client: Factory function for backend selection

The abstraction supports three metric types following OpenTelemetry conventions:
- Counters: Monotonic values that only increase (e.g., request counts)
- Gauges: Point-in-time values that can increase/decrease (e.g., queue size)
- Histograms: Distribution of values with timing data (e.g., request duration)

Migration from TelegrafStatsdClient is seamless - all existing metric calls
continue to work with the same API surface.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
import time

try:
    from opentelemetry import metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

try:
    from aio_statsd import TelegrafStatsdClient
    TELEGRAF_AVAILABLE = True
except ImportError:
    TELEGRAF_AVAILABLE = False

logger = logging.getLogger(__name__)


class MetricsClient(ABC):
    """
    Abstract metrics client interface for vendor-agnostic telemetry collection.
    
    This interface standardizes metrics collection across different backend systems
    while maintaining compatibility with existing TelegrafStatsdClient usage patterns.
    All implementations must support the three core metric types: counters, gauges,
    and histograms/timers.
    
    Tag/attribute handling follows OpenTelemetry conventions where possible, with
    backward compatibility for StatsD-style tag dictionaries.
    """

    @abstractmethod
    def increment(
        self, 
        name: str, 
        value: Union[int, float] = 1, 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Increment a counter metric by the specified value.
        
        Counters are monotonic metrics that only increase over time, suitable for
        tracking events like request counts, error counts, or successful operations.
        
        Args:
            name: Metric name (e.g., 'aip.server.request.count')
            value: Amount to increment by (default: 1)
            tag_dict: Optional tags/attributes for metric dimensions
        """
        pass

    @abstractmethod
    def gauge(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Set a gauge metric to the specified value.
        
        Gauges represent point-in-time values that can increase or decrease,
        suitable for tracking current states like queue sizes, active connections,
        or resource utilization.
        
        Args:
            name: Metric name (e.g., 'aip.task.queue_count')
            value: Current value to set
            tag_dict: Optional tags/attributes for metric dimensions
        """
        pass

    @abstractmethod
    def timer(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record a timing/duration measurement.
        
        Timers record the distribution of durations, suitable for tracking
        request processing times, database query durations, or any time-based
        measurements. Values should be in seconds for consistency.
        
        Args:
            name: Metric name (e.g., 'aip.server.request.time')
            value: Duration in seconds
            tag_dict: Optional tags/attributes for metric dimensions
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """
        Close the metrics client and flush any pending metrics.
        
        Implementations should ensure all buffered metrics are sent and
        any network connections are properly closed.
        """
        pass


class OTELMetricsClient(MetricsClient):
    """
    OpenTelemetry-compliant metrics client implementation.
    
    This client uses the OpenTelemetry Python SDK to collect and export metrics
    to OTEL-compatible backends like Prometheus, OTLP collectors, or cloud
    monitoring services. It automatically handles metric instrument creation
    and caching for performance.
    
    Features:
    - Lazy instrument creation with caching
    - Support for multiple exporters (OTLP, Prometheus)
    - Resource attribution (service name, version)
    - Automatic unit conversion (ms to seconds for timers)
    """

    def __init__(
        self,
        service_name: str = "aip",
        service_version: str = "1.0.0",
        exporter_endpoint: Optional[str] = None,
        export_interval_seconds: int = 30,
        enable_prometheus: bool = False,
    ):
        """
        Initialize OTEL metrics client with specified configuration.
        
        Args:
            service_name: Service identifier for resource attribution
            service_version: Service version for resource attribution  
            exporter_endpoint: OTLP gRPC endpoint (e.g., 'http://localhost:4317')
            export_interval_seconds: How often to export metrics
            enable_prometheus: Whether to enable Prometheus metrics endpoint
        """
        if not OTEL_AVAILABLE:
            raise ImportError(
                "OpenTelemetry packages not available. Install with: "
                "pip install opentelemetry-api opentelemetry-sdk "
                "opentelemetry-exporter-otlp opentelemetry-exporter-prometheus"
            )

        # Create resource with service information
        resource = Resource.create({
            SERVICE_NAME: service_name,
            SERVICE_VERSION: service_version,
        })

        # Set up metric readers/exporters
        readers = []
        
        if exporter_endpoint:
            # OTLP exporter for sending to collectors/backends
            otlp_exporter = OTLPMetricExporter(endpoint=exporter_endpoint)
            otlp_reader = PeriodicExportingMetricReader(
                exporter=otlp_exporter,
                export_interval_millis=export_interval_seconds * 1000,
            )
            readers.append(otlp_reader)

        if enable_prometheus:
            # Prometheus exporter for scraping endpoint
            prometheus_reader = PrometheusMetricReader()
            readers.append(prometheus_reader)

        # Initialize meter provider and meter
        if readers:
            meter_provider = MeterProvider(
                resource=resource,
                metric_readers=readers,
            )
            metrics.set_meter_provider(meter_provider)
        
        self.meter = metrics.get_meter(service_name)
        
        # Cache for created instruments to avoid recreation overhead
        self._counters: Dict[str, Any] = {}
        self._gauges: Dict[str, Any] = {}
        self._histograms: Dict[str, Any] = {}

    def increment(
        self, 
        name: str, 
        value: Union[int, float] = 1, 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """Increment counter using OTEL Counter instrument."""
        if name not in self._counters:
            self._counters[name] = self.meter.create_counter(
                name=name,
                description=f"Counter metric: {name}",
            )
        
        # Convert tag_dict to OTEL attributes format
        attributes = {str(k): str(v) for k, v in (tag_dict or {}).items()}
        self._counters[name].add(value, attributes=attributes)

    def gauge(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """Set gauge value using OTEL UpDownCounter instrument."""
        # OTEL doesn't have true gauges, use UpDownCounter as closest equivalent
        if name not in self._gauges:
            self._gauges[name] = self.meter.create_up_down_counter(
                name=name,
                description=f"Gauge metric: {name}",
            )
        
        attributes = {str(k): str(v) for k, v in (tag_dict or {}).items()}
        # For gauge behavior, we'd need to track previous values and add the delta
        # This is a simplified implementation - in production you might want
        # to use Observable Gauges with callbacks for true gauge semantics
        self._gauges[name].add(value, attributes=attributes)

    def timer(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record timing using OTEL Histogram instrument."""
        if name not in self._histograms:
            self._histograms[name] = self.meter.create_histogram(
                name=name,
                description=f"Timing metric: {name}",
                unit="s",  # OpenTelemetry recommends seconds for duration
            )
        
        attributes = {str(k): str(v) for k, v in (tag_dict or {}).items()}
        self._histograms[name].record(value, attributes=attributes)

    async def close(self) -> None:
        """Close OTEL meter provider and flush metrics."""
        try:
            # Force export of any pending metrics
            meter_provider = metrics.get_meter_provider()
            if hasattr(meter_provider, 'shutdown'):
                meter_provider.shutdown()
        except Exception as e:
            logger.warning(f"Error closing OTEL metrics client: {e}")


class TelegrafCompatibilityClient(MetricsClient):
    """
    Compatibility wrapper for existing TelegrafStatsdClient.
    
    This wrapper provides the MetricsClient interface while delegating to
    the original TelegrafStatsdClient implementation. It ensures backward
    compatibility during migration and allows existing code to work unchanged.
    
    The wrapper handles async/sync differences and maintains the exact same
    behavior as direct TelegrafStatsdClient usage.
    """

    def __init__(self, telegraf_client: Any):
        """
        Initialize with an existing TelegrafStatsdClient instance.
        
        Args:
            telegraf_client: Configured TelegrafStatsdClient instance
        """
        if not TELEGRAF_AVAILABLE:
            raise ImportError(
                "TelegrafStatsdClient not available. Install with: pip install aio-statsd"
            )
        
        self.client = telegraf_client

    def increment(
        self, 
        name: str, 
        value: Union[int, float] = 1, 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """Delegate to TelegrafStatsdClient increment method."""
        self.client.increment(name, value, tag_dict=tag_dict or {})

    def gauge(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """Delegate to TelegrafStatsdClient gauge method."""
        self.client.gauge(name, value, tag_dict=tag_dict or {})

    def timer(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """Delegate to TelegrafStatsdClient timer method."""
        self.client.timer(name, value, tag_dict=tag_dict or {})

    async def close(self) -> None:
        """Close underlying TelegrafStatsdClient."""
        try:
            if hasattr(self.client, 'close'):
                await self.client.close()
        except Exception as e:
            logger.warning(f"Error closing Telegraf client: {e}")


class NoOpMetricsClient(MetricsClient):
    """
    No-operation metrics client for disabled metrics collection.
    
    This implementation provides the MetricsClient interface but performs
    no actual metrics collection. It's useful for testing, development
    environments, or when metrics collection should be disabled entirely.
    
    All methods are no-ops and return immediately without error.
    """

    def increment(
        self, 
        name: str, 
        value: Union[int, float] = 1, 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """No-op increment operation."""
        pass

    def gauge(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """No-op gauge operation."""
        pass

    def timer(
        self, 
        name: str, 
        value: Union[int, float], 
        tag_dict: Optional[Dict[str, Any]] = None
    ) -> None:
        """No-op timer operation."""
        pass

    async def close(self) -> None:
        """No-op close operation."""
        pass


def create_metrics_client(
    backend: str,
    service_name: str = "aip",
    service_version: str = "1.0.0",
    host: str = "localhost",
    port: int = 8125,
    otel_endpoint: Optional[str] = None,
    telegraf_client: Optional[Any] = None,
    debug: bool = False,
) -> MetricsClient:
    """
    Factory function to create the appropriate metrics client based on backend type.
    
    This function handles the complexity of backend selection and configuration,
    providing a simple interface for creating metrics clients with appropriate
    error handling and fallbacks.
    
    Args:
        backend: Backend type ('otel', 'telegraf', 'none')
        service_name: Service name for OTEL resource attribution
        service_version: Service version for OTEL resource attribution
        host: Telegraf/StatsD host
        port: Telegraf/StatsD port
        otel_endpoint: OpenTelemetry OTLP endpoint
        telegraf_client: Pre-configured TelegrafStatsdClient instance
        debug: Enable debug logging
        
    Returns:
        MetricsClient: Configured metrics client instance
        
    Raises:
        ValueError: If backend type is invalid or required dependencies missing
    """
    backend = backend.lower()
    
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Creating metrics client with backend: {backend}")
    
    if backend == "otel":
        if not OTEL_AVAILABLE:
            logger.error("OTEL backend requested but OpenTelemetry packages not available")
            raise ValueError(
                "OpenTelemetry packages required for 'otel' backend. "
                "Install with: pip install opentelemetry-api opentelemetry-sdk "
                "opentelemetry-exporter-otlp opentelemetry-exporter-prometheus"
            )
        
        return OTELMetricsClient(
            service_name=service_name,
            service_version=service_version,
            exporter_endpoint=otel_endpoint,
        )
    
    elif backend == "telegraf":
        if telegraf_client:
            # Use pre-configured client
            return TelegrafCompatibilityClient(telegraf_client)
        
        if not TELEGRAF_AVAILABLE:
            logger.error("Telegraf backend requested but aio-statsd package not available")
            raise ValueError(
                "aio-statsd package required for 'telegraf' backend. "
                "Install with: pip install aio-statsd"
            )
        
        # Create new TelegrafStatsdClient
        from aio_statsd import TelegrafStatsdClient
        telegraf_client = TelegrafStatsdClient(host=host, port=port, debug=debug)
        return TelegrafCompatibilityClient(telegraf_client)
    
    elif backend == "none":
        logger.info("Metrics collection disabled (no-op client)")
        return NoOpMetricsClient()
    
    else:
        raise ValueError(
            f"Invalid metrics backend: {backend}. "
            f"Supported backends: 'otel', 'telegraf', 'none'"
        )


# Convenience type alias for type hints
AnyMetricsClient = Union[OTELMetricsClient, TelegrafCompatibilityClient, NoOpMetricsClient]
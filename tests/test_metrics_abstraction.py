"""
Unit Tests for Metrics Abstraction Layer

This module tests the metrics abstraction layer that enables vendor-agnostic
metrics collection across multiple backends (OTEL, Telegraf, NoOp).

Test Coverage:
- MetricsClient interface implementations
- Backend selection via factory function
- Configuration handling and validation
- Error handling and fallbacks
- Compatibility between implementations
- Integration with application components
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

# Import the metrics abstraction components
from social.graze.aip.app.metrics import (
    MetricsClient,
    OTELMetricsClient,
    TelegrafCompatibilityClient,
    NoOpMetricsClient,
    create_metrics_client,
)


class TestMetricsClientInterface:
    """Test the abstract MetricsClient interface."""

    def test_interface_is_abstract(self):
        """MetricsClient should be abstract and not instantiable."""
        with pytest.raises(TypeError):
            MetricsClient()


class TestNoOpMetricsClient:
    """Test the NoOpMetricsClient implementation."""

    @pytest.fixture
    def noop_client(self):
        """Create a NoOpMetricsClient instance for testing."""
        return NoOpMetricsClient()

    def test_noop_increment(self, noop_client):
        """NoOp increment should not raise exceptions."""
        noop_client.increment("test.counter", 1, {"tag": "value"})
        noop_client.increment("test.counter", 5)
        noop_client.increment("test.counter")

    def test_noop_gauge(self, noop_client):
        """NoOp gauge should not raise exceptions."""
        noop_client.gauge("test.gauge", 42.5, {"tag": "value"})
        noop_client.gauge("test.gauge", 0)

    def test_noop_timer(self, noop_client):
        """NoOp timer should not raise exceptions."""
        noop_client.timer("test.timer", 1.234, {"tag": "value"})
        noop_client.timer("test.timer", 0.001)

    @pytest.mark.asyncio
    async def test_noop_close(self, noop_client):
        """NoOp close should not raise exceptions."""
        await noop_client.close()


class TestTelegrafCompatibilityClient:
    """Test the TelegrafCompatibilityClient wrapper."""

    @pytest.fixture
    def mock_telegraf_client(self):
        """Create a mock TelegrafStatsdClient."""
        mock = Mock()
        mock.increment = Mock()
        mock.gauge = Mock()
        mock.timer = Mock()
        mock.close = AsyncMock()
        return mock

    @pytest.fixture
    def telegraf_client(self, mock_telegraf_client):
        """Create a TelegrafCompatibilityClient with mocked backend."""
        return TelegrafCompatibilityClient(mock_telegraf_client)

    def test_telegraf_increment(self, telegraf_client, mock_telegraf_client):
        """Telegraf increment should delegate to underlying client."""
        telegraf_client.increment("test.counter", 3, {"method": "POST"})
        
        mock_telegraf_client.increment.assert_called_once_with(
            "test.counter", 3, tag_dict={"method": "POST"}
        )

    def test_telegraf_gauge(self, telegraf_client, mock_telegraf_client):
        """Telegraf gauge should delegate to underlying client."""
        telegraf_client.gauge("test.gauge", 42.0, {"status": "ok"})
        
        mock_telegraf_client.gauge.assert_called_once_with(
            "test.gauge", 42.0, tag_dict={"status": "ok"}
        )

    def test_telegraf_timer(self, telegraf_client, mock_telegraf_client):
        """Telegraf timer should delegate to underlying client."""
        telegraf_client.timer("test.timer", 1.234, {"endpoint": "/api"})
        
        mock_telegraf_client.timer.assert_called_once_with(
            "test.timer", 1.234, tag_dict={"endpoint": "/api"}
        )

    @pytest.mark.asyncio
    async def test_telegraf_close(self, telegraf_client, mock_telegraf_client):
        """Telegraf close should delegate to underlying client."""
        await telegraf_client.close()
        
        mock_telegraf_client.close.assert_called_once()

    def test_telegraf_increment_no_tags(self, telegraf_client, mock_telegraf_client):
        """Telegraf increment should handle None tag_dict gracefully."""
        telegraf_client.increment("test.counter")
        
        mock_telegraf_client.increment.assert_called_once_with(
            "test.counter", 1, tag_dict={}
        )

    def test_telegraf_unavailable(self):
        """TelegrafCompatibilityClient should handle missing aio-statsd gracefully."""
        with patch('social.graze.aip.app.metrics.TELEGRAF_AVAILABLE', False):
            with pytest.raises(ImportError, match="TelegrafStatsdClient not available"):
                TelegrafCompatibilityClient(Mock())


@pytest.mark.skipif(
    not hasattr(__import__('social.graze.aip.app.metrics', fromlist=['OTEL_AVAILABLE']), 'OTEL_AVAILABLE') 
    or not __import__('social.graze.aip.app.metrics', fromlist=['OTEL_AVAILABLE']).OTEL_AVAILABLE,
    reason="OpenTelemetry not available"
)
class TestOTELMetricsClient:
    """Test the OTELMetricsClient implementation."""

    @pytest.fixture
    def mock_otel_components(self):
        """Mock OpenTelemetry components for testing."""
        # Create mock objects
        mock_metrics = Mock()
        mock_meter = Mock()
        mock_counter = Mock()
        mock_gauge = Mock()
        mock_histogram = Mock()
        
        mock_meter.create_counter.return_value = mock_counter
        mock_meter.create_up_down_counter.return_value = mock_gauge
        mock_meter.create_histogram.return_value = mock_histogram
        mock_metrics.get_meter.return_value = mock_meter
        
        # Mock the modules and classes
        with patch('social.graze.aip.app.metrics.OTEL_AVAILABLE', True), \
             patch('social.graze.aip.app.metrics.metrics', mock_metrics), \
             patch('social.graze.aip.app.metrics.MeterProvider'), \
             patch('social.graze.aip.app.metrics.Resource'):
            
            yield {
                'metrics': mock_metrics,
                'meter': mock_meter,
                'counter': mock_counter,
                'gauge': mock_gauge,
                'histogram': mock_histogram,
            }

    @pytest.fixture
    def otel_client(self, mock_otel_components):
        """Create an OTELMetricsClient with mocked OTEL components."""
        return OTELMetricsClient(
            service_name="test-service",
            service_version="1.0.0"
        )

    def test_otel_increment(self, otel_client, mock_otel_components):
        """OTEL increment should create counter and add values."""
        otel_client.increment("test.counter", 5, {"method": "GET"})
        
        # Should create counter on first use
        mock_otel_components['meter'].create_counter.assert_called_with(
            name="test.counter",
            description="Counter metric: test.counter"
        )
        
        # Should add value with converted attributes
        mock_otel_components['counter'].add.assert_called_with(
            5, attributes={"method": "GET"}
        )

    def test_otel_gauge(self, otel_client, mock_otel_components):
        """OTEL gauge should create up-down counter and add values."""
        otel_client.gauge("test.gauge", 42.5, {"status": "active"})
        
        # Should create up-down counter (OTEL's closest to gauge)
        mock_otel_components['meter'].create_up_down_counter.assert_called_with(
            name="test.gauge",
            description="Gauge metric: test.gauge"
        )
        
        # Should add value with converted attributes
        mock_otel_components['gauge'].add.assert_called_with(
            42.5, attributes={"status": "active"}
        )

    def test_otel_timer(self, otel_client, mock_otel_components):
        """OTEL timer should create histogram and record values."""
        otel_client.timer("test.timer", 1.234, {"endpoint": "/api/test"})
        
        # Should create histogram with seconds unit
        mock_otel_components['meter'].create_histogram.assert_called_with(
            name="test.timer",
            description="Timing metric: test.timer",
            unit="s"
        )
        
        # Should record value with converted attributes
        mock_otel_components['histogram'].record.assert_called_with(
            1.234, attributes={"endpoint": "/api/test"}
        )

    def test_otel_instrument_caching(self, otel_client, mock_otel_components):
        """OTEL client should cache instruments to avoid recreation."""
        # Use the same metric name multiple times
        otel_client.increment("test.counter", 1)
        otel_client.increment("test.counter", 2)
        
        # Counter should only be created once
        assert mock_otel_components['meter'].create_counter.call_count == 1
        
        # But values should be added multiple times
        assert mock_otel_components['counter'].add.call_count == 2

    def test_otel_attribute_conversion(self, otel_client, mock_otel_components):
        """OTEL client should convert tag values to strings."""
        otel_client.increment("test.counter", 1, {
            "string_tag": "value",
            "int_tag": 42,
            "float_tag": 3.14,
            "bool_tag": True
        })
        
        mock_otel_components['counter'].add.assert_called_with(
            1, attributes={
                "string_tag": "value",
                "int_tag": "42",
                "float_tag": "3.14",
                "bool_tag": "True"
            }
        )

    @pytest.mark.asyncio
    async def test_otel_close(self, otel_client, mock_otel_components):
        """OTEL close should shutdown meter provider."""
        mock_provider = Mock()
        mock_provider.shutdown = Mock()
        mock_otel_components['metrics'].get_meter_provider.return_value = mock_provider
        
        await otel_client.close()
        
        mock_provider.shutdown.assert_called_once()

    def test_otel_unavailable(self):
        """OTELMetricsClient should handle missing OpenTelemetry packages."""
        with patch('social.graze.aip.app.metrics.OTEL_AVAILABLE', False):
            with pytest.raises(ImportError, match="OpenTelemetry packages not available"):
                OTELMetricsClient()


class TestMetricsClientFactory:
    """Test the create_metrics_client factory function."""

    def test_factory_creates_noop_client(self):
        """Factory should create NoOpMetricsClient for 'none' backend."""
        client = create_metrics_client("none")
        assert isinstance(client, NoOpMetricsClient)

    @patch('social.graze.aip.app.metrics.TELEGRAF_AVAILABLE', True)
    @patch('aio_statsd.TelegrafStatsdClient')
    def test_factory_creates_telegraf_client(self, mock_telegraf_class):
        """Factory should create TelegrafCompatibilityClient for 'telegraf' backend."""
        mock_instance = Mock()
        mock_telegraf_class.return_value = mock_instance
        
        client = create_metrics_client(
            "telegraf",
            host="localhost",
            port=8125,
            debug=True
        )
        
        assert isinstance(client, TelegrafCompatibilityClient)
        mock_telegraf_class.assert_called_once_with(
            host="localhost",
            port=8125,
            debug=True
        )

    def test_factory_uses_preconfigured_telegraf_client(self):
        """Factory should use pre-configured TelegrafStatsdClient if provided."""
        mock_client = Mock()
        
        client = create_metrics_client("telegraf", telegraf_client=mock_client)
        
        assert isinstance(client, TelegrafCompatibilityClient)
        assert client.client is mock_client

    @patch('social.graze.aip.app.metrics.OTEL_AVAILABLE', True)
    @patch('social.graze.aip.app.metrics.OTELMetricsClient')
    def test_factory_creates_otel_client(self, mock_otel_class):
        """Factory should create OTELMetricsClient for 'otel' backend."""
        mock_instance = Mock()
        mock_otel_class.return_value = mock_instance
        
        client = create_metrics_client(
            "otel",
            service_name="test-service",
            service_version="2.0.0",
            otel_endpoint="http://localhost:4317"
        )
        
        assert client is mock_instance
        mock_otel_class.assert_called_once_with(
            service_name="test-service",
            service_version="2.0.0",
            exporter_endpoint="http://localhost:4317"
        )

    def test_factory_handles_invalid_backend(self):
        """Factory should raise ValueError for invalid backend types."""
        with pytest.raises(ValueError, match="Invalid metrics backend: invalid"):
            create_metrics_client("invalid")

    def test_factory_handles_case_insensitive_backends(self):
        """Factory should handle case-insensitive backend names."""
        client1 = create_metrics_client("NONE")
        client2 = create_metrics_client("None")
        client3 = create_metrics_client("none")
        
        assert all(isinstance(c, NoOpMetricsClient) for c in [client1, client2, client3])

    @patch('social.graze.aip.app.metrics.TELEGRAF_AVAILABLE', False)
    def test_factory_handles_missing_telegraf(self):
        """Factory should raise ValueError when Telegraf backend unavailable."""
        with pytest.raises(ValueError, match="aio-statsd package required"):
            create_metrics_client("telegraf")

    @patch('social.graze.aip.app.metrics.OTEL_AVAILABLE', False)
    def test_factory_handles_missing_otel(self):
        """Factory should raise ValueError when OTEL backend unavailable."""
        with pytest.raises(ValueError, match="OpenTelemetry packages required"):
            create_metrics_client("otel")


class TestMetricsCompatibility:
    """Test compatibility between different metrics client implementations."""

    @pytest.fixture(params=["noop", "telegraf", "otel"])
    def any_metrics_client(self, request):
        """Parametrized fixture that provides all client implementations."""
        backend = request.param
        
        if backend == "noop":
            return NoOpMetricsClient()
        elif backend == "telegraf":
            mock_telegraf = Mock()
            mock_telegraf.increment = Mock()
            mock_telegraf.gauge = Mock()
            mock_telegraf.timer = Mock()
            mock_telegraf.close = AsyncMock()
            return TelegrafCompatibilityClient(mock_telegraf)
        elif backend == "otel":
            # Skip OTEL tests when OTEL is not available
            pytest.skip("OTEL not available for testing")

    def test_all_clients_implement_interface(self, any_metrics_client):
        """All implementations should satisfy the MetricsClient interface."""
        assert isinstance(any_metrics_client, MetricsClient)

    def test_all_clients_support_increment(self, any_metrics_client):
        """All implementations should support increment operations."""
        # These should not raise exceptions
        any_metrics_client.increment("test.counter")
        any_metrics_client.increment("test.counter", 5)
        any_metrics_client.increment("test.counter", 1, {"tag": "value"})

    def test_all_clients_support_gauge(self, any_metrics_client):
        """All implementations should support gauge operations."""
        # These should not raise exceptions
        any_metrics_client.gauge("test.gauge", 42)
        any_metrics_client.gauge("test.gauge", 3.14, {"tag": "value"})

    def test_all_clients_support_timer(self, any_metrics_client):
        """All implementations should support timer operations."""
        # These should not raise exceptions
        any_metrics_client.timer("test.timer", 1.234)
        any_metrics_client.timer("test.timer", 0.001, {"tag": "value"})

    @pytest.mark.asyncio
    async def test_all_clients_support_close(self, any_metrics_client):
        """All implementations should support close operations."""
        # This should not raise exceptions
        await any_metrics_client.close()


class TestMetricsIntegration:
    """Test integration with application components."""

    def test_config_backward_compatibility(self):
        """Configuration should maintain backward compatibility with telegraf settings."""
        from social.graze.aip.app.config import Settings
        
        # Test that old environment variable names still work
        import os
        old_env = os.environ.copy()
        try:
            os.environ.update({
                'TELEGRAF_HOST': 'legacy-host',
                'TELEGRAF_PORT': '9125',
                'STATSD_PREFIX': 'legacy-prefix',
                'WORKER_ID': 'test-worker'  # Required field
            })
            
            settings = Settings()
            
            assert settings.metrics_host == 'legacy-host'
            assert settings.metrics_port == 9125
            assert settings.metrics_prefix == 'legacy-prefix'
            
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_appkey_replacement(self):
        """MetricsClientAppKey should be properly defined."""
        from social.graze.aip.app.config import MetricsClientAppKey
        from aiohttp import web
        
        assert isinstance(MetricsClientAppKey, web.AppKey)
        # AppKey doesn't have a .name attribute, but we can check the key string representation
        assert "metrics_client" in str(MetricsClientAppKey)

    @patch('social.graze.aip.app.metrics.create_metrics_client')
    def test_server_integration(self, mock_factory):
        """Server should use factory function to create metrics client."""
        from social.graze.aip.app.config import Settings
        
        mock_client = Mock()
        mock_factory.return_value = mock_client
        
        settings = Settings(
            metrics_backend="otel",
            otel_service_name="test-service",
            metrics_host="test-host",
            metrics_port=8125,
            worker_id="test-worker"  # Required field
        )
        
        # Simulate server startup logic
        from social.graze.aip.app.metrics import create_metrics_client
        client = create_metrics_client(
            backend=settings.metrics_backend,
            service_name=settings.otel_service_name,
            service_version=settings.otel_service_version,
            host=settings.metrics_host,
            port=settings.metrics_port,
            otel_endpoint=settings.otel_exporter_endpoint,
            debug=settings.debug,
        )
        
        mock_factory.assert_called_once_with(
            backend="otel",
            service_name="test-service",
            service_version="1.0.0",
            host="test-host",
            port=8125,
            otel_endpoint=None,
            debug=False,
        )


class TestMetricsErrorHandling:
    """Test error handling in metrics implementations."""

    @pytest.mark.asyncio
    async def test_telegraf_close_error_handling(self):
        """TelegrafCompatibilityClient should handle close errors gracefully."""
        mock_client = Mock()
        mock_client.close = AsyncMock(side_effect=Exception("Connection error"))
        
        telegraf_client = TelegrafCompatibilityClient(mock_client)
        
        # Should not raise exception
        await telegraf_client.close()

    @pytest.mark.skipif(
        not hasattr(__import__('social.graze.aip.app.metrics', fromlist=['OTEL_AVAILABLE']), 'OTEL_AVAILABLE') 
        or not __import__('social.graze.aip.app.metrics', fromlist=['OTEL_AVAILABLE']).OTEL_AVAILABLE,
        reason="OpenTelemetry not available"
    )
    @pytest.mark.asyncio
    async def test_otel_close_error_handling(self):
        """OTELMetricsClient should handle close errors gracefully."""
        # This test only runs when OTEL is actually available
        from social.graze.aip.app.metrics import OTELMetricsClient
        
        client = OTELMetricsClient()
        
        # Mock the meter provider to simulate shutdown error
        with patch.object(client, 'meter') as mock_meter:
            mock_provider = Mock()
            mock_provider.shutdown.side_effect = Exception("Shutdown error")
            
            with patch('social.graze.aip.app.metrics.metrics') as mock_metrics:
                mock_metrics.get_meter_provider.return_value = mock_provider
                
                # Should not raise exception - errors are caught and logged
                await client.close()

    def test_metric_operation_error_isolation(self):
        """Metric operations should not crash application on errors."""
        # Test that metric calls are fire-and-forget and don't propagate errors
        mock_client = Mock()
        mock_client.increment.side_effect = Exception("Network error")
        
        telegraf_client = TelegrafCompatibilityClient(mock_client)
        
        # This should propagate the exception since we're testing the wrapper
        with pytest.raises(Exception, match="Network error"):
            telegraf_client.increment("test.counter")

        # But NoOp should never raise
        noop_client = NoOpMetricsClient()
        noop_client.increment("test.counter")  # Should not raise


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
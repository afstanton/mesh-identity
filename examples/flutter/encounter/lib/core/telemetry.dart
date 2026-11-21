/// Abstract telemetry service for event and crash reporting.
abstract interface class TelemetryService {
  /// Record a non-fatal event with optional properties.
  void recordEvent(String event, [Map<String, Object?>? properties]);

  /// Record an error or exception with stack trace.
  void recordError(Object error, [StackTrace? stackTrace]);
}

/// Null-object implementation of [TelemetryService].
///
/// Guaranteed to perform zero network activity, disk writes, or memory caching.
final class NoOpTelemetryService implements TelemetryService {
  const NoOpTelemetryService();

  @override
  void recordEvent(String event, [Map<String, Object?>? properties]) {}

  @override
  void recordError(Object error, [StackTrace? stackTrace]) {}
}

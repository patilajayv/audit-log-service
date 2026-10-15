package com.example.auditlog.security;

/**
 * Monotonic elapsed-time source suitable for measuring elapsed durations and computing token refill rates.
 *
 * <p>Guarantees non-decreasing time values across JVM execution ($t_2 \ge t_1$), unaffected by system
 * wall-clock adjustments or NTP corrections. This time source does not claim that every consecutive call
 * returns a strictly greater value, correctly accommodating high-frequency calls within the resolution limit
 * of the underlying operating system timer.
 */
@FunctionalInterface
public interface NanoTimeSource {

    /**
     * Returns the current value of the monotonic elapsed-time source in nanoseconds.
     *
     * @return current monotonic nanoseconds (non-decreasing)
     */
    long nanoTime();

    /**
     * Returns the standard production time source backed by {@link System#nanoTime()}.
     *
     * @return production NanoTimeSource instance
     */
    static NanoTimeSource system() {
        return System::nanoTime;
    }
}

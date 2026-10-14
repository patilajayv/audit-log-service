package com.example.auditlog.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enforces a strict maximum request-body size for HTTP requests.
 *
 * <p>Requests with declared {@code Content-Length} exceeding the limit are rejected immediately
 * with {@code 413 Payload Too Large} before reading the body or invoking downstream filters.
 *
 * <p>Requests with chunked or undeclared transfer encoding are streamed through a counting
 * bounded input stream that aborts and returns {@code 413 Payload Too Large} as soon as the
 * limit is exceeded, preventing silent truncation or denial-of-service through memory exhaustion.
 */
public class RequestBodySizeLimitFilter extends OncePerRequestFilter {

    /** Default maximum body size: 1 MiB (1,048,576 bytes). */
    public static final long DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

    private final long maxBodyBytes;
    private final ObjectMapper objectMapper;

    public RequestBodySizeLimitFilter() {
        this(DEFAULT_MAX_BODY_BYTES);
    }

    public RequestBodySizeLimitFilter(long maxBodyBytes) {
        this.maxBodyBytes = maxBodyBytes;
        this.objectMapper = new ObjectMapper().findAndRegisterModules();
    }

    public long getMaxBodyBytes() {
        return maxBodyBytes;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Check declared Content-Length first
        long declaredLength = request.getContentLengthLong();
        if (declaredLength > maxBodyBytes) {
            sendPayloadTooLargeResponse(response);
            return;
        }

        // Wrap request to enforce limit on chunked or undeclared streams
        BoundedRequestWrapper wrappedRequest = new BoundedRequestWrapper(request, maxBodyBytes);
        try {
            filterChain.doFilter(wrappedRequest, response);
        } catch (Exception e) {
            if (isPayloadTooLargeException(e)) {
                if (!response.isCommitted()) {
                    sendPayloadTooLargeResponse(response);
                    return;
                }
            }
            if (e instanceof ServletException se) {
                throw se;
            }
            if (e instanceof IOException ioe) {
                throw ioe;
            }
            throw new ServletException(e);
        }
    }

    private boolean isPayloadTooLargeException(Throwable t) {
        Throwable curr = t;
        while (curr != null) {
            if (curr instanceof PayloadTooLargeException) {
                return true;
            }
            curr = curr.getCause();
        }
        return false;
    }

    private void sendPayloadTooLargeResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        ErrorResponse error = new ErrorResponse(
                HttpStatus.PAYLOAD_TOO_LARGE.value(),
                HttpStatus.PAYLOAD_TOO_LARGE.getReasonPhrase(),
                "Request payload exceeds maximum allowed size of " + maxBodyBytes + " bytes",
                Instant.now());
        response.getOutputStream().write(objectMapper.writeValueAsBytes(error));
    }

    private static class BoundedRequestWrapper extends HttpServletRequestWrapper {
        private final long maxBytes;
        private BoundedServletInputStream boundedStream;

        BoundedRequestWrapper(HttpServletRequest request, long maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (boundedStream == null) {
                boundedStream = new BoundedServletInputStream(super.getInputStream(), maxBytes);
            }
            return boundedStream;
        }
    }

    private static class BoundedServletInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long maxBytes;
        private long bytesRead = 0;

        BoundedServletInputStream(ServletInputStream delegate, long maxBytes) {
            this.delegate = delegate;
            this.maxBytes = maxBytes;
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            delegate.setReadListener(readListener);
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) {
                checkLimit(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = delegate.read(b, off, len);
            if (n > 0) {
                checkLimit(n);
            }
            return n;
        }

        private void checkLimit(int additional) throws PayloadTooLargeException {
            bytesRead += additional;
            if (bytesRead > maxBytes) {
                throw new PayloadTooLargeException(
                        "Request payload exceeds maximum allowed size of " + maxBytes + " bytes");
            }
        }
    }
}

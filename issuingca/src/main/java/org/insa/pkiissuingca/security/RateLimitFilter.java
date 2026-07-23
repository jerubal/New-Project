package org.insa.pkiissuingca.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-IP rate limiter applied only to POST /api/v1/auth/login.
 * Allows 5 attempts per 60-second sliding window per client IP.
 * Returns HTTP 429 Too Many Requests on breach.
 *
 * Uses Bucket4j in-memory (no Redis required). For multi-instance deployments,
 * replace with a Bucket4j distributed backend (Redis/Hazelcast).
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final int MAX_REQUESTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    // ConcurrentHashMap is safe for concurrent access; entries are lazily created.
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Only rate-limit POST /api/v1/auth/login
        if ("POST".equalsIgnoreCase(request.getMethod()) &&
                LOGIN_PATH.equals(request.getRequestURI())) {

            String clientIp = resolveClientIp(request);
            Bucket bucket = buckets.computeIfAbsent(clientIp, this::newBucket);

            if (!bucket.tryConsume(1)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setHeader("Retry-After", String.valueOf(WINDOW.getSeconds()));
                response.getWriter().write(
                        "{\"status\":429,\"error\":\"Too Many Requests\"," +
                        "\"message\":\"Login rate limit exceeded. Maximum " + MAX_REQUESTS +
                        " attempts per " + WINDOW.toMinutes() + " minute(s) per IP address.\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private Bucket newBucket(String ip) {
        Bandwidth limit = Bandwidth.classic(MAX_REQUESTS, Refill.greedy(MAX_REQUESTS, WINDOW));
        return Bucket.builder().addLimit(limit).build();
    }

    /**
     * Resolves the real client IP, honouring X-Forwarded-For when behind a reverse proxy.
     * Uses the last IP address appended by upstream proxies to prevent client header spoofing.
     */
    private String resolveClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            String[] parts = xff.split(",");
            return parts[parts.length - 1].trim();
        }
        return request.getRemoteAddr();
    }
}

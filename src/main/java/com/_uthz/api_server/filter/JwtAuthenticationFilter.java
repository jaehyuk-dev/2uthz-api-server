package com._uthz.api_server.filter;

import com._uthz.api_server.security.JwtUserDetails;
import com._uthz.api_server.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT Authentication Filter for processing Bearer token authentication.
 * 
 * This filter intercepts HTTP requests to extract and validate JWT tokens
 * from the Authorization header. It authenticates users based on valid tokens
 * and sets up the Spring Security context for downstream processing.
 * 
 * Key responsibilities:
 * - Extract JWT tokens from Authorization header
 * - Validate token authenticity and expiration
 * - Extract user information from valid tokens
 * - Set up Spring Security authentication context
 * - Handle authentication errors gracefully
 * 
 * Security features:
 * - Bearer token format validation
 * - JWT signature and expiration verification
 * - Proper security context management
 * - Error handling without exposing sensitive information
 * - Request-scoped authentication state
 * 
 * Filter behavior:
 * - Runs once per request (OncePerRequestFilter)
 * - Processes only requests with Authorization header
 * - Skips processing for public endpoints
 * - Continues filter chain regardless of authentication result
 * - Logs security events for monitoring and debugging
 */
@Component
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * JWT utility for token operations.
     * Used for token validation, parsing, and claims extraction.
     */
    private final JwtUtil jwtUtil;

    /**
     * Authorization header name constant.
     * Standard HTTP header for authentication credentials.
     */
    private static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * Bearer token prefix constant.
     * Standard prefix for JWT tokens in Authorization header.
     */
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Default user role for authenticated users.
     * All authenticated users get this basic role.
     */
    private static final String USER_ROLE = "ROLE_USER";

    /**
     * Main filter method that processes each HTTP request.
     * 
     * This method is called once per request to handle JWT authentication.
     * It extracts the token from the Authorization header, validates it,
     * and sets up the security context if authentication is successful.
     * 
     * @param request The HTTP request being processed
     * @param response The HTTP response being prepared
     * @param filterChain The filter chain to continue processing
     * @throws ServletException if servlet processing fails
     * @throws IOException if I/O operations fail
     * 
     * Process flow:
     * 1. Extract JWT token from Authorization header
     * 2. Validate token format and authenticity
     * 3. Extract user information from token claims
     * 4. Create authentication object and set security context
     * 5. Continue with filter chain processing
     * 
     * Error handling:
     * - Invalid tokens are logged but don't stop request processing
     * - Missing tokens simply skip authentication (for public endpoints)
     * - Authentication failures are handled gracefully
     * - Security context is only set for valid tokens
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        log.debug("Processing authentication for request: {} {}", request.getMethod(), request.getRequestURI());

        try {
            // Extract JWT token from Authorization header
            String token = extractTokenFromRequest(request);

            // Process authentication if token is present and no authentication exists
            if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                authenticateWithToken(token, request);
            }

        } catch (Exception e) {
            // Log authentication errors but don't block the request
            // This allows the security framework to handle unauthorized access appropriately
            log.warn("JWT authentication failed for request {} {}: {}", 
                    request.getMethod(), request.getRequestURI(), e.getMessage());
        }

        // Continue with the filter chain regardless of authentication result
        // This ensures that public endpoints work properly and authorization
        // decisions are made by the security configuration
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from the Authorization header.
     * 
     * This method parses the Authorization header to extract the JWT token.
     * It validates the Bearer token format and returns the token string
     * without the "Bearer " prefix.
     * 
     * @param request The HTTP request containing the Authorization header
     * @return String containing the JWT token, or null if not present/invalid
     * 
     * Expected header format: "Authorization: Bearer {jwt-token}"
     * 
     * Validation performed:
     * - Header presence check
     * - Bearer prefix validation
     * - Token content validation (not empty)
     * 
     * Security considerations:
     * - Case-sensitive Bearer prefix matching
     * - Proper token extraction to avoid injection attacks
     * - Null safety for missing or malformed headers
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        // Get the Authorization header value
        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        // Validate header format and extract token
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String token = authorizationHeader.substring(BEARER_PREFIX.length()).trim();
            
            // Ensure token is not empty after removing prefix
            if (StringUtils.hasText(token)) {
                log.debug("JWT token extracted from Authorization header");
                return token;
            } else {
                log.debug("Empty token found in Authorization header");
            }
        } else {
            log.debug("No valid Authorization header found or incorrect format");
        }

        return null;
    }

    /**
     * Authenticates user using the provided JWT token.
     * 
     * This method validates the JWT token and creates a Spring Security
     * authentication object if the token is valid. It extracts user information
     * from the token claims and sets up the security context with the token
     * stored for later access by UserContextService.
     * 
     * @param token The JWT token to authenticate with
     * @param request The HTTP request for authentication details
     * 
     * Authentication process:
     * 1. Validate token signature and expiration
     * 2. Verify token type (must be access token)
     * 3. Extract user information from token claims
     * 4. Create authentication object with user details and token
     * 5. Set authentication in security context for request-scoped access
     * 
     * Security validations:
     * - Token signature verification
     * - Token expiration check
     * - Token type validation (access vs refresh)
     * - User ID extraction and validation
     * - Role extraction for authorization
     * 
     * Error scenarios:
     * - Invalid or expired tokens are rejected
     * - Malformed tokens are logged and ignored
     * - Missing user information prevents authentication
     * - Token type mismatches are logged as security events
     */
    private void authenticateWithToken(String token, HttpServletRequest request) {
        try {
            // Validate token authenticity and expiration
            if (!jwtUtil.isTokenValid(token)) {
                log.debug("Token validation failed - invalid or expired token");
                return;
            }

            // Verify this is an access token (not a refresh token)
            if (!jwtUtil.isTokenOfType(token, "access")) {
                log.warn("Authentication attempted with non-access token type");
                return;
            }

            // Extract user information from token claims
            Long userId = jwtUtil.getUserIdFromToken(token);
            String email = jwtUtil.getEmailFromToken(token);
            String nickname = jwtUtil.getNicknameFromToken(token);
            String role = jwtUtil.getRoleFromToken(token);

            // Validate that required user information is present
            if (userId == null || email == null) {
                log.warn("Token missing required user information (userId: {}, email: {})", userId, email);
                return;
            }

            log.debug("Authenticating user - ID: {}, Email: {}, Role: {}", userId, email, role);

            // Create authentication object with user details and store the token
            // The token is stored in credentials for access by UserContextService
            Authentication authentication = createAuthenticationWithToken(userId, email, nickname, role, token, request);

            // Set authentication in security context for this request
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("Authentication successful for user ID: {} with role: {}", userId, role);

        } catch (Exception e) {
            // Log authentication errors for security monitoring
            log.warn("Error during token authentication: {}", e.getMessage());
            
            // Clear any partial authentication state
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Creates a Spring Security authentication object for the authenticated user with JWT token.
     * 
     * This method constructs an authentication object containing user information,
     * authorities, and the JWT token using a custom JwtUserDetails principal.
     * It represents the authenticated user's identity and permissions within
     * the Spring Security framework with enhanced JWT support.
     * 
     * @param userId The unique identifier of the authenticated user
     * @param email The user's email address (principal)
     * @param nickname The user's display nickname
     * @param role The user's role for authorization
     * @param token The JWT token for storage in credentials
     * @param request The HTTP request for authentication details
     * @return Authentication object representing the authenticated user
     * 
     * Authentication object components:
     * - Principal: JwtUserDetails with comprehensive user information
     * - Credentials: JWT token (stored for UserContextService access)
     * - Authorities: User roles and permissions from JwtUserDetails
     * - Details: Additional request-specific information
     * - Authenticated: true (since token validation passed)
     * 
     * JwtUserDetails advantages:
     * - Implements UserDetails interface for Spring Security compatibility
     * - Contains all user information from JWT token claims
     * - Provides role-based authority mapping with hierarchy
     * - Offers convenience methods for role checking
     * - Thread-safe and immutable user representation
     * 
     * Security considerations:
     * - Principal contains complete user context from JWT
     * - JWT token stored in credentials for UserContextService
     * - Authorities automatically generated from user role
     * - Authentication details include request metadata
     * - Role-based authority assignment with inheritance
     */
    private Authentication createAuthenticationWithToken(Long userId, String email, String nickname, 
                                                       String role, String token, HttpServletRequest request) {
        // Create JwtUserDetails as principal with complete user information
        // This provides a rich UserDetails implementation with JWT support
        JwtUserDetails userDetails = JwtUserDetails.fromTokenClaims(userId, email, nickname, role, token);

        // Create authentication token with JwtUserDetails as principal
        // Principal: JwtUserDetails with comprehensive user information
        // Credentials: JWT token (stored for UserContextService access)
        // Authorities: Automatically provided by JwtUserDetails.getAuthorities()
        UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());

        // Add request details for audit and security logging
        // This includes IP address, session ID, and other request metadata
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        log.debug("Created authentication object for user: {} (ID: {}) with role: {} and authorities: {}", 
                 email, userId, role, userDetails.getAuthorities());

        return authentication;
    }


    /**
     * Determines if this filter should process the current request.
     * 
     * This method can be overridden to skip authentication for certain
     * requests, such as health checks, public resources, or specific endpoints.
     * 
     * @param request The HTTP request to evaluate
     * @return true if the filter should process this request, false to skip
     * 
     * Current behavior: Processes all requests
     * 
     * Potential optimizations:
     * - Skip processing for public endpoints (e.g., /api/auth/*)
     * - Skip processing for static resources (e.g., /css/*, /js/*)
     * - Skip processing for health check endpoints
     * - Skip processing for requests that already have authentication
     * 
     * Example implementation:
     * ```java
     * @Override
     * protected boolean shouldNotFilter(HttpServletRequest request) {
     *     String path = request.getRequestURI();
     *     return path.startsWith("/api/auth/") || 
     *            path.startsWith("/public/") ||
     *            path.equals("/health");
     * }
     * ```
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Process all requests by default
        // This allows the security configuration to determine which endpoints require authentication
        return false;
    }
}
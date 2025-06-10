package com._uthz.api_server.config;

import com._uthz.api_server.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration for the API server with JWT authentication.
 * 
 * This configuration class sets up the security framework for the application,
 * including JWT-based authentication, password encoding, and endpoint security.
 * It configures Spring Security to handle stateless authentication using
 * JSON Web Tokens for API access.
 * 
 * Key security features:
 * - JWT-based stateless authentication using Bearer tokens
 * - BCrypt password encoding for secure password storage
 * - Custom JWT authentication filter for token processing
 * - Stateless session management for REST API architecture
 * - Public endpoints for authentication (login/register)
 * - Protected endpoints requiring valid JWT tokens
 * 
 * Authentication flow:
 * 1. User logs in with credentials via /api/auth/login
 * 2. Server validates credentials and returns JWT tokens
 * 3. Client includes access token in Authorization header
 * 4. JWT filter validates token and sets authentication context
 * 5. Protected endpoints check authentication from security context
 * 
 * Security considerations:
 * - Stateless design prevents session fixation attacks
 * - JWT tokens have configurable expiration times
 * - Refresh tokens allow secure token renewal
 * - Bearer token format prevents CSRF attacks
 * - Public endpoints are limited to essential authentication functions
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor // Lombok: generates constructor for final fields
public class SecurityConfig {

    /**
     * JWT authentication filter for processing Bearer tokens.
     * Injected to be added to the security filter chain.
     */
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Configures the security filter chain for HTTP requests with JWT authentication.
     * 
     * This method defines the complete security configuration including endpoint access rules,
     * JWT authentication filter integration, and security policies. It sets up stateless
     * authentication using JWT tokens for API access.
     * 
     * Security policies implemented:
     * - Authentication endpoints (/api/auth/**) are publicly accessible
     * - H2 database console is accessible for development (should be disabled in production)
     * - All other endpoints require valid JWT authentication
     * - CSRF protection is disabled for stateless REST API
     * - Sessions are stateless to support token-based authentication
     * - JWT authentication filter processes Bearer tokens
     * 
     * Filter chain order:
     * 1. JWT Authentication Filter (validates Bearer tokens)
     * 2. Username/Password Authentication Filter (standard Spring Security)
     * 3. Other Spring Security filters
     * 
     * @param http The HttpSecurity object to configure
     * @return Configured SecurityFilterChain with JWT authentication
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF protection for stateless REST API
            // CSRF is not needed for stateless APIs using JWT tokens
            // JWT tokens in Authorization header are not subject to CSRF attacks
            .csrf(AbstractHttpConfigurer::disable)
            
            // Configure authorization rules for different endpoints
            .authorizeHttpRequests(authz -> authz
                // Allow public access to authentication endpoints
                // These endpoints must be accessible for initial login/registration
                // No authentication required for: login, register, email check, refresh
                .requestMatchers("/api/auth/login", "/api/auth/register", "/api/auth/check-email", "/api/auth/refresh").permitAll()
                
                // Allow access to H2 database console for development
                // TODO: Remove this in production environment for security
                // H2 console should not be accessible in production deployments
                .requestMatchers("/h2-console/**").permitAll()
                
                // Allow access to health check and actuator endpoints
                // These endpoints are used for monitoring and should be accessible
                .requestMatchers("/actuator/**").permitAll()
                
                // Require JWT authentication for all other endpoints
                // Protected endpoints must have valid Bearer token in Authorization header
                // This includes user profiles, protected resources, and API operations
                .anyRequest().authenticated()
            )
            
            // Configure stateless session management
            // This is essential for REST APIs using token-based authentication
            // No server-side sessions are created or maintained
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Add JWT authentication filter to the security filter chain
            // This filter runs before the standard username/password authentication filter
            // It processes Bearer tokens and sets authentication context for valid tokens
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            
            // Disable frame options for H2 console access
            // H2 console uses frames which are blocked by default security headers
            // This setting is required for H2 console functionality in development
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.disable()) // Required for H2 console in development
            );

        return http.build();
    }

    /**
     * Provides BCrypt password encoder bean for secure password hashing.
     * 
     * BCrypt is a strong, adaptive password hashing function that includes
     * built-in salting and is designed to be slow to resist brute-force attacks.
     * 
     * Key features of BCrypt:
     * - Adaptive cost parameter that can be increased as hardware improves
     * - Built-in salt generation for each password
     * - One-way hashing - passwords cannot be decrypted
     * - Resistant to rainbow table attacks
     * - Industry standard for password security
     * 
     * Configuration:
     * - Uses default strength (10) which provides good security/performance balance
     * - Each password gets a unique salt automatically
     * - Hashing time is intentionally slow to prevent brute force
     * 
     * @return BCryptPasswordEncoder instance for password operations
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt with default strength (10) - provides strong security
        // Higher strength values increase security but also processing time
        return new BCryptPasswordEncoder();
    }
}
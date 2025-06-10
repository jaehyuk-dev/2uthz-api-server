package com._uthz.api_server.service;

import com._uthz.api_server.entity.User;
import com._uthz.api_server.repository.UserRepository;
import com._uthz.api_server.security.JwtUserDetails;
import com._uthz.api_server.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service for extracting and managing user context information from JWT tokens.
 * 
 * This utility service provides convenient methods to access current authenticated
 * user information from JWT tokens in API requests. It simplifies the process of
 * retrieving user details in controller methods without repetitive token parsing.
 * 
 * Key features:
 * - Extract user information from JWT tokens in Spring Security context
 * - Convenient methods for accessing user ID, email, nickname, and role
 * - Optional user entity loading for complete user information
 * - Thread-safe access to authentication context
 * - Comprehensive error handling for invalid or missing tokens
 * 
 * Security considerations:
 * - Only works with properly authenticated requests (valid JWT tokens)
 * - Uses Spring Security context for secure user information access
 * - Handles cases where authentication is missing or invalid
 * - No sensitive information logging for security compliance
 * 
 * Usage pattern:
 * 1. Client sends request with valid JWT Bearer token
 * 2. JWT authentication filter validates token and sets security context
 * 3. Controller methods use this service to access current user information
 * 4. Service extracts user details from authentication context
 * 
 * Thread safety:
 * - SecurityContextHolder is thread-local, ensuring proper isolation
 * - Each request thread has its own authentication context
 * - Safe for concurrent use in multi-threaded environments
 */
@Slf4j // Lombok: provides logger instance for debugging and monitoring
@Service // Spring: marks this as a service component for dependency injection
@RequiredArgsConstructor // Lombok: generates constructor for final fields
public class UserContextService {

    /**
     * JWT utility for token operations and user ID extraction.
     * Used to parse JWT tokens and extract user information.
     */
    private final JwtUtil jwtUtil;

    /**
     * User repository for loading complete user entities from database.
     * Used when full user information is needed beyond basic JWT claims.
     */
    private final UserRepository userRepository;

    /**
     * Gets the current authenticated user's ID from the JWT token.
     * 
     * This method extracts the user ID from the JWT token in the current
     * Spring Security authentication context. It's the most commonly used
     * method for identifying the current user in API endpoints.
     * 
     * Process flow:
     * 1. Retrieves authentication from Spring Security context
     * 2. Extracts JWT token from authentication credentials
     * 3. Parses user ID from JWT token claims
     * 4. Returns user ID as Long value
     * 
     * Security validation:
     * - Requires valid authentication in security context
     * - JWT token must be properly signed and not expired
     * - User ID claim must be present in token
     * 
     * Common usage in controllers:
     * ```java
     * @GetMapping("/profile")
     * public ResponseEntity<?> getProfile() {
     *     Long userId = userContextService.getCurrentUserId();
     *     // Use userId for business logic
     * }
     * ```
     * 
     * @return Current authenticated user's ID, or null if not authenticated
     * @throws IllegalStateException if authentication context is invalid
     */
    public Long getCurrentUserId() {
        try {
            // Get current authentication from Spring Security context
            // This contains the JWT token set by the authentication filter
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                log.debug("No valid authentication found in security context");
                return null;
            }

            // Extract JWT token from authentication credentials
            // The JWT authentication filter stores the token in credentials
            String token = (String) authentication.getCredentials();
            
            if (token == null) {
                log.debug("No JWT token found in authentication credentials");
                return null;
            }

            // Extract user ID from JWT token using utility
            // This validates the token and extracts the subject claim
            return jwtUtil.getUserIdFromToken(token);
            
        } catch (Exception e) {
            // Log error for debugging but don't expose sensitive information
            log.error("Error extracting user ID from JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the current authenticated user's email from the JWT token.
     * 
     * This method extracts the email address from the JWT token claims.
     * Email is commonly used for user identification and communication
     * purposes in business logic.
     * 
     * Token requirements:
     * - Valid JWT token in authentication context
     * - Email claim present in token payload
     * - Token must be properly signed and not expired
     * 
     * Usage examples:
     * - Sending notifications to current user
     * - Auditing user actions with email identification
     * - Personalizing responses with user email
     * 
     * @return Current authenticated user's email, or null if not available
     */
    public String getCurrentUserEmail() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return null;
            }

            String token = (String) authentication.getCredentials();
            if (token == null) {
                return null;
            }

            // Extract email from JWT token claims
            return jwtUtil.getEmailFromToken(token);
            
        } catch (Exception e) {
            log.error("Error extracting user email from JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the current authenticated user's nickname from the JWT token.
     * 
     * This method extracts the user's display name or nickname from JWT claims.
     * Nickname is typically used for displaying user-friendly names in UI
     * components and personalized messages.
     * 
     * Business use cases:
     * - Displaying welcome messages with user's preferred name
     * - Showing author names in user-generated content
     * - Personalizing API responses with user's display name
     * 
     * @return Current authenticated user's nickname, or null if not available
     */
    public String getCurrentUserNickname() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return null;
            }

            String token = (String) authentication.getCredentials();
            if (token == null) {
                return null;
            }

            // Extract nickname from JWT token claims
            return jwtUtil.getNicknameFromToken(token);
            
        } catch (Exception e) {
            log.error("Error extracting user nickname from JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the current authenticated user's role from the JWT token.
     * 
     * This method extracts the user's role or permission level from JWT claims.
     * Role information is essential for implementing authorization logic
     * and controlling access to different application features.
     * 
     * Authorization use cases:
     * - Checking if user has admin privileges
     * - Implementing role-based access control (RBAC)
     * - Customizing UI based on user permissions
     * - Filtering data based on user role
     * 
     * Common roles:
     * - USER: Standard user with basic permissions
     * - ADMIN: Administrative user with elevated privileges
     * - MODERATOR: User with content moderation capabilities
     * 
     * @return Current authenticated user's role, or null if not available
     */
    public String getCurrentUserRole() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return null;
            }

            String token = (String) authentication.getCredentials();
            if (token == null) {
                return null;
            }

            // Extract role from JWT token claims
            return jwtUtil.getRoleFromToken(token);
            
        } catch (Exception e) {
            log.error("Error extracting user role from JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Loads the complete User entity for the current authenticated user.
     * 
     * This method combines JWT token user ID extraction with database lookup
     * to provide the full User entity with all fields and relationships.
     * Use this when you need complete user information beyond JWT claims.
     * 
     * Performance considerations:
     * - Involves database query, so use sparingly in high-traffic endpoints
     * - Consider caching user entities for frequently accessed data
     * - Prefer JWT claims for simple user identification
     * 
     * When to use this method:
     * - Need user creation/update timestamps
     * - Require user preferences or settings
     * - Need to update user information
     * - Accessing user relationships or complex data
     * 
     * When to use JWT claims instead:
     * - Simple user identification (ID, email, nickname)
     * - High-frequency operations where performance matters
     * - Read-only operations that don't modify user data
     * 
     * @return Optional containing current User entity, empty if not found or not authenticated
     */
    public Optional<User> getCurrentUser() {
        try {
            // First get the user ID from JWT token
            Long userId = getCurrentUserId();
            
            if (userId == null) {
                log.debug("Cannot load user entity: no valid user ID found");
                return Optional.empty();
            }

            // Load complete user entity from database using user ID
            // This provides access to all user fields and relationships
            return userRepository.findById(userId);
            
        } catch (Exception e) {
            log.error("Error loading current user entity: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Checks if there is a valid authenticated user in the current context.
     * 
     * This utility method provides a simple way to verify if the current
     * request has valid authentication without extracting specific user details.
     * Useful for conditional logic and validation checks.
     * 
     * Validation checks:
     * - Authentication object exists in security context
     * - Authentication is marked as authenticated
     * - JWT token is present in credentials
     * - User ID can be extracted from token
     * 
     * Usage patterns:
     * ```java
     * if (userContextService.isAuthenticated()) {
     *     // Perform authenticated user operations
     * } else {
     *     // Handle unauthenticated access
     * }
     * ```
     * 
     * @return true if valid authenticated user exists, false otherwise
     */
    public boolean isAuthenticated() {
        try {
            // Check if we can successfully extract user ID
            // This validates the complete authentication chain
            Long userId = getCurrentUserId();
            return userId != null;
            
        } catch (Exception e) {
            log.debug("Authentication check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if the current authenticated user has the specified role.
     * 
     * This method provides convenient role-based authorization checking
     * for implementing access control in business logic. It compares
     * the current user's role with the specified required role.
     * 
     * Authorization patterns:
     * ```java
     * if (userContextService.hasRole("ADMIN")) {
     *     // Admin-only operations
     * }
     * ```
     * 
     * Role comparison:
     * - Case-sensitive string comparison
     * - Exact role match required
     * - Returns false for unauthenticated users
     * 
     * @param role The role to check for (case-sensitive)
     * @return true if current user has the specified role, false otherwise
     */
    public boolean hasRole(String role) {
        try {
            String userRole = getCurrentUserRole();
            return userRole != null && userRole.equals(role);
            
        } catch (Exception e) {
            log.debug("Role check failed for role '{}': {}", role, e.getMessage());
            return false;
        }
    }

    /**
     * Checks if the current authenticated user is an admin.
     * 
     * Convenience method for checking admin privileges. This is a common
     * authorization check in many applications for administrative functions.
     * 
     * Admin role definition:
     * - Role must be exactly "ADMIN" (case-sensitive)
     * - Used for elevated privilege operations
     * - Common administrative functions: user management, system configuration
     * 
     * @return true if current user has admin role, false otherwise
     */
    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    /**
     * Gets the current authenticated user's UserDetails from Spring Security context.
     * 
     * This method retrieves the UserDetails object from the Spring Security
     * authentication context. If using JwtUserDetails, it provides rich user
     * information directly from the principal without database queries.
     * 
     * Spring Security integration:
     * - Accesses principal from authentication context
     * - Returns UserDetails if principal implements the interface
     * - Provides type-safe access to user information
     * - Works with both custom and standard UserDetails implementations
     * 
     * @return Optional containing UserDetails, empty if not authenticated or principal is not UserDetails
     * 
     * Usage scenarios:
     * - Accessing user information through Spring Security interfaces
     * - Integration with Spring Security method-level security
     * - Type-safe user context access in business logic
     * - Compatibility with Spring Security ecosystem
     */
    public Optional<UserDetails> getCurrentUserDetails() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                log.debug("No authenticated user found for UserDetails access");
                return Optional.empty();
            }

            Object principal = authentication.getPrincipal();
            
            // Check if principal implements UserDetails interface
            if (principal instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principal;
                log.debug("Retrieved UserDetails for user: {}", userDetails.getUsername());
                return Optional.of(userDetails);
            } else {
                log.debug("Principal is not a UserDetails instance: {}", principal.getClass().getSimpleName());
                return Optional.empty();
            }
            
        } catch (Exception e) {
            log.error("Error retrieving UserDetails from security context: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Gets the current authenticated user's JwtUserDetails if available.
     * 
     * This method specifically retrieves JwtUserDetails from the Spring Security
     * context, providing access to JWT-specific user information and convenience
     * methods for role checking and user data access.
     * 
     * JwtUserDetails advantages:
     * - Direct access to JWT token claims
     * - Convenience methods for role checking
     * - Rich user information without database queries
     * - Thread-safe and immutable user representation
     * 
     * @return Optional containing JwtUserDetails, empty if not authenticated or not using JWT authentication
     * 
     * Usage patterns:
     * - Accessing JWT-specific user information
     * - Using convenience methods like isAdmin(), hasRole()
     * - Getting user details directly from token claims
     * - Performance-optimized user context access
     */
    public Optional<JwtUserDetails> getCurrentJwtUserDetails() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                log.debug("No authenticated user found for JwtUserDetails access");
                return Optional.empty();
            }

            Object principal = authentication.getPrincipal();
            
            // Check if principal is specifically JwtUserDetails
            if (principal instanceof JwtUserDetails) {
                JwtUserDetails jwtUserDetails = (JwtUserDetails) principal;
                log.debug("Retrieved JwtUserDetails for user: {} (ID: {})", 
                         jwtUserDetails.getEmail(), jwtUserDetails.getUserId());
                return Optional.of(jwtUserDetails);
            } else {
                log.debug("Principal is not a JwtUserDetails instance: {}", principal.getClass().getSimpleName());
                return Optional.empty();
            }
            
        } catch (Exception e) {
            log.error("Error retrieving JwtUserDetails from security context: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Gets the current authenticated user's username from Spring Security principal.
     * 
     * This method provides a Spring Security standard way to access the current
     * user's username (email in our case) from the authentication context.
     * It works with any UserDetails implementation and provides consistent
     * username access across different authentication mechanisms.
     * 
     * @return Current authenticated user's username (email), or null if not authenticated
     * 
     * Usage scenarios:
     * - Standard Spring Security username access
     * - Integration with Spring Security audit logging
     * - Compatibility with Spring Security annotations
     * - General user identification without JWT specifics
     */
    public String getCurrentUsername() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return null;
            }

            Object principal = authentication.getPrincipal();
            
            // Handle UserDetails principal
            if (principal instanceof UserDetails) {
                return ((UserDetails) principal).getUsername();
            }
            
            // Handle string principal (fallback)
            if (principal instanceof String) {
                return (String) principal;
            }
            
            // Handle other principal types by converting to string
            return principal.toString();
            
        } catch (Exception e) {
            log.error("Error extracting username from security context: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the JWT token from the current authentication context.
     * 
     * This method retrieves the JWT token stored in the authentication
     * credentials by the JWT authentication filter. It provides direct
     * access to the token for operations that require the raw JWT.
     * 
     * @return Current JWT token, or null if not available
     * 
     * Usage scenarios:
     * - Token forwarding to external services
     * - Token validation or parsing operations
     * - Debugging and logging token information
     * - Custom token-based operations
     */
    public String getCurrentJwtToken() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return null;
            }

            Object credentials = authentication.getCredentials();
            
            // JWT token is stored in credentials as a string
            if (credentials instanceof String) {
                return (String) credentials;
            }
            
            log.debug("Credentials is not a string: {}", 
                     credentials != null ? credentials.getClass().getSimpleName() : "null");
            return null;
            
        } catch (Exception e) {
            log.error("Error extracting JWT token from security context: {}", e.getMessage());
            return null;
        }
    }
}
package com._uthz.api_server.controller;

import com._uthz.api_server.dto.UserProfileDto;
import com._uthz.api_server.entity.User;
import com._uthz.api_server.service.UserContextService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Controller demonstrating UserContextService usage for extracting user information from JWT tokens.
 * 
 * This controller showcases various ways to access current authenticated user information
 * using the UserContextService utility. It provides practical examples of how to:
 * - Extract user details from JWT tokens in API endpoints
 * - Access user information without repetitive token parsing
 * - Implement role-based authorization using user context
 * - Handle authentication validation and error cases
 * 
 * Key features demonstrated:
 * - Getting current user basic information (ID, email, nickname, role)
 * - Loading complete user entity for complex operations
 * - Role-based access control and authorization checks
 * - Admin-only operations with role validation
 * - Error handling for unauthenticated requests
 * - User context validation and security checks
 * 
 * Security considerations:
 * - All endpoints require valid JWT authentication
 * - Role-based authorization is enforced where appropriate
 * - User context is validated before accessing user information
 * - Sensitive operations are restricted to appropriate roles
 * - Authentication failures are handled gracefully
 * 
 * Usage patterns demonstrated:
 * - Simple user identification for standard operations
 * - Complete user data access for profile management
 * - Admin privilege checking for administrative functions
 * - User context validation for security-sensitive operations
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance
@Tag(name = "User Management", description = "User information and context operations using JWT tokens")
public class UserController {

    /**
     * UserContextService for extracting user information from JWT tokens.
     * This utility service provides convenient access to current user context.
     */
    private final UserContextService userContextService;

    /**
     * Gets the current authenticated user's basic information from JWT token.
     * 
     * This endpoint demonstrates how to use UserContextService to extract
     * user details directly from JWT tokens without manual token parsing.
     * It shows the most common pattern for accessing current user information.
     * 
     * Process flow:
     * 1. JWT authentication filter validates Bearer token
     * 2. UserContextService extracts user info from token claims
     * 3. User details are returned in a structured response
     * 4. No database queries needed for basic user information
     * 
     * Usage scenarios:
     * - User profile display in client applications
     * - User identification for business logic
     * - Quick access to user details without DB queries
     * - Client-side personalization and customization
     * 
     * @return ResponseEntity with current user's basic information
     */
    @GetMapping("/me")
    @Operation(
        summary = "Get current user information",
        description = "Retrieves the current authenticated user's basic information from JWT token claims. " +
                     "This endpoint demonstrates how to use UserContextService for quick access to user details " +
                     "without database queries."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Successfully retrieved current user information",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = Map.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - no valid JWT token provided",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - invalid or expired JWT token",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Map<String, Object>> getCurrentUserInfo() {
        log.info("Request to get current user information from JWT token");

        // Extract user information from JWT token using UserContextService
        // This demonstrates the primary usage pattern for accessing user context
        Long userId = userContextService.getCurrentUserId();
        String email = userContextService.getCurrentUserEmail();
        String nickname = userContextService.getCurrentUserNickname();
        String role = userContextService.getCurrentUserRole();

        // Validate that user context is available
        if (userId == null) {
            log.warn("Current user info request failed: No valid user context found");
            return ResponseEntity.status(401).body(Map.of(
                "error", "Authentication required",
                "message", "No valid user context found in JWT token"
            ));
        }

        // Build response with user information extracted from JWT token
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("userId", userId);
        userInfo.put("email", email);
        userInfo.put("nickname", nickname);
        userInfo.put("role", role);
        userInfo.put("authenticated", true);
        userInfo.put("source", "JWT Token Claims");

        log.info("Successfully retrieved user info for user ID: {} ({})", userId, email);
        return ResponseEntity.ok(userInfo);
    }

    /**
     * Gets the current authenticated user's complete profile from database.
     * 
     * This endpoint demonstrates how to use UserContextService to get the user ID
     * from JWT token and then load the complete User entity from the database.
     * It shows the pattern for accessing complete user information when needed.
     * 
     * Process flow:
     * 1. JWT authentication filter validates Bearer token
     * 2. UserContextService extracts user ID from token
     * 3. Complete User entity is loaded from database
     * 4. User profile data is returned with all fields
     * 
     * When to use this pattern:
     * - Need complete user information beyond JWT claims
     * - Accessing user timestamps (created/updated)
     * - Require the most up-to-date user data
     * - Building comprehensive user profiles
     * 
     * @return ResponseEntity with complete user profile information
     */
    @GetMapping("/profile")
    @Operation(
        summary = "Get current user's complete profile",
        description = "Retrieves the current authenticated user's complete profile information from the database. " +
                     "This endpoint demonstrates how to use UserContextService to get user ID from JWT token " +
                     "and then load complete user data from the database."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Successfully retrieved user profile",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = UserProfileDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - no valid JWT token provided",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found in database",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<?> getCurrentUserProfile() {
        log.info("Request to get current user's complete profile");

        // Use UserContextService to load complete user entity
        // This demonstrates how to access full user data when needed
        Optional<User> currentUser = userContextService.getCurrentUser();

        // Handle case where user is not authenticated or not found
        if (currentUser.isEmpty()) {
            log.warn("User profile request failed: User not found or not authenticated");
            return ResponseEntity.status(401).body(Map.of(
                "error", "User not found",
                "message", "Current user not found or authentication invalid"
            ));
        }

        User user = currentUser.get();
        
        // Convert to profile DTO (excluding sensitive information like password)
        UserProfileDto profile = UserProfileDto.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();

        log.info("Successfully retrieved profile for user ID: {} ({})", user.getUserId(), user.getEmail());
        return ResponseEntity.ok(profile);
    }

    /**
     * Demonstrates role-based authorization using UserContextService.
     * 
     * This endpoint shows how to implement role-based access control using
     * the UserContextService utility. It demonstrates checking user roles
     * and restricting access based on authorization requirements.
     * 
     * Authorization flow:
     * 1. JWT authentication filter validates Bearer token
     * 2. UserContextService extracts user role from token
     * 3. Role is validated against required permissions
     * 4. Access is granted or denied based on role check
     * 
     * Role-based access patterns:
     * - Check specific roles for administrative functions
     * - Validate user permissions before sensitive operations
     * - Implement hierarchical role checking
     * - Provide role-specific functionality
     * 
     * @return ResponseEntity with role validation result
     */
    @GetMapping("/admin/status")
    @Operation(
        summary = "Check admin access status",
        description = "Demonstrates role-based authorization by checking if the current user has admin privileges. " +
                     "This endpoint shows how to use UserContextService for implementing role-based access control."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Successfully checked admin status",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = Map.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - admin role required",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Map<String, Object>> checkAdminStatus() {
        log.info("Request to check admin access status");

        // Validate user authentication using UserContextService
        if (!userContextService.isAuthenticated()) {
            log.warn("Admin status check failed: User not authenticated");
            return ResponseEntity.status(401).body(Map.of(
                "error", "Authentication required",
                "message", "Valid JWT token required for admin status check"
            ));
        }

        // Get current user information for role checking
        Long userId = userContextService.getCurrentUserId();
        String userRole = userContextService.getCurrentUserRole();
        boolean isAdmin = userContextService.isAdmin();

        // Build response with role information and admin status
        Map<String, Object> adminStatus = new HashMap<>();
        adminStatus.put("userId", userId);
        adminStatus.put("currentRole", userRole);
        adminStatus.put("isAdmin", isAdmin);
        adminStatus.put("hasAdminAccess", isAdmin);
        adminStatus.put("message", isAdmin ? "Admin access granted" : "Admin access denied");

        log.info("Admin status check for user ID: {} - Role: {} - Admin: {}", userId, userRole, isAdmin);
        return ResponseEntity.ok(adminStatus);
    }

    /**
     * Admin-only endpoint demonstrating role-based access control.
     * 
     * This endpoint requires admin role and demonstrates how to implement
     * secure administrative functions using UserContextService for role validation.
     * It shows the pattern for protecting sensitive operations with role checks.
     * 
     * Security implementation:
     * 1. Authenticate user via JWT token validation
     * 2. Extract user role using UserContextService
     * 3. Validate admin role requirement
     * 4. Execute admin-only functionality if authorized
     * 5. Return appropriate error for unauthorized access
     * 
     * @return ResponseEntity with admin operation result or access denied
     */
    @GetMapping("/admin/dashboard")
    @Operation(
        summary = "Access admin dashboard (Admin only)",
        description = "Admin-only endpoint that demonstrates role-based access control. " +
                     "Requires admin role and shows how to protect sensitive operations using UserContextService."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Successfully accessed admin dashboard",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = Map.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - admin role required",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Map<String, Object>> getAdminDashboard() {
        log.info("Request to access admin dashboard");

        // Validate authentication using UserContextService
        if (!userContextService.isAuthenticated()) {
            log.warn("Admin dashboard access denied: User not authenticated");
            return ResponseEntity.status(401).body(Map.of(
                "error", "Authentication required",
                "message", "Valid JWT token required for admin dashboard access"
            ));
        }

        // Check admin role using UserContextService convenience method
        if (!userContextService.isAdmin()) {
            Long userId = userContextService.getCurrentUserId();
            String userRole = userContextService.getCurrentUserRole();
            
            log.warn("Admin dashboard access denied: User ID {} has role '{}' (admin required)", userId, userRole);
            return ResponseEntity.status(403).body(Map.of(
                "error", "Access denied",
                "message", "Admin role required for dashboard access",
                "currentRole", userRole,
                "requiredRole", "ADMIN"
            ));
        }

        // Admin access granted - provide dashboard information
        Long adminUserId = userContextService.getCurrentUserId();
        String adminEmail = userContextService.getCurrentUserEmail();
        String adminNickname = userContextService.getCurrentUserNickname();

        Map<String, Object> dashboardData = new HashMap<>();
        dashboardData.put("message", "Welcome to the admin dashboard!");
        dashboardData.put("adminUser", Map.of(
            "userId", adminUserId,
            "email", adminEmail,
            "nickname", adminNickname,
            "role", "ADMIN"
        ));
        dashboardData.put("accessTime", java.time.LocalDateTime.now());
        dashboardData.put("permissions", new String[]{"USER_MANAGEMENT", "SYSTEM_CONFIG", "ANALYTICS", "CONTENT_MODERATION"});

        log.info("Admin dashboard accessed by user ID: {} ({})", adminUserId, adminEmail);
        return ResponseEntity.ok(dashboardData);
    }

    /**
     * Demonstrates user context validation and error handling.
     * 
     * This endpoint shows how to properly validate user context and handle
     * various authentication scenarios using UserContextService. It demonstrates
     * comprehensive error handling and validation patterns.
     * 
     * Validation scenarios covered:
     * - Valid authentication with complete user context
     * - Missing or invalid JWT tokens
     * - Expired or malformed tokens
     * - User not found in database
     * - Role validation and authorization checks
     * 
     * @return ResponseEntity with validation results and user context status
     */
    @GetMapping("/context/validate")
    @Operation(
        summary = "Validate user context and authentication status",
        description = "Demonstrates comprehensive user context validation using UserContextService. " +
                     "Shows how to handle various authentication scenarios and error conditions."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "User context validation completed",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = Map.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication validation failed",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Map<String, Object>> validateUserContext() {
        log.info("Request to validate user context and authentication status");

        Map<String, Object> validation = new HashMap<>();
        
        // Check if user is authenticated
        boolean isAuthenticated = userContextService.isAuthenticated();
        validation.put("isAuthenticated", isAuthenticated);

        if (!isAuthenticated) {
            validation.put("status", "UNAUTHENTICATED");
            validation.put("message", "No valid authentication found");
            validation.put("recommendations", new String[]{
                "Ensure Bearer token is included in Authorization header",
                "Verify token is not expired",
                "Check token format and signature"
            });
            
            log.warn("User context validation failed: No valid authentication");
            return ResponseEntity.status(401).body(validation);
        }

        // Extract user context information
        Long userId = userContextService.getCurrentUserId();
        String email = userContextService.getCurrentUserEmail();
        String nickname = userContextService.getCurrentUserNickname();
        String role = userContextService.getCurrentUserRole();
        
        // Check if complete user entity can be loaded
        Optional<User> userEntity = userContextService.getCurrentUser();
        boolean userEntityAvailable = userEntity.isPresent();

        // Build comprehensive validation response
        validation.put("status", "AUTHENTICATED");
        validation.put("message", "User context validation successful");
        validation.put("tokenClaims", Map.of(
            "userId", userId,
            "email", email,
            "nickname", nickname,
            "role", role
        ));
        validation.put("userEntityAvailable", userEntityAvailable);
        validation.put("roleChecks", Map.of(
            "isAdmin", userContextService.isAdmin(),
            "hasUserRole", userContextService.hasRole("USER"),
            "hasModeratorRole", userContextService.hasRole("MODERATOR")
        ));
        validation.put("validationTime", java.time.LocalDateTime.now());

        if (userEntityAvailable) {
            User user = userEntity.get();
            validation.put("userEntityInfo", Map.of(
                "createdAt", user.getCreatedAt(),
                "updatedAt", user.getUpdatedAt(),
                "dataSource", "Database"
            ));
        }

        log.info("User context validation successful for user ID: {} ({})", userId, email);
        return ResponseEntity.ok(validation);
    }
}
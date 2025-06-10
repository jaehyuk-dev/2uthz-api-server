package com._uthz.api_server.controller;

import com._uthz.api_server.dto.*;
import com._uthz.api_server.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for JWT-based user authentication and registration operations.
 * 
 * This controller provides HTTP endpoints for user authentication functionality
 * including user registration, login, token refresh, and profile management.
 * It handles all authentication-related REST API requests and delegates business
 * logic to the AuthenticationService.
 * 
 * Endpoint mappings:
 * - POST /api/auth/register - User registration with JWT tokens
 * - POST /api/auth/login - User authentication with JWT tokens
 * - POST /api/auth/refresh - JWT token refresh
 * - GET /api/auth/profile/{userId} - User profile retrieval
 * - GET /api/auth/check-email - Email availability checking
 * 
 * Key features:
 * - JWT-based stateless authentication
 * - Comprehensive input validation using Bean Validation
 * - Proper HTTP status codes and error handling
 * - Consistent JSON response format
 * - Request logging for security monitoring
 * - RESTful API design principles
 * - Bearer token authentication support
 * 
 * Security considerations:
 * - JWT tokens provide stateless authentication
 * - Input validation prevents malformed requests
 * - Error messages don't expose sensitive information
 * - Request logging helps with security monitoring
 * - Proper HTTP status codes for different scenarios
 * - Token refresh prevents session interruption
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance
public class AuthController {

    /**
     * Authentication service for handling business logic.
     * Injected through constructor for dependency inversion and testability.
     */
    private final AuthenticationService authenticationService;

    /**
     * Registers a new user account with JWT token generation.
     * 
     * This endpoint handles user registration requests by validating input data,
     * creating a new user account, and returning JWT tokens for immediate
     * authentication after successful registration.
     * 
     * @param registerRequest The registration data (email, password, nickname)
     * @return ResponseEntity with TokenResponseDto containing JWT tokens and metadata
     * 
     * HTTP Status Codes:
     * - 201 CREATED: User registration successful
     * - 400 BAD REQUEST: Validation errors or email already exists
     * - 500 INTERNAL SERVER ERROR: Unexpected server errors
     * 
     * Request validation:
     * - Email format and uniqueness validation
     * - Password strength requirements
     * - Nickname length and format validation
     * 
     * Success response includes:
     * - JWT access token for API authentication
     * - JWT refresh token for token renewal
     * - Token metadata (type, expiration, etc.)
     * - Welcome message for user feedback
     */
    @PostMapping("/register")
    public ResponseEntity<TokenResponseDto> registerUser(@Valid @RequestBody RegisterRequestDto registerRequest) {
        log.info("User registration request received for email: {}", registerRequest.getEmail());
        
        try {
            // Delegate business logic to service layer
            TokenResponseDto response = authenticationService.registerUser(registerRequest);
            
            log.info("User registration successful for email: {}", registerRequest.getEmail());
            
            // Return 201 Created with JWT tokens and metadata
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
            
        } catch (IllegalArgumentException e) {
            // Handle validation errors (email exists, invalid data, etc.)
            log.warn("User registration failed for email {}: {}", registerRequest.getEmail(), e.getMessage());
            
            // Create error response with appropriate message
            TokenResponseDto errorResponse = TokenResponseDto.builder()
                    .message(e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            
        } catch (Exception e) {
            // Handle unexpected server errors
            log.error("Unexpected error during user registration for email {}: {}", 
                     registerRequest.getEmail(), e.getMessage(), e);
            
            // Return generic error message to avoid exposing system details
            TokenResponseDto errorResponse = TokenResponseDto.builder()
                    .message("Registration failed due to a server error. Please try again later.")
                    .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Authenticates user login credentials with JWT token generation.
     * 
     * This endpoint validates user credentials and returns JWT tokens including
     * access and refresh tokens for subsequent authenticated requests.
     * 
     * @param loginRequest The login credentials (email and password)
     * @return ResponseEntity with TokenResponseDto containing JWT tokens and metadata
     * 
     * HTTP Status Codes:
     * - 200 OK: Authentication successful
     * - 401 UNAUTHORIZED: Invalid credentials
     * - 400 BAD REQUEST: Malformed request data
     * - 500 INTERNAL SERVER ERROR: Unexpected server errors
     * 
     * Security features:
     * - Secure password verification using BCrypt
     * - JWT tokens provide stateless authentication
     * - Failed login attempts are logged for monitoring
     * - Generic error messages prevent user enumeration
     * - Rate limiting should be implemented at infrastructure level
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> loginUser(@Valid @RequestBody LoginRequestDto loginRequest) {
        log.info("User login attempt for email: {}", loginRequest.getEmail());
        
        try {
            // Delegate authentication logic to service layer
            TokenResponseDto response = authenticationService.authenticateUser(loginRequest);
            
            log.info("User login successful for email: {}", loginRequest.getEmail());
            
            // Return 200 OK with JWT tokens and metadata
            return ResponseEntity.ok(response);
            
        } catch (IllegalArgumentException e) {
            // Handle authentication failures (invalid credentials)
            log.warn("User login failed for email {}: {}", loginRequest.getEmail(), e.getMessage());
            
            // Return generic error message to prevent user enumeration attacks
            TokenResponseDto errorResponse = TokenResponseDto.builder()
                    .message("Invalid email or password")
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            
        } catch (Exception e) {
            // Handle unexpected server errors
            log.error("Unexpected error during user login for email {}: {}", 
                     loginRequest.getEmail(), e.getMessage(), e);
            
            // Return generic error message to avoid exposing system details
            TokenResponseDto errorResponse = TokenResponseDto.builder()
                    .message("Login failed due to a server error. Please try again later.")
                    .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Refreshes JWT tokens using a valid refresh token.
     * 
     * This endpoint allows clients to obtain new access and refresh tokens
     * using a valid refresh token, enabling continued authentication without
     * requiring the user to log in again.
     * 
     * @param refreshTokenRequest The request containing the refresh token
     * @return ResponseEntity with TokenResponseDto containing new JWT tokens
     * 
     * HTTP Status Codes:
     * - 200 OK: Token refresh successful
     * - 401 UNAUTHORIZED: Invalid or expired refresh token
     * - 400 BAD REQUEST: Malformed request data
     * - 500 INTERNAL SERVER ERROR: Unexpected server errors
     * 
     * Security features:
     * - Refresh token signature and expiration validation
     * - Token type verification (must be refresh token)
     * - User existence verification
     * - Failed refresh attempts are logged for monitoring
     * - New refresh token issued to prevent token reuse
     * 
     * Usage flow:
     * 1. Client detects access token is expired or about to expire
     * 2. Client sends refresh token to this endpoint
     * 3. Server validates refresh token and generates new tokens
     * 4. Client receives new tokens and continues API usage
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refreshTokens(@Valid @RequestBody RefreshTokenRequestDto refreshTokenRequest) {
        log.info("Token refresh request received");
        
        try {
            // Delegate token refresh logic to service layer
            TokenResponseDto response = authenticationService.refreshTokens(refreshTokenRequest);
            
            log.info("Token refresh successful");
            
            // Return 200 OK with new JWT tokens and metadata
            return ResponseEntity.ok(response);
            
        } catch (IllegalArgumentException e) {
            // Handle refresh token validation failures
            log.warn("Token refresh failed: {}", e.getMessage());
            
            // Return error message for invalid or expired refresh token
            TokenResponseDto errorResponse = TokenResponseDto.builder()
                    .message(e.getMessage())
                    .build();
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            
        } catch (Exception e) {
            // Handle unexpected server errors
            log.error("Unexpected error during token refresh: {}", e.getMessage(), e);
            
            // Return generic error message to avoid exposing system details
            TokenResponseDto errorResponse = TokenResponseDto.builder()
                    .message("Token refresh failed due to a server error. Please try again later.")
                    .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Retrieves user profile information by user ID.
     * 
     * This endpoint provides access to non-sensitive user profile data
     * for authenticated users. It can be used for user profile displays,
     * user directory listings, and other profile-related functionality.
     * 
     * @param userId The unique identifier of the user
     * @return ResponseEntity with UserProfileDto containing profile information
     * 
     * HTTP Status Codes:
     * - 200 OK: Profile retrieved successfully
     * - 404 NOT FOUND: User not found
     * - 400 BAD REQUEST: Invalid user ID format
     * - 500 INTERNAL SERVER ERROR: Unexpected server errors
     * 
     * Future enhancements:
     * - Add authentication requirement for this endpoint
     * - Implement privacy controls for profile visibility
     * - Add caching for frequently accessed profiles
     */
    @GetMapping("/profile/{userId}")
    public ResponseEntity<?> getUserProfile(@PathVariable Long userId) {
        log.debug("User profile request for ID: {}", userId);
        
        try {
            // Validate user ID parameter
            if (userId == null || userId <= 0) {
                log.warn("Invalid user ID provided: {}", userId);
                
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("message", "Invalid user ID provided");
                
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            // Delegate profile retrieval to service layer
            UserProfileDto profile = authenticationService.getUserProfile(userId);
            
            log.debug("User profile retrieved successfully for ID: {}", userId);
            
            // Return profile data with 200 OK status
            return ResponseEntity.ok(profile);
            
        } catch (IllegalArgumentException e) {
            // Handle user not found scenarios
            log.warn("User profile request failed for ID {}: {}", userId, e.getMessage());
            
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "User not found");
            
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
            
        } catch (Exception e) {
            // Handle unexpected server errors
            log.error("Unexpected error during profile retrieval for user ID {}: {}", 
                     userId, e.getMessage(), e);
            
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Profile retrieval failed due to a server error");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Checks if an email address is available for registration.
     * 
     * This endpoint provides real-time email availability checking for
     * user registration forms, improving user experience by providing
     * immediate feedback on email availability.
     * 
     * @param email The email address to check for availability
     * @return ResponseEntity with availability status
     * 
     * HTTP Status Codes:
     * - 200 OK: Check completed successfully
     * - 400 BAD REQUEST: Invalid email format
     * - 500 INTERNAL SERVER ERROR: Unexpected server errors
     * 
     * Response format:
     * - available: boolean indicating if email is available
     * - message: descriptive message about availability status
     * 
     * Usage scenarios:
     * - Real-time validation in registration forms
     * - Email suggestion systems
     * - User experience improvements
     */
    @GetMapping("/check-email")
    public ResponseEntity<Map<String, Object>> checkEmailAvailability(@RequestParam String email) {
        log.debug("Email availability check for: {}", email);
        
        try {
            // Validate email parameter
            if (email == null || email.trim().isEmpty()) {
                log.warn("Empty email provided for availability check");
                
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("available", false);
                errorResponse.put("message", "Email parameter is required");
                
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            // Check email availability through service layer
            boolean isAvailable = authenticationService.isEmailAvailable(email);
            
            // Build response with availability status
            Map<String, Object> response = new HashMap<>();
            response.put("available", isAvailable);
            response.put("message", isAvailable ? 
                "Email is available for registration" : 
                "Email is already registered");
            
            log.debug("Email availability check completed for {}: {}", email, isAvailable);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            // Handle unexpected server errors
            log.error("Unexpected error during email availability check for {}: {}", 
                     email, e.getMessage(), e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("available", false);
            errorResponse.put("message", "Email availability check failed due to a server error");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
}
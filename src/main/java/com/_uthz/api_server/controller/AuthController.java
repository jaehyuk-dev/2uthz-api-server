package com._uthz.api_server.controller;

import com._uthz.api_server.dto.*;
import com._uthz.api_server.service.AuthenticationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(
    name = "Authentication", 
    description = """
        Authentication and user management endpoints for the 2uthz API.
        
        This controller provides comprehensive user authentication functionality including:
        - User registration with immediate JWT token issuance
        - User login with credential validation and token generation
        - JWT token refresh for maintaining authenticated sessions
        - User profile retrieval for authenticated users
        - Email availability checking for registration validation
        
        **Authentication Flow:**
        1. Register a new account or login with existing credentials
        2. Receive JWT access and refresh tokens in the response
        3. Include access token in Authorization header for protected endpoints
        4. Refresh tokens before expiration using the refresh endpoint
        
        **Security Features:**
        - BCrypt password encryption for secure credential storage
        - JWT-based stateless authentication with configurable expiration
        - Separate access and refresh tokens for enhanced security
        - Comprehensive input validation and error handling
        - Rate limiting and security monitoring (recommended for production)
        """
)
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
    @Operation(
        summary = "Register a new user account",
        description = """
            Creates a new user account and immediately issues JWT tokens for authentication.
            
            **Registration Process:**
            1. Validates email format and uniqueness
            2. Encrypts password using BCrypt
            3. Creates user account in database
            4. Generates JWT access and refresh tokens
            5. Returns tokens for immediate API access
            
            **Security Features:**
            - Email uniqueness validation prevents duplicate accounts
            - Password is encrypted with BCrypt before storage
            - JWT tokens enable stateless authentication
            - Input validation prevents malformed data
            
            **Post-Registration:**
            - Use the returned access token for API authentication
            - Store refresh token securely for token renewal
            - Include access token in Authorization header: `Bearer {token}`
            
            **Token Information:**
            - Access Token: Valid for 24 hours, used for API calls
            - Refresh Token: Valid for 7 days, used only for token refresh
            """,
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "201",
            description = "User successfully registered and tokens issued",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Successful Registration",
                    summary = "Example of successful user registration response",
                    value = """
                        {
                          "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsIm5pY2tuYW1lIjoiSm9obiBEb2UiLCJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjg5NzY0ODAwLCJleHAiOjE2ODk4NTEyMDB9.signature",
                          "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidHlwZSI6InJlZnJlc2giLCJpYXQiOjE2ODk3NjQ4MDAsImV4cCI6MTY5MDM2OTYwMH0.signature",
                          "tokenType": "Bearer",
                          "expiresIn": 86400,
                          "issuedAt": "2024-07-19T10:00:00",
                          "message": "Registration successful! Welcome to the platform."
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Registration failed due to validation errors or email already exists",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = {
                    @ExampleObject(
                        name = "Email Already Exists",
                        summary = "Error when email is already registered",
                        value = """
                            {
                              "accessToken": null,
                              "refreshToken": null,
                              "tokenType": null,
                              "expiresIn": null,
                              "issuedAt": null,
                              "message": "Email already exists. Please use a different email address."
                            }
                            """
                    ),
                    @ExampleObject(
                        name = "Validation Error",
                        summary = "Error when input validation fails",
                        value = """
                            {
                              "accessToken": null,
                              "refreshToken": null,
                              "tokenType": null,
                              "expiresIn": null,
                              "issuedAt": null,
                              "message": "Email must be a valid email address"
                            }
                            """
                    )
                }
            )
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error during registration",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Server Error",
                    summary = "Example of server error response",
                    value = """
                        {
                          "accessToken": null,
                          "refreshToken": null,
                          "tokenType": null,
                          "expiresIn": null,
                          "issuedAt": null,
                          "message": "Registration failed due to a server error. Please try again later."
                        }
                        """
                )
            )
        )
    })
    @SecurityRequirement(name = "") // Override global security requirement - this endpoint is public
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
    @Operation(
        summary = "Authenticate user and issue JWT tokens",
        description = """
            Validates user credentials and issues JWT tokens for API authentication.
            
            **Authentication Process:**
            1. Validates email format and existence
            2. Verifies password using secure BCrypt comparison
            3. Generates new JWT access and refresh tokens
            4. Returns tokens with metadata for API access
            
            **Security Features:**
            - BCrypt password verification prevents rainbow table attacks
            - Failed attempts are logged for security monitoring
            - Generic error messages prevent user enumeration attacks
            - Stateless JWT tokens eliminate server-side session storage
            
            **Token Usage:**
            - Include access token in Authorization header: `Bearer {token}`
            - Use refresh token to obtain new tokens before expiration
            - Access tokens expire in 24 hours for enhanced security
            - Refresh tokens are valid for 7 days
            
            **Error Handling:**
            - Invalid credentials return generic error message
            - Multiple failed attempts should trigger rate limiting
            - All authentication failures are logged for monitoring
            """,
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Authentication successful and tokens issued",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Successful Login",
                    summary = "Example of successful authentication response",
                    value = """
                        {
                          "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsIm5pY2tuYW1lIjoiSm9obiBEb2UiLCJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjg5NzY0ODAwLCJleHAiOjE2ODk4NTEyMDB9.signature",
                          "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidHlwZSI6InJlZnJlc2giLCJpYXQiOjE2ODk3NjQ4MDAsImV4cCI6MTY5MDM2OTYwMH0.signature",
                          "tokenType": "Bearer",
                          "expiresIn": 86400,
                          "issuedAt": "2024-07-19T10:00:00",
                          "message": "Login successful! Welcome back."
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication failed due to invalid credentials",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Invalid Credentials",
                    summary = "Error when email or password is incorrect",
                    value = """
                        {
                          "accessToken": null,
                          "refreshToken": null,
                          "tokenType": null,
                          "expiresIn": null,
                          "issuedAt": null,
                          "message": "Invalid email or password"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Request validation failed",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Validation Error",
                    summary = "Error when request format is invalid",
                    value = """
                        {
                          "accessToken": null,
                          "refreshToken": null,
                          "tokenType": null,
                          "expiresIn": null,
                          "issuedAt": null,
                          "message": "Email must be a valid email address"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error during authentication",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Server Error",
                    summary = "Example of server error response",
                    value = """
                        {
                          "accessToken": null,
                          "refreshToken": null,
                          "tokenType": null,
                          "expiresIn": null,
                          "issuedAt": null,
                          "message": "Login failed due to a server error. Please try again later."
                        }
                        """
                )
            )
        )
    })
    @SecurityRequirement(name = "") // Override global security requirement - this endpoint is public
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
    @Operation(
        summary = "Refresh JWT tokens using refresh token",
        description = """
            Issues new JWT tokens using a valid refresh token, enabling session continuation without re-authentication.
            
            **Token Refresh Process:**
            1. Validates refresh token signature and expiration
            2. Verifies token type (must be refresh token, not access token)
            3. Extracts user ID and verifies user still exists
            4. Generates new access and refresh tokens
            5. Returns new token pair for continued API access
            
            **Security Features:**
            - Refresh token signature verification prevents tampering
            - Token type validation prevents access token misuse
            - User existence check ensures account is still active
            - New refresh token issued to prevent token reuse attacks
            - Failed attempts logged for security monitoring
            
            **When to Refresh:**
            - Before access token expires (proactive refresh)
            - When API returns 401 Unauthorized (reactive refresh)
            - Recommended: refresh when token has <30% lifespan remaining
            
            **Best Practices:**
            - Store refresh tokens securely (secure storage, not localStorage)
            - Invalidate refresh tokens on logout or security events
            - Monitor refresh token usage for suspicious activity
            - Implement token rotation for enhanced security
            """,
        tags = {"Authentication"}
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Token refresh successful and new tokens issued",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Successful Token Refresh",
                    summary = "Example of successful token refresh response",
                    value = """
                        {
                          "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsIm5pY2tuYW1lIjoiSm9obiBEb2UiLCJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjg5NzY0ODAwLCJleHAiOjE2ODk4NTEyMDB9.new_signature",
                          "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidHlwZSI6InJlZnJlc2giLCJpYXQiOjE2ODk3NjQ4MDAsImV4cCI6MTY5MDM2OTYwMH0.new_signature",
                          "tokenType": "Bearer",
                          "expiresIn": 86400,
                          "issuedAt": "2024-07-19T11:00:00",
                          "message": "Tokens refreshed successfully"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Token refresh failed due to invalid or expired refresh token",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = {
                    @ExampleObject(
                        name = "Invalid Refresh Token",
                        summary = "Error when refresh token is invalid or expired",
                        value = """
                            {
                              "accessToken": null,
                              "refreshToken": null,
                              "tokenType": null,
                              "expiresIn": null,
                              "issuedAt": null,
                              "message": "Invalid or expired refresh token"
                            }
                            """
                    ),
                    @ExampleObject(
                        name = "Wrong Token Type",
                        summary = "Error when access token is used instead of refresh token",
                        value = """
                            {
                              "accessToken": null,
                              "refreshToken": null,
                              "tokenType": null,
                              "expiresIn": null,
                              "issuedAt": null,
                              "message": "Invalid token type for refresh operation"
                            }
                            """
                    )
                }
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Request validation failed",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Missing Refresh Token",
                    summary = "Error when refresh token is missing from request",
                    value = """
                        {
                          "accessToken": null,
                          "refreshToken": null,
                          "tokenType": null,
                          "expiresIn": null,
                          "issuedAt": null,
                          "message": "Refresh token is required"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error during token refresh",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = TokenResponseDto.class),
                examples = @ExampleObject(
                    name = "Server Error",
                    summary = "Example of server error response",
                    value = """
                        {
                          "accessToken": null,
                          "refreshToken": null,
                          "tokenType": null,
                          "expiresIn": null,
                          "issuedAt": null,
                          "message": "Token refresh failed due to a server error. Please try again later."
                        }
                        """
                )
            )
        )
    })
    @SecurityRequirement(name = "") // Override global security requirement - this endpoint is public
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
    @Operation(
        summary = "Retrieve user profile information",
        description = """
            Retrieves non-sensitive user profile information by user ID.
            
            **Profile Information Included:**
            - User ID and email address
            - Display nickname
            - Account creation and last update timestamps
            - Public profile information
            
            **Security Notes:**
            - Sensitive information (passwords, tokens) are never included
            - This endpoint requires JWT authentication
            - Users can access any profile (privacy controls to be implemented)
            - Profile data is safe for public display
            
            **Use Cases:**
            - User profile page display
            - User directory listings
            - Public user information for comments/posts
            - Admin user management interfaces
            
            **Future Enhancements:**
            - Privacy controls for profile visibility
            - User relationship management (friends, blocked users)
            - Profile customization options
            - Caching for performance optimization
            """,
        tags = {"User Management"}
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "User profile retrieved successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = UserProfileDto.class),
                examples = @ExampleObject(
                    name = "User Profile",
                    summary = "Example of user profile response",
                    value = """
                        {
                          "userId": 1,
                          "email": "john.doe@example.com",
                          "nickname": "John Doe",
                          "createdAt": "2024-07-15T10:30:00",
                          "updatedAt": "2024-07-19T14:20:00"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "404",
            description = "User not found",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "User Not Found",
                    summary = "Error when user ID does not exist",
                    value = """
                        {
                          "message": "User not found"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid user ID format",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Invalid User ID",
                    summary = "Error when user ID is invalid",
                    value = """
                        {
                          "message": "Invalid user ID provided"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Authentication Required",
                    summary = "Error when no valid JWT token is provided",
                    value = """
                        {
                          "message": "Authentication required"
                        }
                        """
                )
            )
        )
    })
    public ResponseEntity<?> getUserProfile(
        @Parameter(
            description = "Unique identifier of the user whose profile to retrieve",
            example = "1",
            required = true
        )
        @PathVariable Long userId) {
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
    @Operation(
        summary = "Check email availability for registration",
        description = """
            Validates whether an email address is available for new user registration.
            
            **Availability Check Process:**
            1. Validates email format using standard email validation
            2. Checks database for existing users with the same email
            3. Returns availability status with descriptive message
            4. Provides immediate feedback for registration forms
            
            **Use Cases:**
            - Real-time email validation in registration forms
            - Preventing duplicate account creation attempts
            - Improving user experience with instant feedback
            - Email suggestion and alternative recommendations
            
            **Response Format:**
            - `available`: Boolean indicating if email can be used
            - `message`: User-friendly description of availability status
            
            **Integration Tips:**
            - Call this endpoint on email field blur/change events
            - Debounce requests to avoid excessive API calls
            - Use response to show green/red indicators in UI
            - Provide helpful messages for unavailable emails
            
            **Performance Notes:**
            - Lightweight query for fast response times
            - Consider rate limiting for abuse prevention
            - Cache results briefly to reduce database load
            """,
        tags = {"Validation"}
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Email availability check completed successfully",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Email Available",
                        summary = "Response when email is available for registration",
                        value = """
                            {
                              "available": true,
                              "message": "Email is available for registration"
                            }
                            """
                    ),
                    @ExampleObject(
                        name = "Email Unavailable",
                        summary = "Response when email is already registered",
                        value = """
                            {
                              "available": false,
                              "message": "Email is already registered"
                            }
                            """
                    )
                }
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid email format or missing email parameter",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Invalid Email",
                    summary = "Error when email format is invalid",
                    value = """
                        {
                          "available": false,
                          "message": "Email parameter is required"
                        }
                        """
                )
            )
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error during email check",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Server Error",
                    summary = "Error during email availability check",
                    value = """
                        {
                          "available": false,
                          "message": "Email availability check failed due to a server error"
                        }
                        """
                )
            )
        )
    })
    @SecurityRequirement(name = "") // Override global security requirement - this endpoint is public
    public ResponseEntity<Map<String, Object>> checkEmailAvailability(
        @Parameter(
            description = "Email address to check for availability",
            example = "newuser@example.com",
            required = true
        )
        @RequestParam String email) {
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
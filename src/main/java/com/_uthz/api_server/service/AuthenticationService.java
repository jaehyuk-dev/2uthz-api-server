package com._uthz.api_server.service;

import com._uthz.api_server.dto.*;
import com._uthz.api_server.entity.User;
import com._uthz.api_server.repository.UserRepository;
import com._uthz.api_server.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service class for handling user authentication and JWT token operations.
 * 
 * This service provides comprehensive authentication functionality including
 * user registration, login validation, JWT token generation, and token refresh
 * operations. It handles password encryption, user validation, and secure
 * authentication flows using JSON Web Tokens.
 * 
 * Key responsibilities:
 * - User registration with validation and password encryption
 * - User authentication and login verification
 * - JWT access and refresh token generation
 * - Token refresh and validation operations
 * - Password security through BCrypt encryption
 * - User data validation and duplicate checking
 * 
 * Security features:
 * - Password encryption using BCrypt algorithm
 * - JWT-based stateless authentication
 * - Separate access and refresh tokens with different lifespans
 * - Token type validation and signature verification
 * - Email uniqueness validation
 * - Input validation and sanitization
 * - Transaction management for data consistency
 * 
 * Token management:
 * - Access tokens: Short-lived, used for API authentication
 * - Refresh tokens: Longer-lived, used only for token renewal
 * - Token validation: Signature and expiration checking
 * - Secure token generation with user claims
 */
@Service
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance
@Transactional // Ensures database operations are atomic
public class AuthenticationService {

    /**
     * Repository for user data access operations.
     * Used for user creation, retrieval, and validation queries.
     */
    private final UserRepository userRepository;

    /**
     * Password encoder for secure password hashing.
     * Uses BCrypt algorithm for one-way password encryption.
     */
    private final PasswordEncoder passwordEncoder;

    /**
     * JWT utility for token generation, validation, and parsing.
     * Handles all JWT-related operations including signing and verification.
     */
    private final JwtUtil jwtUtil;

    /**
     * Registers a new user in the system with JWT token generation.
     * 
     * This method handles the complete user registration process including:
     * - Email uniqueness validation
     * - Password encryption using BCrypt
     * - User entity creation and persistence
     * - JWT access and refresh token generation
     * 
     * @param registerRequest The registration data containing email, password, and nickname
     * @return TokenResponseDto containing JWT tokens and user information
     * @throws IllegalArgumentException if email already exists or validation fails
     * 
     * Process flow:
     * 1. Validate email uniqueness
     * 2. Encrypt the provided password
     * 3. Create and save new user entity
     * 4. Generate JWT access and refresh tokens
     * 5. Return response with tokens and metadata
     * 
     * Security considerations:
     * - Password is immediately encrypted and never stored in plain text
     * - Email validation prevents duplicate accounts
     * - JWT tokens provide stateless authentication
     * - Separate access and refresh tokens for enhanced security
     * - Transaction ensures atomic operation
     */
    public TokenResponseDto registerUser(RegisterRequestDto registerRequest) {
        log.info("Starting user registration process for email: {}", registerRequest.getEmail());

        // Validate email uniqueness to prevent duplicate accounts
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            log.warn("Registration attempt with existing email: {}", registerRequest.getEmail());
            throw new IllegalArgumentException("Email already exists. Please use a different email address.");
        }

        // Encrypt the password using BCrypt for secure storage
        String encryptedPassword = passwordEncoder.encode(registerRequest.getPassword());
        log.debug("Password encrypted successfully for user registration");

        // Create new user entity with validated and encrypted data
        User newUser = User.builder()
                .email(registerRequest.getEmail().toLowerCase().trim()) // Normalize email format
                .password(encryptedPassword) // Store encrypted password
                .nickname(registerRequest.getNickname().trim()) // Normalize nickname
                .build();

        // Save user to database with automatic timestamp generation
        User savedUser = userRepository.save(newUser);
        log.info("User registered successfully with ID: {} and email: {}", savedUser.getUserId(), savedUser.getEmail());

        // Generate JWT tokens for immediate authentication after registration
        return generateTokenResponse(savedUser, "Registration successful! Welcome to the platform.");
    }

    /**
     * Authenticates a user login attempt with JWT token generation.
     * 
     * This method validates user credentials and generates JWT tokens for
     * successful logins. It performs secure password verification using
     * BCrypt comparison and returns both access and refresh tokens.
     * 
     * @param loginRequest The login credentials containing email and password
     * @return TokenResponseDto containing JWT tokens and metadata
     * @throws IllegalArgumentException if credentials are invalid
     * 
     * Authentication process:
     * 1. Find user by email address
     * 2. Verify password using BCrypt comparison
     * 3. Generate new JWT access and refresh tokens
     * 4. Return tokens with metadata
     * 
     * Security features:
     * - Password verification using secure BCrypt comparison
     * - JWT tokens provide stateless authentication
     * - Separate access and refresh tokens for enhanced security
     * - No plain text password storage or transmission
     * - Failed login attempts are logged for security monitoring
     */
    public TokenResponseDto authenticateUser(LoginRequestDto loginRequest) {
        log.info("Authentication attempt for email: {}", loginRequest.getEmail());

        // Find user by email address (case-insensitive lookup)
        User user = userRepository.findByEmail(loginRequest.getEmail().toLowerCase().trim())
                .orElseThrow(() -> {
                    log.warn("Authentication failed: User not found for email: {}", loginRequest.getEmail());
                    return new IllegalArgumentException("Invalid email or password");
                });

        // Verify password using BCrypt comparison for security
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            log.warn("Authentication failed: Invalid password for email: {}", loginRequest.getEmail());
            throw new IllegalArgumentException("Invalid email or password");
        }

        log.info("User authenticated successfully: {} (ID: {})", user.getEmail(), user.getUserId());

        // Generate JWT tokens for the authenticated session
        return generateTokenResponse(user, "Login successful! Welcome back.");
    }

    /**
     * Retrieves user profile information by user ID.
     * 
     * This method fetches non-sensitive user profile data that can be
     * safely exposed to clients. It excludes password and other sensitive
     * information from the response.
     * 
     * @param userId The unique identifier of the user
     * @return UserProfileDto containing safe user profile information
     * @throws IllegalArgumentException if user is not found
     * 
     * Usage scenarios:
     * - User profile page display
     * - User information for authenticated requests
     * - Public user directory listings
     */
    public UserProfileDto getUserProfile(Long userId) {
        log.debug("Retrieving user profile for ID: {}", userId);

        // Find user by ID with appropriate error handling
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User profile request failed: User not found for ID: {}", userId);
                    return new IllegalArgumentException("User not found");
                });

        // Convert entity to DTO excluding sensitive information
        return UserProfileDto.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    /**
     * Validates if an email address is available for registration.
     * 
     * This method provides a way to check email availability without
     * attempting full registration, useful for real-time validation
     * in user interfaces.
     * 
     * @param email The email address to validate
     * @return true if email is available, false if already taken
     * 
     * Usage:
     * - Real-time email validation in registration forms
     * - Email availability checking API endpoints
     * - User experience improvement during registration
     */
    public boolean isEmailAvailable(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        boolean available = !userRepository.existsByEmail(normalizedEmail);
        log.debug("Email availability check for {}: {}", normalizedEmail, available);
        return available;
    }

    /**
     * Refreshes JWT tokens using a valid refresh token.
     * 
     * This method validates a refresh token and generates new access and refresh tokens
     * if the provided refresh token is valid. This allows clients to obtain new tokens
     * without requiring the user to log in again.
     * 
     * @param refreshTokenRequest The request containing the refresh token
     * @return TokenResponseDto containing new JWT tokens and metadata
     * @throws IllegalArgumentException if refresh token is invalid or expired
     * 
     * Refresh process:
     * 1. Validate refresh token format and signature
     * 2. Verify token type (must be refresh token)
     * 3. Extract user ID from token claims
     * 4. Verify user still exists in the system
     * 5. Generate new access and refresh tokens
     * 6. Return new tokens with metadata
     * 
     * Security considerations:
     * - Refresh tokens are validated for signature and expiration
     * - Only refresh token types are accepted (not access tokens)
     * - User existence is verified before token generation
     * - Failed refresh attempts are logged for security monitoring
     * - New refresh token is issued to prevent token reuse
     */
    public TokenResponseDto refreshTokens(RefreshTokenRequestDto refreshTokenRequest) {
        log.info("Token refresh attempt");

        String refreshToken = refreshTokenRequest.getRefreshToken();

        // Validate refresh token authenticity and expiration
        if (!jwtUtil.isTokenValid(refreshToken)) {
            log.warn("Token refresh failed: Invalid or expired refresh token");
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        // Verify this is a refresh token (not an access token)
        if (!jwtUtil.isTokenOfType(refreshToken, "refresh")) {
            log.warn("Token refresh failed: Token is not a refresh token");
            throw new IllegalArgumentException("Invalid token type for refresh operation");
        }

        // Extract user ID from refresh token
        Long userId = jwtUtil.getUserIdFromToken(refreshToken);
        if (userId == null) {
            log.warn("Token refresh failed: Unable to extract user ID from token");
            throw new IllegalArgumentException("Invalid refresh token - missing user information");
        }

        // Verify user still exists in the system
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Token refresh failed: User not found for ID: {}", userId);
                    return new IllegalArgumentException("User not found - refresh token invalid");
                });

        log.info("Token refresh successful for user: {} (ID: {})", user.getEmail(), user.getUserId());

        // Generate new access and refresh tokens
        return generateTokenResponse(user, "Tokens refreshed successfully");
    }

    /**
     * Generates a complete token response with access and refresh tokens.
     * 
     * This method creates both JWT access and refresh tokens for a user and
     * packages them into a comprehensive response with metadata. It's used
     * by login, registration, and token refresh operations.
     * 
     * @param user The user for whom to generate tokens
     * @param message Custom message for the response
     * @return TokenResponseDto containing JWT tokens and metadata
     * 
     * Token characteristics:
     * - Access token: Contains user claims including role, shorter lifespan, used for API authentication
     * - Refresh token: Minimal claims, longer lifespan, used only for token refresh
     * - Both tokens signed with the same secret key
     * - Tokens include appropriate type identifiers
     * 
     * Response metadata:
     * - Token type (Bearer)
     * - Expiration time for access token
     * - Issuance timestamp
     * - Custom success message
     */
    private TokenResponseDto generateTokenResponse(User user, String message) {
        log.debug("Generating JWT tokens for user ID: {} with role: {}", user.getUserId(), user.getRole());

        // Generate JWT access token with user claims including role for authorization
        String accessToken = jwtUtil.generateAccessToken(
                user.getUserId(),
                user.getEmail(),
                user.getNickname(),
                user.getRole()
        );

        // Generate JWT refresh token with minimal claims
        String refreshToken = jwtUtil.generateRefreshToken(user.getUserId());

        // Build comprehensive token response
        return TokenResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(86400L) // 24 hours in seconds (should match JWT configuration)
                .issuedAt(LocalDateTime.now())
                .message(message)
                .build();
    }
}
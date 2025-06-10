package com._uthz.api_server.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Utility class for JWT (JSON Web Token) operations.
 * 
 * This utility provides comprehensive JWT functionality including token generation,
 * validation, parsing, and claims extraction. It handles both access tokens and
 * refresh tokens with different expiration times and purposes.
 * 
 * Key responsibilities:
 * - Generate secure JWT access and refresh tokens
 * - Validate token signatures and expiration
 * - Extract user information from token claims
 * - Handle token parsing errors gracefully
 * - Provide token metadata and validation status
 * 
 * Security features:
 * - Uses HMAC-SHA256 algorithm for token signing
 * - Configurable secret key for token security
 * - Different expiration times for access vs refresh tokens
 * - Comprehensive error handling for invalid tokens
 * - Subject validation for token authenticity
 * 
 * Token structure:
 * - Header: Algorithm and token type
 * - Payload: User claims (userId, email, nickname) and metadata
 * - Signature: HMAC-SHA256 signature for verification
 */
@Component
@Slf4j // Lombok: provides logger instance
public class JwtUtil {

    /**
     * Secret key for JWT token signing and validation.
     * This key is used to create and verify the digital signature of tokens.
     * Should be a strong, randomly generated secret in production.
     */
    @Value("${jwt.secret:mySecretKey123456789012345678901234567890}")
    private String jwtSecret;

    /**
     * Access token expiration time in milliseconds.
     * Default: 24 hours (86400000 ms)
     * Access tokens should have shorter lifespans for security.
     */
    @Value("${jwt.access.expiration:86400000}")
    private long accessTokenExpiration;

    /**
     * Refresh token expiration time in milliseconds.
     * Default: 7 days (604800000 ms)
     * Refresh tokens can have longer lifespans since they're used less frequently.
     */
    @Value("${jwt.refresh.expiration:604800000}")
    private long refreshTokenExpiration;

    /**
     * Gets the secret key for JWT operations.
     * 
     * This method creates a SecretKey instance from the configured secret string.
     * The key is used for both signing tokens during generation and verifying
     * signatures during validation.
     * 
     * Security considerations:
     * - The secret should be at least 256 bits for HMAC-SHA256
     * - Should be stored securely and not hardcoded in production
     * - Different environments should use different secrets
     * 
     * @return SecretKey instance for JWT operations
     */
    private SecretKey getSigningKey() {
        // Convert the secret string to bytes and create HMAC key
        // Keys.hmacShaKeyFor() ensures the key meets HMAC-SHA256 requirements
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    /**
     * Generates a JWT access token for authenticated user sessions.
     * 
     * Access tokens are short-lived tokens used for authenticating API requests.
     * They contain user identity information and have limited validity to
     * minimize security risks if compromised.
     * 
     * @param userId The unique identifier of the user
     * @param email The user's email address (username)
     * @param nickname The user's display nickname
     * @param role The user's role for authorization purposes
     * @return String containing the signed JWT access token
     * 
     * Token claims include:
     * - sub (subject): User ID for token identification
     * - email: User's email address
     * - nickname: User's display name
     * - role: User's role for authorization
     * - iat (issued at): Token creation timestamp
     * - exp (expiration): Token expiry timestamp
     * - type: Token type identifier ("access")
     * 
     * Usage:
     * - Include in Authorization header as "Bearer {token}"
     * - Used for authenticating protected API endpoints
     * - Should be refreshed before expiration using refresh token
     */
    public String generateAccessToken(Long userId, String email, String nickname, String role) {
        log.debug("Generating access token for user ID: {}", userId);

        // Create claims map with user information
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("nickname", nickname);
        claims.put("role", role);
        claims.put("type", "access"); // Token type identifier

        // Build and sign the JWT token
        String token = Jwts.builder()
                .setClaims(claims) // Add user information to token payload
                .setSubject(userId.toString()) // Set user ID as token subject
                .setIssuedAt(new Date()) // Set token creation time
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration)) // Set expiration
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Sign with HMAC-SHA256
                .compact(); // Build the final token string

        log.debug("Access token generated successfully for user ID: {}", userId);
        return token;
    }

    /**
     * Generates a JWT access token for authenticated user sessions (with default role).
     * 
     * This is an overloaded method that provides backward compatibility
     * for existing code that doesn't specify a role. It defaults to "USER" role.
     * 
     * @param userId The unique identifier of the user
     * @param email The user's email address (username)
     * @param nickname The user's display nickname
     * @return String containing the signed JWT access token with default "USER" role
     */
    public String generateAccessToken(Long userId, String email, String nickname) {
        return generateAccessToken(userId, email, nickname, "USER");
    }

    /**
     * Generates a JWT refresh token for token renewal operations.
     * 
     * Refresh tokens are longer-lived tokens used exclusively for obtaining
     * new access tokens. They don't contain detailed user information and
     * should only be used for the refresh endpoint.
     * 
     * @param userId The unique identifier of the user
     * @return String containing the signed JWT refresh token
     * 
     * Token claims include:
     * - sub (subject): User ID for token identification
     * - iat (issued at): Token creation timestamp
     * - exp (expiration): Token expiry timestamp
     * - type: Token type identifier ("refresh")
     * 
     * Security considerations:
     * - Longer expiration time but more restricted usage
     * - Should be stored securely by client applications
     * - Used only for obtaining new access tokens
     * - Should be invalidated when user logs out
     */
    public String generateRefreshToken(Long userId) {
        log.debug("Generating refresh token for user ID: {}", userId);

        // Create minimal claims for refresh token
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh"); // Token type identifier

        // Build and sign the refresh token
        String token = Jwts.builder()
                .setClaims(claims) // Minimal claims for refresh token
                .setSubject(userId.toString()) // Set user ID as token subject
                .setIssuedAt(new Date()) // Set token creation time
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration)) // Set expiration
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Sign with HMAC-SHA256
                .compact(); // Build the final token string

        log.debug("Refresh token generated successfully for user ID: {}", userId);
        return token;
    }

    /**
     * Extracts the user ID from a JWT token.
     * 
     * This method parses the token and retrieves the user ID from the
     * token's subject claim. It's commonly used for identifying the
     * authenticated user in API requests.
     * 
     * @param token The JWT token to parse
     * @return Long containing the user ID, or null if token is invalid
     * 
     * Usage scenarios:
     * - Identifying the current user in protected endpoints
     * - Validating token ownership for user-specific operations
     * - Logging and auditing user actions
     * 
     * Error handling:
     * - Returns null if token is malformed or invalid
     * - Logs appropriate error messages for debugging
     * - Graceful degradation for authentication failures
     */
    public Long getUserIdFromToken(String token) {
        try {
            String subject = getClaimFromToken(token, Claims::getSubject);
            return subject != null ? Long.valueOf(subject) : null;
        } catch (NumberFormatException e) {
            log.warn("Invalid user ID format in token: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            log.warn("Error extracting user ID from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the email address from a JWT token.
     * 
     * This method retrieves the user's email from the token claims.
     * The email is stored as a custom claim in access tokens.
     * 
     * @param token The JWT token to parse
     * @return String containing the email address, or null if not present
     * 
     * Note: Refresh tokens don't contain email claims, so this method
     * will return null for refresh tokens.
     */
    public String getEmailFromToken(String token) {
        try {
            return getClaimFromToken(token, claims -> claims.get("email", String.class));
        } catch (Exception e) {
            log.warn("Error extracting email from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the nickname from a JWT token.
     * 
     * This method retrieves the user's display nickname from the token claims.
     * The nickname is stored as a custom claim in access tokens.
     * 
     * @param token The JWT token to parse
     * @return String containing the nickname, or null if not present
     * 
     * Note: Refresh tokens don't contain nickname claims, so this method
     * will return null for refresh tokens.
     */
    public String getNicknameFromToken(String token) {
        try {
            return getClaimFromToken(token, claims -> claims.get("nickname", String.class));
        } catch (Exception e) {
            log.warn("Error extracting nickname from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the role from a JWT token.
     * 
     * This method retrieves the user's role from the token claims.
     * The role is stored as a custom claim in access tokens and is used
     * for authorization and access control purposes.
     * 
     * @param token The JWT token to parse
     * @return String containing the user's role, or null if not present
     * 
     * Common roles:
     * - "USER": Standard user with basic permissions
     * - "ADMIN": Administrative user with elevated privileges
     * - "MODERATOR": User with content moderation capabilities
     * 
     * Note: Refresh tokens don't contain role claims, so this method
     * will return null for refresh tokens. Role information is only
     * included in access tokens for security purposes.
     */
    public String getRoleFromToken(String token) {
        try {
            return getClaimFromToken(token, claims -> claims.get("role", String.class));
        } catch (Exception e) {
            log.warn("Error extracting role from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the token type from a JWT token.
     * 
     * This method determines whether a token is an access token or refresh token
     * by examining the 'type' claim. This is useful for validating that the
     * correct token type is being used for specific operations.
     * 
     * @param token The JWT token to parse
     * @return String containing the token type ("access" or "refresh"), or null if not present
     * 
     * Usage:
     * - Validating that access tokens are used for API requests
     * - Ensuring refresh tokens are only used for token refresh operations
     * - Security checks to prevent token misuse
     */
    public String getTokenTypeFromToken(String token) {
        try {
            return getClaimFromToken(token, claims -> claims.get("type", String.class));
        } catch (Exception e) {
            log.warn("Error extracting token type from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the expiration date from a JWT token.
     * 
     * This method retrieves when the token will expire, which is useful
     * for determining if a token needs to be refreshed soon.
     * 
     * @param token The JWT token to parse
     * @return Date representing when the token expires, or null if invalid
     * 
     * Usage:
     * - Checking if token is close to expiration
     * - Proactive token refresh before expiration
     * - Token lifetime analytics and monitoring
     */
    public Date getExpirationDateFromToken(String token) {
        try {
            return getClaimFromToken(token, Claims::getExpiration);
        } catch (Exception e) {
            log.warn("Error extracting expiration date from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Generic method to extract any claim from a JWT token.
     * 
     * This utility method provides a flexible way to extract any claim
     * from a token using a function resolver. It handles token parsing
     * and signature validation automatically.
     * 
     * @param token The JWT token to parse
     * @param claimsResolver Function to extract specific claim from Claims object
     * @param <T> The type of the claim value
     * @return The extracted claim value, or null if token is invalid
     * 
     * Security features:
     * - Validates token signature before extracting claims
     * - Handles expired tokens gracefully
     * - Logs security-relevant parsing errors
     * 
     * Usage examples:
     * - String subject = getClaimFromToken(token, Claims::getSubject);
     * - Date expiration = getClaimFromToken(token, Claims::getExpiration);
     * - String customClaim = getClaimFromToken(token, claims -> claims.get("custom", String.class));
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = getAllClaimsFromToken(token);
            return claimsResolver.apply(claims);
        } catch (ExpiredJwtException e) {
            log.warn("Token has expired: {}", e.getMessage());
            return null;
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
            return null;
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token: {}", e.getMessage());
            return null;
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature: {}", e.getMessage());
            return null;
        } catch (IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            log.error("Unexpected error parsing JWT token: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Extracts all claims from a JWT token.
     * 
     * This method parses the token and returns all claims contained within it.
     * It validates the token signature and ensures the token is not expired
     * before returning the claims.
     * 
     * @param token The JWT token to parse
     * @return Claims object containing all token claims
     * @throws JwtException if token is invalid, expired, or malformed
     * 
     * Security validations performed:
     * - Signature verification using the secret key
     * - Expiration time validation
     * - Token format validation
     * - Algorithm validation (prevents algorithm substitution attacks)
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(getSigningKey()) // Set the key for signature verification
                .build()
                .parseClaimsJws(token) // Parse and validate the token
                .getBody(); // Return the claims payload
    }

    /**
     * Validates if a JWT token is valid and not expired.
     * 
     * This method performs comprehensive token validation including
     * signature verification, expiration checking, and basic format validation.
     * It's the primary method for determining if a token can be trusted.
     * 
     * @param token The JWT token to validate
     * @return true if token is valid and not expired, false otherwise
     * 
     * Validation checks performed:
     * - Token format and structure validation
     * - Signature verification against secret key
     * - Expiration time validation
     * - Algorithm validation
     * - Claims structure validation
     * 
     * Usage:
     * - Authentication filter validation
     * - API endpoint security checks
     * - Token refresh eligibility validation
     * 
     * Security considerations:
     * - Always validate tokens before trusting claims
     * - Log validation failures for security monitoring
     * - Handle validation errors gracefully
     */
    public boolean isTokenValid(String token) {
        try {
            // Attempt to parse the token - this validates signature and expiration
            getAllClaimsFromToken(token);
            log.debug("Token validation successful");
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Token validation failed: Token has expired");
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("Token validation failed: Unsupported JWT token");
            return false;
        } catch (MalformedJwtException e) {
            log.warn("Token validation failed: Malformed JWT token");
            return false;
        } catch (SignatureException e) {
            log.warn("Token validation failed: Invalid JWT signature");
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("Token validation failed: Invalid JWT token");
            return false;
        } catch (Exception e) {
            log.error("Token validation failed: Unexpected error: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Checks if a JWT token is expired.
     * 
     * This method specifically checks the token's expiration time
     * without performing full validation. It's useful for determining
     * if a token needs to be refreshed.
     * 
     * @param token The JWT token to check
     * @return true if token is expired, false if still valid
     * 
     * Usage scenarios:
     * - Proactive token refresh before expiration
     * - Client-side token lifecycle management
     * - Token cleanup and maintenance operations
     * 
     * Note: This method only checks expiration time. For full security
     * validation including signature verification, use isTokenValid().
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration != null && expiration.before(new Date());
        } catch (Exception e) {
            log.warn("Error checking token expiration: {}", e.getMessage());
            return true; // Treat parsing errors as expired tokens for security
        }
    }

    /**
     * Validates that a token is of the expected type.
     * 
     * This method checks the 'type' claim in the token to ensure
     * it matches the expected token type (access or refresh).
     * This prevents misuse of tokens for unintended purposes.
     * 
     * @param token The JWT token to validate
     * @param expectedType The expected token type ("access" or "refresh")
     * @return true if token type matches expected type, false otherwise
     * 
     * Security benefits:
     * - Prevents access tokens from being used for refresh operations
     * - Prevents refresh tokens from being used for API authentication
     * - Adds an additional layer of token validation
     * 
     * Usage:
     * - Authentication filter: validate access token type
     * - Refresh endpoint: validate refresh token type
     * - Security middleware: ensure correct token usage
     */
    public boolean isTokenOfType(String token, String expectedType) {
        try {
            String tokenType = getTokenTypeFromToken(token);
            boolean isCorrectType = expectedType.equals(tokenType);
            
            if (!isCorrectType) {
                log.warn("Token type mismatch. Expected: {}, Found: {}", expectedType, tokenType);
            }
            
            return isCorrectType;
        } catch (Exception e) {
            log.warn("Error validating token type: {}", e.getMessage());
            return false;
        }
    }
}
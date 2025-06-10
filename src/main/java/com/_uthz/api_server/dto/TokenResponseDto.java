package com._uthz.api_server.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Data Transfer Object for token-related responses.
 * 
 * This DTO encapsulates both access and refresh tokens along with metadata
 * about the token issuance. It's used for responses from login, registration,
 * and token refresh operations where new tokens are provided to the client.
 * 
 * Key features:
 * - Contains both access and refresh tokens
 * - Includes token metadata for client token management
 * - Provides expiration information for proactive refresh
 * - Standardized response format for all token operations
 * 
 * Security considerations:
 * - Contains sensitive authentication tokens
 * - Should be transmitted over HTTPS only
 * - Tokens should be stored securely by client applications
 * - Access tokens have shorter lifespan for enhanced security
 * - Refresh tokens have longer lifespan but limited usage scope
 * 
 * Client usage guidelines:
 * - Store both tokens securely (preferably in secure storage)
 * - Use access token for API authentication
 * - Use refresh token only for obtaining new access tokens
 * - Monitor expiration times for proactive token refresh
 * - Clear tokens on logout or security events
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON serialization
@AllArgsConstructor // Lombok: generates constructor with all fields
@Schema(
    name = "TokenResponse",
    description = "Response containing JWT access and refresh tokens with metadata"
)
public class TokenResponseDto {

    /**
     * JWT access token for API authentication.
     * 
     * This token should be included in the Authorization header of API requests
     * using the Bearer token format. It contains user identity information and
     * has a relatively short lifespan for security purposes.
     * 
     * Usage:
     * - Include in Authorization header: "Bearer {accessToken}"
     * - Used for all authenticated API requests
     * - Contains user claims (ID, email, nickname)
     * - Has shorter expiration time (typically hours)
     * 
     * Security notes:
     * - Should be transmitted over HTTPS only
     * - Store securely in client application
     * - Refresh before expiration using refresh token
     * - Clear on logout or security events
     */
    @Schema(
        description = "JWT access token for API authentication (include in Authorization header as 'Bearer {token}')",
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsIm5pY2tuYW1lIjoiSm9obiBEb2UiLCJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjg5NzY0ODAwLCJleHAiOjE2ODk4NTEyMDB9.signature"
    )
    private String accessToken;

    /**
     * JWT refresh token for obtaining new access tokens.
     * 
     * This token is used exclusively for refreshing expired access tokens
     * without requiring the user to log in again. It has a longer lifespan
     * than access tokens but more limited functionality.
     * 
     * Usage:
     * - Send to /api/auth/refresh endpoint when access token expires
     * - Store securely alongside access token
     * - Has longer expiration time (typically days or weeks)
     * - Cannot be used for API authentication
     * 
     * Security notes:
     * - More valuable than access tokens due to longer lifespan
     * - Should be stored in most secure available storage
     * - Invalidated on logout or password change
     * - Monitor for unauthorized usage
     */
    @Schema(
        description = "JWT refresh token for obtaining new access tokens (use only with /api/auth/refresh endpoint)",
        example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidHlwZSI6InJlZnJlc2giLCJpYXQiOjE2ODk3NjQ4MDAsImV4cCI6MTY5MDM2OTYwMH0.signature"
    )
    private String refreshToken;

    /**
     * Type of the access token (typically "Bearer").
     * 
     * This field indicates the token type for proper Authorization header formatting.
     * It helps clients understand how to include the token in API requests.
     * 
     * Standard value: "Bearer"
     * Usage: "Authorization: Bearer {accessToken}"
     */
    @Schema(
        description = "Token type for Authorization header formatting",
        example = "Bearer"
    )
    private String tokenType;

    /**
     * Access token expiration time in seconds.
     * 
     * This value indicates how long the access token will remain valid
     * from the time of issuance. Clients can use this to determine when
     * to refresh the token proactively.
     * 
     * Typical values:
     * - 3600 (1 hour)
     * - 86400 (24 hours)
     * - Custom based on security requirements
     * 
     * Client usage:
     * - Calculate absolute expiration time: issuedAt + expiresIn
     * - Set up proactive refresh before expiration
     * - Handle token expiration gracefully in API calls
     */
    @Schema(
        description = "Access token expiration time in seconds from issuance",
        example = "86400"
    )
    private Long expiresIn;

    /**
     * Timestamp when the tokens were issued.
     * 
     * This timestamp indicates when the tokens were created and can be used
     * by clients for token age calculations and cache management.
     * 
     * Usage:
     * - Token age calculation for security policies
     * - Cache invalidation strategies
     * - Audit logging and monitoring
     * - Absolute expiration time calculation
     */
    private LocalDateTime issuedAt;

    /**
     * Human-readable message about the token issuance.
     * 
     * This message provides additional context about the token operation
     * and can be displayed to users for feedback and confirmation.
     * 
     * Example messages:
     * - "Login successful - tokens issued"
     * - "Tokens refreshed successfully"
     * - "Registration complete - welcome aboard"
     * 
     * Usage:
     * - User feedback and notifications
     * - Success confirmations
     * - Operation status communication
     * - Client application messaging
     */
    private String message;
}
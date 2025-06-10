package com._uthz.api_server.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for refresh token requests.
 * 
 * This DTO encapsulates the refresh token required for obtaining new access tokens.
 * It's used when clients need to refresh their authentication without requiring
 * the user to log in again with their credentials.
 * 
 * Key features:
 * - Contains only the refresh token for security
 * - Validates token presence to prevent empty requests
 * - Used exclusively for token refresh operations
 * - Minimal data exposure for enhanced security
 * 
 * Security considerations:
 * - Only contains refresh token, no sensitive user data
 * - Refresh tokens should be transmitted over HTTPS only
 * - Refresh tokens have longer expiration but limited usage scope
 * - Failed refresh attempts should be logged for security monitoring
 * 
 * Usage flow:
 * 1. Client receives refresh token during login or previous refresh
 * 2. When access token expires, client sends refresh token
 * 3. Server validates refresh token and issues new access token
 * 4. Client continues API usage with new access token
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON deserialization
@AllArgsConstructor // Lombok: generates constructor with all fields
public class RefreshTokenRequestDto {

    /**
     * The refresh token used to obtain new access tokens.
     * 
     * This token is a JWT refresh token that was previously issued during
     * login or a previous token refresh operation. It has a longer lifespan
     * than access tokens but can only be used for token refresh purposes.
     * 
     * Security requirements:
     * - Must be a valid JWT with proper signature
     * - Must not be expired
     * - Must be of type "refresh" (not an access token)
     * - Should be transmitted over secure HTTPS connection
     * 
     * Validation constraints:
     * - Cannot be null, empty, or contain only whitespace
     * - Must be a properly formatted JWT token
     * 
     * Token characteristics:
     * - Longer expiration time (typically days or weeks)
     * - Limited scope - only for obtaining new access tokens
     * - Should be stored securely by client applications
     * - Invalidated when user logs out or changes password
     * 
     * Example usage:
     * POST /api/auth/refresh
     * {
     *   "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
     * }
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
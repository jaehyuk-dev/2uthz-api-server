package com._uthz.api_server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for authentication response data.
 * 
 * This DTO encapsulates the response data sent back to clients
 * after successful authentication operations (login/registration).
 * It contains user information and authentication tokens needed
 * for maintaining user sessions.
 * 
 * Key features:
 * - Contains non-sensitive user information for client use
 * - Excludes password and other sensitive data
 * - Provides authentication token for subsequent API calls
 * - Standardized response format for all auth operations
 * 
 * Security considerations:
 * - Never includes password or other sensitive credentials
 * - Contains only information safe to transmit to client
 * - Token should be used for authenticated API requests
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON serialization
@AllArgsConstructor // Lombok: generates constructor with all fields
public class AuthResponseDto {

    /**
     * Unique identifier for the authenticated user.
     * 
     * This ID can be used by the client for:
     * - User-specific API requests
     * - Caching user data on client side
     * - Linking user actions to specific accounts
     * 
     * The user ID is safe to expose as it's used for
     * identification purposes and doesn't contain sensitive information.
     */
    private Long userId;

    /**
     * User's email address (username).
     * 
     * Included in the response for:
     * - Display in user interface
     * - Account verification purposes
     * - User identification in client applications
     * 
     * Note: Email is not considered sensitive information
     * in this context as it's already known to the user
     * and is used for identification purposes.
     */
    private String email;

    /**
     * User's display nickname.
     * 
     * This friendly name is used by client applications for:
     * - Personalized user interface elements
     * - User profile displays
     * - Greeting messages and user identification
     * 
     * The nickname provides a user-friendly alternative
     * to displaying the email address in interfaces.
     */
    private String nickname;

    /**
     * Authentication token for subsequent API requests.
     * 
     * This token serves as proof of authentication and should be:
     * - Included in Authorization header for protected endpoints
     * - Stored securely on the client side
     * - Used for all authenticated API requests
     * - Treated as sensitive information by the client
     * 
     * Security notes:
     * - Token has limited lifespan for security
     * - Should be transmitted over HTTPS only
     * - Client should handle token expiration gracefully
     * - Token format and encryption handled by security layer
     * 
     * Example usage in subsequent requests:
     * Authorization: Bearer {token}
     */
    private String token;

    /**
     * Timestamp indicating when the authentication occurred.
     * 
     * This information can be used by clients for:
     * - Session tracking and analytics
     * - User activity monitoring
     * - Token age verification
     * - Audit logging purposes
     * 
     * The timestamp helps clients understand when the
     * authentication session was established.
     */
    private java.time.LocalDateTime authenticatedAt;

    /**
     * Message providing additional context about the authentication result.
     * 
     * This human-readable message can be used for:
     * - User notification and feedback
     * - Success confirmations
     * - Welcome messages for new registrations
     * - Status updates for returning users
     * 
     * Example messages:
     * - "Login successful"
     * - "Welcome! Your account has been created successfully"
     * - "Authentication completed"
     */
    private String message;
}
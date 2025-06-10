package com._uthz.api_server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Data Transfer Object for user profile information.
 * 
 * This DTO represents user profile data that can be safely exposed
 * to clients without revealing sensitive information. It's used for
 * user profile displays, user listings, and other public user information.
 * 
 * Key features:
 * - Contains only non-sensitive user information
 * - Excludes password and other private data
 * - Suitable for public user profiles and listings
 * - Includes metadata like creation timestamp
 * 
 * Security considerations:
 * - Never includes password or authentication credentials
 * - Contains only information appropriate for public display
 * - Can be safely cached and transmitted to any authenticated user
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON serialization
@AllArgsConstructor // Lombok: generates constructor with all fields
public class UserProfileDto {

    /**
     * Unique identifier for the user.
     * 
     * This ID is used for:
     * - Referencing users in API requests
     * - Linking user profiles to other entities
     * - Client-side user identification
     * 
     * The user ID is safe to expose as it's used for
     * identification and doesn't reveal sensitive information.
     */
    private Long userId;

    /**
     * User's email address.
     * 
     * Included in profile information for:
     * - User identification
     * - Contact information display
     * - Account verification status
     * 
     * Note: Email visibility may be controlled by privacy settings
     * in future implementations. Currently exposed for identification.
     */
    private String email;

    /**
     * User's display nickname.
     * 
     * This friendly name is the primary identifier shown in:
     * - User profiles and listings
     * - Comments and posts
     * - User mentions and references
     * - Application interfaces
     * 
     * The nickname provides a user-friendly way to identify
     * users without exposing their email addresses.
     */
    private String nickname;

    /**
     * User's role for authorization and access control.
     * 
     * This field indicates the user's permission level within the application
     * and is used for displaying role-specific UI elements and determining
     * what actions the user can perform.
     * 
     * Common roles:
     * - "USER": Standard user with basic permissions
     * - "ADMIN": Administrative user with elevated privileges
     * - "MODERATOR": User with content moderation capabilities
     * 
     * Usage in profiles:
     * - Display user badges or indicators based on role
     * - Show role-specific profile sections
     * - Enable role-based UI elements
     * - Provide role information for other users to see authority levels
     * 
     * Security note: Role information is safe to expose in profiles
     * as it helps users understand authority levels and is used for
     * client-side UI customization.
     */
    private String role;

    /**
     * Timestamp indicating when the user account was created.
     * 
     * This information is useful for:
     * - Displaying account age to users
     * - User engagement analytics
     * - Account verification and trust indicators
     * - Historical user data tracking
     * 
     * The creation timestamp helps establish user credibility
     * and provides context about account history.
     */
    private LocalDateTime createdAt;

    /**
     * Timestamp indicating when the user profile was last updated.
     * 
     * This metadata is valuable for:
     * - Cache invalidation strategies
     * - User activity tracking
     * - Profile freshness indicators
     * - Audit trails for profile changes
     * 
     * The update timestamp helps clients determine if
     * cached profile data needs to be refreshed.
     */
    private LocalDateTime updatedAt;
}
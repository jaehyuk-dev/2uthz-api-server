package com._uthz.api_server.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * User entity representing a registered user in the system.
 * 
 * This entity handles user authentication and basic profile information.
 * It stores essential user data including email (used as username), password,
 * and display nickname for the application.
 * 
 * Key features:
 * - Email serves as the unique identifier for authentication
 * - Password is stored in encrypted format (handled by service layer)
 * - Nickname provides a user-friendly display name
 * - Automatic timestamp tracking for creation and updates
 * 
 * Security considerations:
 * - Email must be unique to prevent duplicate accounts
 * - Password validation is enforced at service level
 * - Sensitive data should be excluded from serialization when needed
 */
@Entity
@Table(name = "users") // Using "users" table name to avoid conflicts with SQL reserved word "user"
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor (required by JPA)
@AllArgsConstructor // Lombok: generates constructor with all fields
public class User {

    /**
     * Primary key for the user entity.
     * Auto-generated using database identity strategy for optimal performance.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    /**
     * User's email address, serving as the unique username for authentication.
     * 
     * Constraints:
     * - Must be a valid email format
     * - Cannot be null or blank
     * - Must be unique across all users
     * - Maximum length of 100 characters to prevent abuse
     * 
     * This field is used for:
     * - User authentication (login)
     * - Account verification
     * - Password reset functionality
     */
    @Column(name = "email", unique = true, nullable = false, length = 100)
    @Email(message = "Email must be a valid email address")
    @NotBlank(message = "Email is required")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    private String email;

    /**
     * User's encrypted password for authentication.
     * 
     * Security considerations:
     * - Stored in encrypted format using BCrypt
     * - Minimum 8 characters required for security
     * - Maximum 255 characters to accommodate encrypted hash
     * - Should never be returned in API responses
     * 
     * The actual password validation and encryption is handled
     * by the authentication service layer.
     */
    @Column(name = "password", nullable = false, length = 255)
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    /**
     * User's display nickname for the application interface.
     * 
     * This friendly name is used for:
     * - Display in user interfaces
     * - User identification in comments/posts
     * - Personalization of user experience
     * 
     * Constraints:
     * - Cannot be null or blank
     * - Must be between 2-30 characters for usability
     * - Does not need to be unique (unlike email)
     */
    @Column(name = "nickname", nullable = false, length = 30)
    @NotBlank(message = "Nickname is required")
    @Size(min = 2, max = 30, message = "Nickname must be between 2 and 30 characters")
    private String nickname;

    /**
     * Timestamp indicating when the user account was created.
     * Automatically set by Hibernate on entity persistence.
     * Used for audit trails and account age tracking.
     */
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Timestamp indicating when the user account was last updated.
     * Automatically updated by Hibernate on any entity modification.
     * Useful for tracking recent account activity and changes.
     */
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
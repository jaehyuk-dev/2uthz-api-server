package com._uthz.api_server.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for user registration requests.
 * 
 * This DTO encapsulates all the information required to create a new user account.
 * It includes validation rules to ensure data integrity and security compliance
 * before processing the registration request.
 * 
 * Key features:
 * - Comprehensive input validation for all required fields
 * - Email uniqueness is validated at the service layer
 * - Password security requirements enforcement
 * - Nickname validation for user experience
 * 
 * Security considerations:
 * - Password is validated for minimum security requirements
 * - Email format validation prevents injection attacks
 * - Input length limits prevent buffer overflow attacks
 * - All fields are required to prevent incomplete registrations
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON deserialization
@AllArgsConstructor // Lombok: generates constructor with all fields
public class RegisterRequestDto {

    /**
     * User's email address that will serve as their unique username.
     * 
     * This email will be used for:
     * - User authentication (login)
     * - Account verification processes
     * - Password reset functionality
     * - Important account notifications
     * 
     * Validation constraints:
     * - Must be a valid email format (RFC 5322 compliant)
     * - Cannot be null, empty, or contain only whitespace
     * - Maximum 100 characters to match database constraints
     * - Must be unique across all users (validated at service layer)
     * 
     * Example valid emails:
     * - "newuser@example.com"
     * - "user.name+tag@domain.co.uk"
     * - "123user@test-domain.org"
     */
    @Email(message = "Email must be a valid email address")
    @NotBlank(message = "Email is required")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    private String email;

    /**
     * User's password for account security.
     * 
     * The password will be immediately encrypted using BCrypt hashing
     * algorithm before being stored in the database. This field is
     * never persisted in plain text.
     * 
     * Security requirements:
     * - Minimum 8 characters for basic security
     * - Transmitted over HTTPS only
     * - Immediately hashed upon server receipt
     * - Never logged or returned in API responses
     * 
     * Validation constraints:
     * - Cannot be null, empty, or contain only whitespace
     * - Must be at least 8 characters long
     * - Additional complexity rules enforced at service layer
     * 
     * Note: Consider implementing additional password strength
     * requirements such as:
     * - At least one uppercase letter
     * - At least one number
     * - At least one special character
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;

    /**
     * User's display nickname for the application interface.
     * 
     * This friendly name will be used throughout the application for:
     * - User identification in interfaces
     * - Display in user profiles
     * - Comments and post attribution
     * - Personalized user experience
     * 
     * Business rules:
     * - Does not need to be unique (unlike email)
     * - Should be user-friendly and appropriate
     * - Used for display purposes only, not authentication
     * 
     * Validation constraints:
     * - Cannot be null, empty, or contain only whitespace
     * - Must be between 2-30 characters for usability
     * - Length limits ensure good user experience and database efficiency
     * 
     * Example valid nicknames:
     * - "John"
     * - "User123"
     * - "Cool_User_Name"
     * 
     * Example invalid nicknames:
     * - "A" (too short)
     * - "ThisNicknameIsWayTooLongForOurSystem" (too long)
     * - "" (empty)
     */
    @NotBlank(message = "Nickname is required")
    @Size(min = 2, max = 30, message = "Nickname must be between 2 and 30 characters")
    private String nickname;
}
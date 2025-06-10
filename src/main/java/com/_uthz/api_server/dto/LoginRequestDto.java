package com._uthz.api_server.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for user login requests.
 * 
 * This DTO encapsulates the credentials required for user authentication.
 * It provides validation rules and ensures that only necessary data
 * is transmitted between the client and server during login operations.
 * 
 * Security considerations:
 * - Password is validated for minimum length requirements
 * - Email format validation prevents malformed input
 * - No sensitive data is logged or exposed in toString methods
 * 
 * Validation rules:
 * - Email must be valid format and not blank
 * - Password must be at least 8 characters
 * - Both fields are required for authentication
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON deserialization
@AllArgsConstructor // Lombok: generates constructor with all fields
public class LoginRequestDto {

    /**
     * User's email address used as the username for authentication.
     * 
     * This field serves as the unique identifier for user login.
     * The email is validated for proper format and cannot be empty.
     * 
     * Validation constraints:
     * - Must be a valid email format (RFC 5322 compliant)
     * - Cannot be null, empty, or contain only whitespace
     * 
     * Example valid values:
     * - "user@example.com"
     * - "test.user+tag@domain.co.uk"
     * 
     * Example invalid values:
     * - "invalid-email" (missing @ and domain)
     * - "@example.com" (missing local part)
     * - "user@" (missing domain)
     */
    @Email(message = "Email must be a valid email address")
    @NotBlank(message = "Email is required")
    private String email;

    /**
     * User's password for authentication.
     * 
     * The password is transmitted as plain text over HTTPS and
     * immediately encrypted using BCrypt upon receipt by the server.
     * 
     * Security requirements:
     * - Minimum 8 characters to ensure adequate security
     * - Transmitted over secure HTTPS connection only
     * - Never stored in logs or returned in responses
     * - Immediately hashed upon server receipt
     * 
     * Validation constraints:
     * - Cannot be null, empty, or contain only whitespace
     * - Must be at least 8 characters long
     * 
     * Note: Additional password complexity rules (uppercase, lowercase,
     * numbers, special characters) should be enforced at the service
     * layer based on business security requirements.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
}
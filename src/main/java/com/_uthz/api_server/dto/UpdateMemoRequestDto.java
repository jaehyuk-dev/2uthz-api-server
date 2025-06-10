package com._uthz.api_server.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for updating existing memo requests.
 * 
 * This DTO encapsulates the information required for updating an existing memo
 * through the API. It includes the same validation constraints as creation
 * requests to ensure data integrity and consistency across memo operations.
 * 
 * Key features:
 * - Input validation for title and memo content updates
 * - Character limit enforcement matching entity constraints
 * - Swagger documentation for API clarity
 * - Supports both full and partial memo updates
 * 
 * Update behavior:
 * - Both title and memo fields are required for complete updates
 * - Validation ensures updated content meets the same standards as creation
 * - Memo ownership verification performed at service layer
 * - Automatic timestamp and modifier tracking via JPA Auditing
 * 
 * Validation rules:
 * - Title: Required, maximum 50 characters
 * - Memo: Required, maximum 255 characters
 * - Both fields must contain non-whitespace content
 * 
 * Usage pattern:
 * - Received in PUT/PATCH requests to update existing memos
 * - Memo ID provided in URL path parameter
 * - Validated automatically by Spring Boot validation
 * - Authorization checked before applying updates
 * 
 * Security considerations:
 * - No user ID field (owner verification done via authentication)
 * - Input validation prevents malicious or oversized content
 * - DTO pattern prevents direct entity manipulation
 * - Owner-only update enforcement at service layer
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON deserialization
@AllArgsConstructor // Lombok: generates constructor with all fields
@Schema(
    name = "UpdateMemoRequest",
    description = "Request payload for updating an existing memo with new title and content"
)
public class UpdateMemoRequestDto {

    /**
     * Updated title of the memo for identification and organization.
     * 
     * The new title to replace the existing memo title. This allows users
     * to refine their memo organization or correct titles as their needs
     * evolve. The same validation rules apply as during memo creation.
     * 
     * Validation constraints:
     * - Required field (cannot be null, empty, or only whitespace)
     * - Maximum 50 characters to ensure concise, focused titles
     * - Must contain at least one non-whitespace character
     * 
     * Update considerations:
     * - Replaces the existing title completely
     * - Users should review the new title for clarity
     * - Title changes are tracked via JPA Auditing
     * - Updated title immediately visible in memo listings
     * 
     * API usage:
     * ```json
     * PUT /api/memos/123
     * {
     *   "title": "Updated Meeting Notes - Project Alpha",
     *   "memo": "Revised notes with additional action items..."
     * }
     * ```
     * 
     * Use cases:
     * - Correcting typos in original title
     * - Adding specificity to generic titles
     * - Updating titles to reflect changed content
     * - Improving memo organization and searchability
     */
    @Schema(
        description = "Updated title of the memo for identification and organization",
        example = "Updated Meeting Notes - Project Alpha Review",
        maxLength = 50,
        required = true
    )
    @NotBlank(message = "Title is required")
    @Size(max = 50, message = "Title must not exceed 50 characters")
    private String title;

    /**
     * Updated content of the memo containing revised notes or information.
     * 
     * The new content to replace the existing memo content. This allows users
     * to add information, correct details, or completely revise their memos
     * while maintaining the memo's identity and creation history.
     * 
     * Validation constraints:
     * - Required field (cannot be null, empty, or only whitespace)
     * - Maximum 255 characters for database efficiency and focused content
     * - Must contain at least one non-whitespace character
     * 
     * Update behavior:
     * - Completely replaces existing memo content
     * - Previous content is not preserved (consider versioning for future)
     * - Character limit enforced to maintain consistency
     * - Content changes tracked via JPA Auditing timestamps
     * 
     * Content update guidelines:
     * - Review entire content for completeness after updates
     * - Consider character limit when adding new information
     * - Maintain memo focus and relevance
     * - Use clear, concise language for future reference
     * 
     * API usage examples:
     * ```json
     * {
     *   "title": "Project Deadline - UPDATED",
     *   "memo": "REVISED: Submit final report by Monday 5 PM (extended). Include budget analysis, timeline review, and risk assessment. Contact Sarah for financial data by Thursday."
     * }
     * ```
     * 
     * Common update scenarios:
     * - Adding new information to existing notes
     * - Correcting errors or outdated information
     * - Expanding on brief initial notes
     * - Updating deadlines or contact information
     * - Refining content for better clarity
     */
    @Schema(
        description = "Updated content of the memo containing revised notes or information",
        example = "Updated project timeline with new deadlines. Budget approved with 10% increase. Next meeting scheduled for Friday 2 PM to discuss implementation details.",
        maxLength = 255,
        required = true
    )
    @NotBlank(message = "Memo content is required")
    @Size(max = 255, message = "Memo content must not exceed 255 characters")
    private String memo;
}
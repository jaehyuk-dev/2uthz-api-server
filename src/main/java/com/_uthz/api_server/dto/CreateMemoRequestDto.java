package com._uthz.api_server.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for creating new memo requests.
 * 
 * This DTO encapsulates the required information for creating a new memo
 * through the API. It includes validation constraints to ensure data integrity
 * and provides a clean interface for client applications to submit memo data.
 * 
 * Key features:
 * - Input validation for title and memo content
 * - Character limit enforcement matching entity constraints
 * - Swagger documentation for API clarity
 * - Clean separation between API layer and domain model
 * 
 * Validation rules:
 * - Title: Required, maximum 50 characters
 * - Memo: Required, maximum 255 characters
 * - Both fields must contain non-whitespace content
 * 
 * Usage pattern:
 * - Received in POST requests to create new memos
 * - Validated automatically by Spring Boot validation
 * - Converted to Memo entity in service layer
 * - User ID automatically captured from authentication context
 * 
 * Security considerations:
 * - No user ID field (automatically captured from authentication)
 * - Input validation prevents malicious or oversized content
 * - DTO pattern prevents direct entity manipulation
 * - Clean API surface for client applications
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON deserialization
@AllArgsConstructor // Lombok: generates constructor with all fields
@Schema(
    name = "CreateMemoRequest",
    description = "Request payload for creating a new memo with title and content"
)
public class CreateMemoRequestDto {

    /**
     * Title of the memo for identification and organization.
     * 
     * The title provides a brief, descriptive label for the memo that helps
     * users quickly identify and organize their content. It should be concise
     * but meaningful enough to distinguish the memo from others.
     * 
     * Validation constraints:
     * - Required field (cannot be null, empty, or only whitespace)
     * - Maximum 50 characters to ensure concise, focused titles
     * - Must contain at least one non-whitespace character
     * 
     * User experience considerations:
     * - Short enough for list displays and mobile interfaces
     * - Descriptive enough for easy memo identification
     * - Encourages clear, focused memo organization
     * 
     * API usage:
     * ```json
     * {
     *   "title": "Meeting Notes - Project Alpha",
     *   "memo": "Discussed timeline and budget requirements..."
     * }
     * ```
     * 
     * Validation examples:
     * - Valid: "Meeting Notes", "Todo List", "Important Reminder"
     * - Invalid: null, "", "   ", "This title is way too long and exceeds the fifty character limit"
     */
    @Schema(
        description = "Title of the memo for easy identification and organization",
        example = "Meeting Notes - Project Alpha",
        maxLength = 50,
        required = true
    )
    @NotBlank(message = "Title is required")
    @Size(max = 50, message = "Title must not exceed 50 characters")
    private String title;

    /**
     * Content of the memo containing the actual note or information.
     * 
     * This field contains the main content of the memo - the actual note,
     * reminder, or information the user wants to store. The content should
     * be concise but comprehensive enough to be useful when referenced later.
     * 
     * Validation constraints:
     * - Required field (cannot be null, empty, or only whitespace)
     * - Maximum 255 characters for database efficiency and focused content
     * - Must contain at least one non-whitespace character
     * 
     * Content guidelines:
     * - Suitable for notes, reminders, quick thoughts, action items
     * - Character limit encourages focused, essential information
     * - Supports any text content including special characters and Unicode
     * - Consider using bullet points or abbreviations for longer content
     * 
     * Usage scenarios:
     * - Personal notes and reminders
     * - Meeting notes and action items
     * - Quick thoughts and ideas
     * - Reference information and links
     * - Task descriptions and deadlines
     * - Shopping lists and checklists
     * 
     * API usage examples:
     * ```json
     * {
     *   "title": "Project Deadline",
     *   "memo": "Submit final report by Friday 5 PM. Include budget analysis and timeline review. Contact Sarah for financial data."
     * }
     * ```
     * 
     * Validation examples:
     * - Valid: "Buy groceries: milk, eggs, bread", "Call dentist to reschedule appointment"
     * - Invalid: null, "", "   ", [content exceeding 255 characters]
     */
    @Schema(
        description = "Content of the memo containing notes, reminders, or information",
        example = "Discussed project timeline, budget constraints, and next steps. Need to follow up with team lead by Friday.",
        maxLength = 255,
        required = true
    )
    @NotBlank(message = "Memo content is required")
    @Size(max = 255, message = "Memo content must not exceed 255 characters")
    private String memo;
}
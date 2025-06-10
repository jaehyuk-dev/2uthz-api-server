package com._uthz.api_server.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Data Transfer Object for memo response data.
 * 
 * This DTO encapsulates memo information returned to clients through the API.
 * It includes all memo details along with auditing information for complete
 * transparency about memo creation and modification history.
 * 
 * Key features:
 * - Complete memo information including content and metadata
 * - Auditing information for creation and modification tracking
 * - Character count statistics for user feedback
 * - Swagger documentation for API clarity
 * - Clean separation between domain model and API response
 * 
 * Response information:
 * - Core memo data (ID, title, content)
 * - Creation metadata (creator, timestamp)
 * - Modification metadata (last modifier, timestamp)
 * - Content statistics (character counts, limits)
 * 
 * Usage pattern:
 * - Returned in all memo API responses (GET, POST, PUT)
 * - Provides complete memo information for client applications
 * - Includes metadata for user interface enhancements
 * - Supports audit trails and modification tracking
 * 
 * Security considerations:
 * - Only returns memos owned by the authenticated user
 * - Creator/modifier IDs included for audit purposes
 * - No sensitive information exposed beyond memo content
 * - Consistent response format across all memo operations
 */
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor for JSON serialization
@AllArgsConstructor // Lombok: generates constructor with all fields
@Schema(
    name = "MemoResponse",
    description = "Complete memo information including content and auditing metadata"
)
public class MemoResponseDto {

    /**
     * Unique identifier of the memo.
     * 
     * The memo ID serves as the primary identifier for all memo operations
     * and is used in API endpoints for specific memo access. This ID is
     * auto-generated and unique across all memos in the system.
     * 
     * Usage:
     * - Used in API URLs for specific memo operations (GET, PUT, DELETE)
     * - Client-side memo identification and caching
     * - Reference for memo relationships (if implemented in future)
     * - Database primary key for query optimization
     */
    @Schema(
        description = "Unique identifier of the memo",
        example = "123",
        required = true
    )
    private Long memoId;

    /**
     * Title of the memo for identification and organization.
     * 
     * The memo title provides a brief, descriptive label that helps users
     * quickly identify and organize their memos. This is the primary way
     * users will distinguish between different memos in lists and searches.
     * 
     * Display characteristics:
     * - Maximum 50 characters for consistent UI display
     * - Used in memo lists, search results, and navigation
     * - Primary identification method for users
     * - Suitable for sorting and filtering operations
     */
    @Schema(
        description = "Title of the memo for identification and organization",
        example = "Meeting Notes - Project Alpha",
        maxLength = 50,
        required = true
    )
    private String title;

    /**
     * Content of the memo containing the actual notes or information.
     * 
     * The full content of the memo as entered by the user. This contains
     * the actual notes, reminders, or information that the user wanted
     * to store and reference later.
     * 
     * Content characteristics:
     * - Maximum 255 characters for focused, concise content
     * - Contains the primary value of the memo
     * - Supports full-text search capabilities (if implemented)
     * - Displayed in memo detail views and previews
     */
    @Schema(
        description = "Content of the memo containing notes or information",
        example = "Discussed project timeline, budget constraints, and next steps. Need to follow up with team lead by Friday.",
        maxLength = 255,
        required = true
    )
    private String memo;

    /**
     * User ID of the memo creator.
     * 
     * Identifies the user who originally created this memo. This information
     * is automatically captured during memo creation through JPA Auditing
     * and provides accountability and ownership tracking.
     * 
     * Auditing purposes:
     * - Ownership verification for authorization
     * - User activity tracking and analytics
     * - Audit trails for compliance requirements
     * - Data retention and cleanup operations
     */
    @Schema(
        description = "User ID of the memo creator for ownership tracking",
        example = "456",
        required = true
    )
    private Long createdBy;

    /**
     * Timestamp when the memo was created.
     * 
     * Records the exact date and time when the memo was first created.
     * This information is automatically captured through JPA Auditing
     * and provides a complete chronological record.
     * 
     * Timestamp usage:
     * - Chronological sorting and filtering
     * - User activity analysis
     * - Data retention policy implementation
     * - Audit trail documentation
     */
    @Schema(
        description = "Timestamp when the memo was created",
        example = "2023-12-01T10:30:00",
        required = true
    )
    private LocalDateTime createdAt;

    /**
     * User ID of the last user to modify the memo.
     * 
     * Identifies the user who most recently updated this memo. For newly
     * created memos, this will be the same as createdBy. This information
     * is automatically updated through JPA Auditing on each modification.
     * 
     * Modification tracking:
     * - Change accountability and responsibility
     * - User activity monitoring
     * - Audit trails for data modifications
     * - Collaboration tracking (if sharing features added)
     */
    @Schema(
        description = "User ID of the last user to modify the memo",
        example = "456"
    )
    private Long lastModifiedBy;

    /**
     * Timestamp of the last modification to the memo.
     * 
     * Records when the memo was most recently updated. For newly created
     * memos, this will be the same as createdAt. This timestamp is
     * automatically updated through JPA Auditing on each modification.
     * 
     * Modification tracking:
     * - Cache invalidation and synchronization
     * - Change detection and notifications
     * - Data freshness indicators
     * - Audit trail completeness
     */
    @Schema(
        description = "Timestamp of the last modification to the memo",
        example = "2023-12-01T14:45:00"
    )
    private LocalDateTime lastModifiedAt;

    /**
     * Current character count of the memo content.
     * 
     * Provides the current length of the memo content in characters.
     * This information helps users understand how much content they have
     * and how much space remains within the character limit.
     * 
     * User interface benefits:
     * - Character count display in editing interfaces
     * - Progress indicators for content limits
     * - Content statistics and analytics
     * - Input validation feedback
     */
    @Schema(
        description = "Current character count of the memo content",
        example = "147",
        minimum = "1",
        maximum = "255"
    )
    private Integer contentLength;

    /**
     * Remaining characters available for memo content.
     * 
     * Calculates how many more characters can be added to the memo
     * before reaching the 255-character limit. This provides immediate
     * feedback to users about available content space.
     * 
     * User experience benefits:
     * - Real-time feedback during content editing
     * - Visual indicators for content limits
     * - Helps users plan content additions
     * - Prevents content truncation surprises
     */
    @Schema(
        description = "Remaining characters available for memo content (255 - current length)",
        example = "108",
        minimum = "0",
        maximum = "254"
    )
    private Integer remainingCharacters;

    /**
     * Indicates if the memo content is near the character limit.
     * 
     * Boolean flag indicating whether the memo is approaching the
     * 255-character limit (within 20 characters). This helps user
     * interfaces provide appropriate warnings or styling changes.
     * 
     * User interface applications:
     * - Warning indicators in editing interfaces
     * - Color changes or styling for limit warnings
     * - Conditional display of character count information
     * - Input validation and user guidance
     */
    @Schema(
        description = "Indicates if the memo is near the character limit (within 20 characters)",
        example = "false"
    )
    private Boolean nearLimit;

    /**
     * Preview of the memo content for list displays.
     * 
     * Provides a truncated version of the memo content (50 characters)
     * suitable for list views and previews where full content display
     * is not appropriate or necessary.
     * 
     * Usage scenarios:
     * - Memo list views with content previews
     * - Search results with content snippets
     * - Dashboard displays with memo summaries
     * - Mobile interfaces with limited screen space
     */
    @Schema(
        description = "Preview of memo content (first 50 characters) for list displays",
        example = "Discussed project timeline, budget constraints...",
        maxLength = 53
    )
    private String preview;
}
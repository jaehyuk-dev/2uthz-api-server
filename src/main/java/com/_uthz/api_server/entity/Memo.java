package com._uthz.api_server.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * Memo entity representing a personal note or memo created by a user.
 * 
 * This entity serves as the core domain model for the memo functionality,
 * which is the main service of the application. Each memo contains a title
 * and content, and is automatically associated with its creator through
 * JPA Auditing via the BaseEntity.
 * 
 * Key features:
 * - Extends BaseEntity for automatic auditing (creator, timestamps)
 * - Title limited to 50 characters for concise identification
 * - Memo content limited to 255 characters for database efficiency
 * - Automatic owner association through JPA Auditing
 * - Input validation for data integrity
 * 
 * Business rules:
 * - Only the memo creator can read, update, or delete their memos
 * - Title and memo content are both required fields
 * - Character limits ensure consistent user experience and database performance
 * - Auditing provides complete creation and modification history
 * 
 * Database design:
 * - Uses IDENTITY generation strategy for auto-incrementing primary key
 * - VARCHAR lengths optimized for typical memo usage patterns
 * - Inherits auditing columns from BaseEntity (created_by, created_at, etc.)
 * - Indexes on memo_id (primary) and created_by (for user filtering)
 * 
 * Security considerations:
 * - Owner-only access enforced at service layer
 * - No direct user ID field (uses inherited createdBy from BaseEntity)
 * - Validation prevents malicious input
 * - Auditing provides accountability and traceability
 */
@Entity
@Table(name = "memos") // Use plural table name following conventions
@Data // Lombok: generates getters, setters, toString, equals, hashCode
@EqualsAndHashCode(callSuper = false) // Lombok: handle inheritance from BaseEntity
@Builder // Lombok: provides builder pattern for object creation
@NoArgsConstructor // Lombok: generates default constructor (required by JPA)
@AllArgsConstructor // Lombok: generates constructor with all fields
public class Memo extends BaseEntity {

    /**
     * Primary key for the memo entity.
     * 
     * Auto-generated using database identity strategy for optimal performance
     * and consistency across different database systems. The memo ID serves
     * as the unique identifier for API operations and foreign key references.
     * 
     * Database characteristics:
     * - Auto-incrementing integer primary key
     * - Unique across all memos in the system
     * - Used in API endpoints for memo identification
     * - Referenced in indexes for query optimization
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "memo_id")
    private Long memoId;

    /**
     * Title of the memo for easy identification and organization.
     * 
     * The title serves as a brief, descriptive label for the memo content.
     * It helps users quickly identify and organize their memos without
     * reading the full content. The 50-character limit encourages concise
     * but meaningful titles.
     * 
     * Validation constraints:
     * - Required field (cannot be null or empty)
     * - Maximum 50 characters to ensure concise titles
     * - Minimum implied by @NotBlank (at least one non-whitespace character)
     * 
     * Usage patterns:
     * - Displayed in memo lists and search results
     * - Used for memo identification in user interfaces
     * - Searchable field for memo discovery
     * - Brief summary of memo content
     * 
     * Business considerations:
     * - Length limit promotes clear, focused titles
     * - Required to ensure all memos have identifiable names
     * - Supports user organization and memo management
     * - Enables efficient memo browsing and selection
     * 
     * Database storage:
     * - Column name: title
     * - Type: VARCHAR(50) for optimal storage and indexing
     * - Not nullable to enforce required constraint
     * - Indexable for search and filtering operations
     */
    @Column(name = "title", nullable = false, length = 50)
    @NotBlank(message = "Title is required")
    @Size(max = 50, message = "Title must not exceed 50 characters")
    private String title;

    /**
     * Content of the memo containing the actual note or information.
     * 
     * This field stores the main content of the memo, such as notes, reminders,
     * thoughts, or any text the user wants to save. The 255-character limit
     * is designed for short to medium-length notes while maintaining database
     * performance and encouraging focused content.
     * 
     * Validation constraints:
     * - Required field (cannot be null or empty)
     * - Maximum 255 characters for database efficiency
     * - Minimum implied by @NotBlank (at least one non-whitespace character)
     * 
     * Content guidelines:
     * - Suitable for notes, reminders, quick thoughts
     * - Character limit encourages concise, focused content
     * - Supports any text content within character limits
     * - Unicode support for international characters
     * 
     * Usage scenarios:
     * - Personal notes and reminders
     * - Quick thoughts and ideas
     * - Meeting notes and action items
     * - Reference information and links
     * - Task descriptions and deadlines
     * 
     * Performance considerations:
     * - VARCHAR(255) provides good balance of storage and performance
     * - Length suitable for indexing if search features are added
     * - Memory-efficient for common memo operations
     * - Fast retrieval and display in user interfaces
     * 
     * Database storage:
     * - Column name: memo
     * - Type: VARCHAR(255) for optimal storage and performance
     * - Not nullable to enforce required constraint
     * - Full-text search capable if needed in future
     */
    @Column(name = "memo", nullable = false, length = 255)
    @NotBlank(message = "Memo content is required")
    @Size(max = 255, message = "Memo content must not exceed 255 characters")
    private String memo;

    /**
     * Checks if the specified user is the owner of this memo.
     * 
     * Convenience method that leverages the inherited BaseEntity functionality
     * to determine memo ownership. This is used throughout the application
     * for authorization checks to ensure only memo owners can access their content.
     * 
     * @param userId The user ID to check for ownership
     * @return true if the user is the memo owner, false otherwise
     * 
     * Authorization usage:
     * ```java
     * if (!memo.isOwnedBy(currentUserId)) {
     *     throw new AccessDeniedException("Access denied");
     * }
     * ```
     * 
     * Security implementation:
     * - Uses inherited isCreatedBy() method from BaseEntity
     * - Relies on JPA Auditing for accurate creator information
     * - Cannot be manually overridden or spoofed
     * - Provides consistent authorization logic across the application
     * 
     * Business logic:
     * - Only memo creators can read, update, or delete their memos
     * - Supports owner-only operations throughout the memo service
     * - Enables secure multi-user memo management
     * - Provides foundation for future sharing features
     */
    public boolean isOwnedBy(Long userId) {
        return isCreatedBy(userId);
    }

    /**
     * Gets a preview of the memo content for display purposes.
     * 
     * Returns a truncated version of the memo content suitable for
     * list views and previews where full content display is not needed.
     * Useful for memo browsing and search result displays.
     * 
     * @param maxLength Maximum length of the preview (default 50 characters)
     * @return Truncated memo content with ellipsis if truncated
     * 
     * Usage scenarios:
     * - Memo list views showing content previews
     * - Search results with content snippets
     * - Dashboard displays with memo summaries
     * - Mobile interfaces with limited screen space
     */
    public String getPreview(int maxLength) {
        if (memo == null) {
            return "";
        }
        
        if (memo.length() <= maxLength) {
            return memo;
        }
        
        return memo.substring(0, maxLength) + "...";
    }

    /**
     * Gets a default preview of the memo content (50 characters).
     * 
     * Convenience method that returns a 50-character preview of the memo
     * content, suitable for most list and summary displays.
     * 
     * @return Truncated memo content (50 characters max) with ellipsis if needed
     */
    public String getPreview() {
        return getPreview(50);
    }

    /**
     * Returns the character count of the memo content.
     * 
     * Utility method for displaying content statistics and helping users
     * understand how much content they can still add within the limit.
     * 
     * @return Number of characters in the memo content, or 0 if content is null
     * 
     * Usage scenarios:
     * - Character count displays in editing interfaces
     * - Validation feedback for users
     * - Content statistics and analytics
     * - Input guidance for character limits
     */
    public int getContentLength() {
        return memo != null ? memo.length() : 0;
    }

    /**
     * Returns the remaining characters available for memo content.
     * 
     * Calculates how many more characters the user can add before
     * reaching the 255-character limit. Useful for real-time feedback
     * in editing interfaces.
     * 
     * @return Number of characters remaining (255 - current length)
     */
    public int getRemainingCharacters() {
        return 255 - getContentLength();
    }

    /**
     * Checks if the memo content is at or near the character limit.
     * 
     * Determines if the memo is approaching the 255-character limit,
     * useful for displaying warnings or styling changes in user interfaces.
     * 
     * @param warningThreshold Characters remaining to trigger warning (default 20)
     * @return true if remaining characters <= threshold, false otherwise
     */
    public boolean isNearLimit(int warningThreshold) {
        return getRemainingCharacters() <= warningThreshold;
    }

    /**
     * Checks if the memo is near the character limit (20 characters remaining).
     * 
     * Convenience method using default warning threshold of 20 characters.
     * 
     * @return true if 20 or fewer characters remaining, false otherwise
     */
    public boolean isNearLimit() {
        return isNearLimit(20);
    }
}
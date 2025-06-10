package com._uthz.api_server.repository;

import com._uthz.api_server.entity.Memo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Memo entity data access operations.
 * 
 * This repository provides data access methods for memo management with
 * a focus on user-specific operations and authorization. All query methods
 * are designed to respect memo ownership and provide efficient data access
 * patterns for the memo service.
 * 
 * Key responsibilities:
 * - User-specific memo queries respecting ownership
 * - Efficient data access with proper indexing considerations
 * - Support for pagination and sorting operations
 * - Custom queries for advanced memo search and filtering
 * - Authorization-aware data access patterns
 * 
 * Security considerations:
 * - All queries filter by creator user ID for data isolation
 * - No direct access to other users' memos
 * - Owner verification built into query methods
 * - Consistent authorization patterns across all operations
 * 
 * Performance considerations:
 * - Queries designed for efficient index usage
 * - Pagination support for large memo collections
 * - Optimized queries for common access patterns
 * - Consider database indexes on (created_by, created_at) for performance
 * 
 * Usage pattern:
 * - Used exclusively by MemoService for data access
 * - Service layer handles authorization and business logic
 * - Repository focuses on efficient data retrieval
 * - Supports both individual memo access and bulk operations
 */
@Repository
public interface MemoRepository extends JpaRepository<Memo, Long> {

    /**
     * Finds all memos created by a specific user.
     * 
     * Retrieves all memos owned by the specified user, ordered by creation
     * timestamp in descending order (newest first). This method provides
     * the primary memo listing functionality for users.
     * 
     * @param createdBy The user ID of the memo creator
     * @return List of memos owned by the user, ordered by creation time (newest first)
     * 
     * Query optimization:
     * - Uses inherited createdBy field from BaseEntity
     * - Ordering by createdAt provides chronological memo browsing
     * - Index recommendation: (created_by, created_at DESC)
     * 
     * Usage scenarios:
     * - User memo dashboard display
     * - Memo management interfaces
     * - User activity tracking
     * - Data export operations
     * 
     * Authorization:
     * - Inherently secure as it filters by creator user ID
     * - No risk of cross-user data access
     * - Service layer provides additional authorization checks
     */
    List<Memo> findByCreatedByOrderByCreatedAtDesc(Long createdBy);

    /**
     * Finds all memos created by a specific user with pagination support.
     * 
     * Retrieves memos owned by the specified user with pagination and sorting
     * capabilities. This method is essential for efficient handling of users
     * with large memo collections.
     * 
     * @param createdBy The user ID of the memo creator
     * @param pageable Pagination and sorting parameters
     * @return Page of memos owned by the user with pagination metadata
     * 
     * Pagination benefits:
     * - Efficient handling of large memo collections
     * - Reduced memory usage and network transfer
     * - Improved user interface performance
     * - Configurable page sizes and sorting options
     * 
     * Usage scenarios:
     * - Paginated memo listings in web interfaces
     * - Mobile applications with lazy loading
     * - API endpoints with page-based navigation
     * - Large-scale memo management operations
     */
    Page<Memo> findByCreatedBy(Long createdBy, Pageable pageable);

    /**
     * Finds a specific memo by ID and creator user ID.
     * 
     * Retrieves a memo only if it exists and was created by the specified user.
     * This method provides secure access to individual memos with built-in
     * ownership verification.
     * 
     * @param memoId The unique identifier of the memo
     * @param createdBy The user ID of the memo creator
     * @return Optional containing the memo if found and owned by user, empty otherwise
     * 
     * Security benefits:
     * - Combines memo lookup with ownership verification
     * - Prevents access to other users' memos
     * - Returns empty Optional for unauthorized access attempts
     * - Single query for both existence and authorization checks
     * 
     * Usage scenarios:
     * - Individual memo retrieval for display
     * - Memo editing and update operations
     * - Memo deletion with ownership verification
     * - API endpoints requiring memo-specific access
     */
    Optional<Memo> findByMemoIdAndCreatedBy(Long memoId, Long createdBy);

    /**
     * Searches memos by title containing the specified text (case-insensitive).
     * 
     * Finds all memos owned by the specified user where the title contains
     * the search term. The search is case-insensitive and supports partial
     * matches for flexible memo discovery.
     * 
     * @param createdBy The user ID of the memo creator
     * @param titleKeyword The keyword to search for in memo titles
     * @return List of matching memos ordered by creation time (newest first)
     * 
     * Search features:
     * - Case-insensitive title search
     * - Partial match support (contains search)
     * - User-specific search scope
     * - Chronological result ordering
     * 
     * Usage scenarios:
     * - Memo search functionality in user interfaces
     * - Quick memo discovery and navigation
     * - Memo organization and categorization
     * - Content management and retrieval
     * 
     * Performance considerations:
     * - Consider full-text index on title column for large datasets
     * - LIKE queries may be slower on large datasets
     * - Could be enhanced with full-text search in future
     */
    List<Memo> findByCreatedByAndTitleContainingIgnoreCaseOrderByCreatedAtDesc(Long createdBy, String titleKeyword);

    /**
     * Searches memos by content containing the specified text (case-insensitive).
     * 
     * Finds all memos owned by the specified user where the memo content contains
     * the search term. This enables full-content search for comprehensive
     * memo discovery and information retrieval.
     * 
     * @param createdBy The user ID of the memo creator
     * @param contentKeyword The keyword to search for in memo content
     * @return List of matching memos ordered by creation time (newest first)
     * 
     * Search capabilities:
     * - Case-insensitive content search
     * - Partial match support within memo text
     * - User-specific search scope
     * - Chronological result ordering
     * 
     * Usage scenarios:
     * - Comprehensive memo content search
     * - Information retrieval from memo collection
     * - Content-based memo organization
     * - Research and reference lookup
     */
    List<Memo> findByCreatedByAndMemoContainingIgnoreCaseOrderByCreatedAtDesc(Long createdBy, String contentKeyword);

    /**
     * Counts the total number of memos created by a specific user.
     * 
     * Provides the total count of memos owned by the specified user.
     * This method is useful for analytics, user interface statistics,
     * and quota management.
     * 
     * @param createdBy The user ID of the memo creator
     * @return Total number of memos owned by the user
     * 
     * Usage scenarios:
     * - User dashboard statistics
     * - Quota management and limits
     * - User activity analytics
     * - Storage and usage reporting
     * 
     * Performance benefits:
     * - Efficient counting without data transfer
     * - Database-optimized count operation
     * - Suitable for real-time statistics
     */
    long countByCreatedBy(Long createdBy);

    /**
     * Finds memos created by a user within a specific date range.
     * 
     * Retrieves memos owned by the specified user that were created
     * between the specified start and end dates. This method supports
     * time-based filtering and analysis of memo creation patterns.
     * 
     * @param createdBy The user ID of the memo creator
     * @param startDate The start date for the search range (inclusive)
     * @param endDate The end date for the search range (inclusive)
     * @return List of memos created within the date range, ordered by creation time
     * 
     * Query features:
     * - Date range filtering with inclusive boundaries
     * - User-specific scope for data isolation
     * - Chronological ordering for temporal analysis
     * - Supports both date and datetime parameters
     * 
     * Usage scenarios:
     * - Time-based memo analysis and reporting
     * - Periodic memo review and cleanup
     * - Activity tracking and productivity analysis
     * - Data archival and retention operations
     * 
     * Performance considerations:
     * - Index recommendation: (created_by, created_at) for optimal performance
     * - Date range queries are efficiently supported by database indexes
     * - Consider partitioning for very large datasets
     */
    List<Memo> findByCreatedByAndCreatedAtBetweenOrderByCreatedAtDesc(
        Long createdBy, 
        LocalDateTime startDate, 
        LocalDateTime endDate
    );

    /**
     * Finds the most recently created memos by a user (limited count).
     * 
     * Custom query to retrieve the most recent memos for a user with
     * a configurable limit. This method is optimized for dashboard
     * displays and quick access to recent user activity.
     * 
     * @param createdBy The user ID of the memo creator
     * @param limit Maximum number of memos to return
     * @return List of recent memos (up to limit) ordered by creation time (newest first)
     * 
     * Query optimization:
     * - LIMIT clause reduces data transfer and processing
     * - ORDER BY with LIMIT is optimized by most databases
     * - Index on (created_by, created_at DESC) provides optimal performance
     * 
     * Usage scenarios:
     * - User dashboard with recent memo display
     * - Quick access widgets and summaries
     * - Mobile applications with limited screen space
     * - Performance-optimized memo previews
     * 
     * Example usage:
     * - Recent 5 memos for dashboard: findRecentMemosByUser(userId, 5)
     * - Latest memo for quick access: findRecentMemosByUser(userId, 1)
     */
    @Query("SELECT m FROM Memo m WHERE m.createdBy = :createdBy ORDER BY m.createdAt DESC LIMIT :limit")
    List<Memo> findRecentMemosByUser(@Param("createdBy") Long createdBy, @Param("limit") int limit);

    /**
     * Checks if a memo with the specified ID exists and is owned by the user.
     * 
     * Efficiently determines whether a memo exists and belongs to the specified
     * user without transferring the full memo data. This method is optimized
     * for authorization checks and validation operations.
     * 
     * @param memoId The unique identifier of the memo
     * @param createdBy The user ID of the memo creator
     * @return true if memo exists and is owned by the user, false otherwise
     * 
     * Performance benefits:
     * - Existence check without data transfer
     * - Optimized for authorization verification
     * - Database-level optimization for COUNT queries
     * - Minimal network and memory overhead
     * 
     * Usage scenarios:
     * - Authorization checks before memo operations
     * - Validation in service layer methods
     * - API endpoint existence verification
     * - Security auditing and access logging
     */
    boolean existsByMemoIdAndCreatedBy(Long memoId, Long createdBy);
}
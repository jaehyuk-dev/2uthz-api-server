package com._uthz.api_server.service;

import com._uthz.api_server.dto.CreateMemoRequestDto;
import com._uthz.api_server.dto.MemoResponseDto;
import com._uthz.api_server.dto.UpdateMemoRequestDto;
import com._uthz.api_server.entity.Memo;
import com._uthz.api_server.repository.MemoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service class for memo management operations.
 * 
 * This service provides comprehensive memo management functionality including
 * creation, retrieval, updating, and deletion of memos. All operations are
 * secured with user-based authorization to ensure users can only access
 * their own memos.
 * 
 * Key responsibilities:
 * - Complete CRUD operations for memo management
 * - User authorization and ownership verification
 * - Data transformation between entities and DTOs
 * - Business logic implementation for memo operations
 * - Integration with UserContextService for current user identification
 * 
 * Security features:
 * - Owner-only access enforcement for all memo operations
 * - Automatic user association through JPA Auditing
 * - Authorization checks before any memo access
 * - Data isolation between users
 * - Comprehensive access denied handling
 * 
 * Business logic:
 * - Memo creation with automatic owner assignment
 * - Ownership verification for read, update, delete operations
 * - Data validation and integrity checks
 * - Search and filtering capabilities
 * - Statistics and analytics support
 * 
 * Performance considerations:
 * - Transactional operations for data consistency
 * - Efficient queries through repository layer
 * - Pagination support for large memo collections
 * - Optimized DTO conversion for API responses
 * 
 * Usage pattern:
 * - Used exclusively by MemoController for memo operations
 * - Integrates with UserContextService for user identification
 * - Handles all business logic and authorization
 * - Provides clean interface for controller layer
 */
@Service
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance
@Transactional // Ensures all operations are executed within transactions
public class MemoService {

    /**
     * Repository for memo data access operations.
     * Provides efficient data retrieval and persistence functionality.
     */
    private final MemoRepository memoRepository;

    /**
     * Service for accessing current user context and authentication information.
     * Used for user identification and authorization in memo operations.
     */
    private final UserContextService userContextService;

    /**
     * Creates a new memo for the currently authenticated user.
     * 
     * This method creates a new memo with the provided title and content,
     * automatically associating it with the current authenticated user
     * through JPA Auditing. The memo owner is determined from the
     * authentication context, ensuring secure memo creation.
     * 
     * @param createRequest The memo creation request containing title and content
     * @return MemoResponseDto containing the created memo information
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Process flow:
     * 1. Verify user authentication
     * 2. Create memo entity from request data
     * 3. Save memo with automatic owner assignment via JPA Auditing
     * 4. Convert saved entity to response DTO
     * 5. Return complete memo information
     * 
     * Security implementation:
     * - User identification from authentication context
     * - Automatic owner assignment through JPA Auditing
     * - No manual user ID manipulation possible
     * - Transaction rollback on any security failures
     * 
     * Auditing behavior:
     * - createdBy automatically set to current user ID
     * - createdAt automatically set to current timestamp
     * - lastModifiedBy initially set to current user ID
     * - lastModifiedAt initially set to current timestamp
     * 
     * Validation:
     * - Input validation performed at DTO level
     * - Title length and memo content size enforced
     * - Business rule validation in entity
     * - Database constraints as final validation layer
     */
    public MemoResponseDto createMemo(CreateMemoRequestDto createRequest) {
        log.info("Creating new memo with title: {}", createRequest.getTitle());

        // Verify user authentication for memo creation
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo creation attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo creation");
        }

        // Create memo entity from request data
        // JPA Auditing will automatically set createdBy and timestamps
        Memo memo = Memo.builder()
                .title(createRequest.getTitle().trim()) // Normalize title whitespace
                .memo(createRequest.getMemo().trim())   // Normalize content whitespace
                .build();

        // Save memo to database with automatic auditing
        Memo savedMemo = memoRepository.save(memo);
        
        log.info("Memo created successfully with ID: {} for user: {}", 
                savedMemo.getMemoId(), currentUserId);

        // Convert entity to response DTO with complete information
        return convertToResponseDto(savedMemo);
    }

    /**
     * Retrieves all memos owned by the currently authenticated user.
     * 
     * This method returns a list of all memos created by the current user,
     * ordered by creation timestamp in descending order (newest first).
     * Only memos owned by the authenticated user are returned, ensuring
     * data privacy and security.
     * 
     * @return List of MemoResponseDto containing user's memos
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Authorization:
     * - Only returns memos owned by the current authenticated user
     * - No access to other users' memos possible
     * - Empty list returned if user has no memos
     * - User identification from secure authentication context
     * 
     * Ordering:
     * - Memos ordered by creation timestamp (newest first)
     * - Consistent ordering for predictable user experience
     * - Efficient ordering through database indexes
     * 
     * Performance:
     * - Single query for all user memos
     * - Efficient conversion to DTOs
     * - Optimized for typical user memo collection sizes
     * - Consider pagination for users with many memos
     */
    public List<MemoResponseDto> getUserMemos() {
        log.debug("Retrieving memos for current user");

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo retrieval attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo access");
        }

        // Retrieve all memos for the current user
        List<Memo> userMemos = memoRepository.findByCreatedByOrderByCreatedAtDesc(currentUserId);
        
        log.debug("Retrieved {} memos for user: {}", userMemos.size(), currentUserId);

        // Convert entities to response DTOs
        return userMemos.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }

    /**
     * Retrieves all memos owned by the current user with pagination support.
     * 
     * This method provides paginated access to user memos, enabling efficient
     * handling of users with large memo collections. It supports sorting
     * and filtering through the Pageable parameter.
     * 
     * @param pageable Pagination and sorting parameters
     * @return Page of MemoResponseDto with pagination metadata
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Pagination benefits:
     * - Efficient handling of large memo collections
     * - Reduced memory usage and network transfer
     * - Improved user interface performance
     * - Configurable page sizes and sorting options
     * 
     * Usage scenarios:
     * - Web interfaces with paginated memo lists
     * - Mobile applications with lazy loading
     * - API clients requiring page-based navigation
     * - Large-scale memo management operations
     */
    public Page<MemoResponseDto> getUserMemosPaginated(Pageable pageable) {
        log.debug("Retrieving paginated memos for current user with page: {}", pageable);

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Paginated memo retrieval attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo access");
        }

        // Retrieve paginated memos for the current user
        Page<Memo> memoPage = memoRepository.findByCreatedBy(currentUserId, pageable);
        
        log.debug("Retrieved page {} of {} with {} memos for user: {}", 
                memoPage.getNumber(), memoPage.getTotalPages(), 
                memoPage.getNumberOfElements(), currentUserId);

        // Convert page of entities to page of DTOs
        return memoPage.map(this::convertToResponseDto);
    }

    /**
     * Retrieves a specific memo by ID if owned by the current user.
     * 
     * This method fetches a memo by its unique identifier, but only if
     * the memo is owned by the currently authenticated user. This ensures
     * users cannot access other users' memos even if they know the memo ID.
     * 
     * @param memoId The unique identifier of the memo to retrieve
     * @return MemoResponseDto containing the memo information
     * @throws IllegalStateException if no authenticated user is found
     * @throws IllegalArgumentException if memo not found or not owned by user
     * 
     * Security implementation:
     * - Combines memo lookup with ownership verification
     * - Single query for both existence and authorization
     * - No memo data returned for unauthorized access attempts
     * - Detailed logging for security monitoring
     * 
     * Authorization checks:
     * - Memo must exist in the system
     * - Memo must be owned by the current authenticated user
     * - Any failure results in "not found" response for security
     * - No information leakage about other users' memos
     * 
     * Error handling:
     * - Clear error messages for different failure scenarios
     * - Security-conscious error responses
     * - Comprehensive logging for debugging and monitoring
     */
    public MemoResponseDto getMemoById(Long memoId) {
        log.debug("Retrieving memo with ID: {}", memoId);

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo retrieval attempted without authenticated user for memo ID: {}", memoId);
            throw new IllegalStateException("User authentication required for memo access");
        }

        // Find memo by ID and verify ownership
        Memo memo = memoRepository.findByMemoIdAndCreatedBy(memoId, currentUserId)
                .orElseThrow(() -> {
                    log.warn("Memo not found or access denied - ID: {}, User: {}", memoId, currentUserId);
                    return new IllegalArgumentException("Memo not found or access denied");
                });

        log.debug("Successfully retrieved memo ID: {} for user: {}", memoId, currentUserId);

        // Convert entity to response DTO
        return convertToResponseDto(memo);
    }

    /**
     * Updates an existing memo if owned by the current user.
     * 
     * This method allows users to update the title and content of their
     * existing memos. The update is only permitted if the memo is owned
     * by the currently authenticated user. JPA Auditing automatically
     * tracks the modification details.
     * 
     * @param memoId The unique identifier of the memo to update
     * @param updateRequest The update request containing new title and content
     * @return MemoResponseDto containing the updated memo information
     * @throws IllegalStateException if no authenticated user is found
     * @throws IllegalArgumentException if memo not found or not owned by user
     * 
     * Process flow:
     * 1. Verify user authentication
     * 2. Find memo and verify ownership
     * 3. Update memo fields with new values
     * 4. Save updated memo (triggers JPA Auditing)
     * 5. Return updated memo as response DTO
     * 
     * Security implementation:
     * - Ownership verification before any modifications
     * - Automatic modifier tracking via JPA Auditing
     * - Transaction rollback on authorization failures
     * - No cross-user memo access possible
     * 
     * Auditing behavior:
     * - lastModifiedBy automatically set to current user ID
     * - lastModifiedAt automatically set to current timestamp
     * - createdBy and createdAt remain unchanged
     * - Complete modification history maintained
     * 
     * Validation:
     * - Input validation performed at DTO level
     * - Business rule validation in entity
     * - Database constraints as final validation layer
     * - Character limits enforced consistently
     */
    public MemoResponseDto updateMemo(Long memoId, UpdateMemoRequestDto updateRequest) {
        log.info("Updating memo with ID: {} with new title: {}", memoId, updateRequest.getTitle());

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo update attempted without authenticated user for memo ID: {}", memoId);
            throw new IllegalStateException("User authentication required for memo updates");
        }

        // Find memo and verify ownership
        Memo memo = memoRepository.findByMemoIdAndCreatedBy(memoId, currentUserId)
                .orElseThrow(() -> {
                    log.warn("Memo update failed - not found or access denied - ID: {}, User: {}", 
                            memoId, currentUserId);
                    return new IllegalArgumentException("Memo not found or access denied");
                });

        // Update memo fields with new values
        memo.setTitle(updateRequest.getTitle().trim()); // Normalize title whitespace
        memo.setMemo(updateRequest.getMemo().trim());   // Normalize content whitespace

        // Save updated memo (JPA Auditing will update lastModifiedBy and lastModifiedAt)
        Memo updatedMemo = memoRepository.save(memo);
        
        log.info("Memo updated successfully - ID: {} for user: {}", memoId, currentUserId);

        // Convert updated entity to response DTO
        return convertToResponseDto(updatedMemo);
    }

    /**
     * Deletes a memo if owned by the current user.
     * 
     * This method permanently removes a memo from the system, but only
     * if the memo is owned by the currently authenticated user. The
     * deletion is permanent and cannot be undone.
     * 
     * @param memoId The unique identifier of the memo to delete
     * @throws IllegalStateException if no authenticated user is found
     * @throws IllegalArgumentException if memo not found or not owned by user
     * 
     * Security implementation:
     * - Ownership verification before deletion
     * - No cross-user memo deletion possible
     * - Transaction rollback on authorization failures
     * - Comprehensive logging for audit trails
     * 
     * Deletion behavior:
     * - Permanent removal from database
     * - No soft delete or recovery mechanism
     * - Cascading deletes handled automatically
     * - Database constraints ensure referential integrity
     * 
     * Audit considerations:
     * - Deletion events logged for audit trails
     * - User identification recorded in logs
     * - Timestamp of deletion captured
     * - Consider implementing soft delete for compliance requirements
     * 
     * Error handling:
     * - Clear error messages for different failure scenarios
     * - Security-conscious error responses
     * - Rollback protection for failed operations
     */
    public void deleteMemo(Long memoId) {
        log.info("Deleting memo with ID: {}", memoId);

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo deletion attempted without authenticated user for memo ID: {}", memoId);
            throw new IllegalStateException("User authentication required for memo deletion");
        }

        // Find memo and verify ownership
        Memo memo = memoRepository.findByMemoIdAndCreatedBy(memoId, currentUserId)
                .orElseThrow(() -> {
                    log.warn("Memo deletion failed - not found or access denied - ID: {}, User: {}", 
                            memoId, currentUserId);
                    return new IllegalArgumentException("Memo not found or access denied");
                });

        // Delete the memo permanently
        memoRepository.delete(memo);
        
        log.info("Memo deleted successfully - ID: {} by user: {}", memoId, currentUserId);
    }

    /**
     * Searches user's memos by title containing the specified keyword.
     * 
     * This method searches through the current user's memos to find those
     * with titles containing the specified keyword. The search is case-
     * insensitive and supports partial matches for flexible memo discovery.
     * 
     * @param keyword The keyword to search for in memo titles
     * @return List of MemoResponseDto containing matching memos
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Search features:
     * - Case-insensitive title search
     * - Partial match support (contains search)
     * - User-specific search scope
     * - Chronological result ordering (newest first)
     * 
     * Performance considerations:
     * - Efficient database-level search
     * - Results ordered for optimal user experience
     * - Consider full-text search for advanced requirements
     * 
     * Usage scenarios:
     * - Memo search functionality in user interfaces
     * - Quick memo discovery and navigation
     * - Memo organization and categorization
     * - Content management and retrieval
     */
    public List<MemoResponseDto> searchMemosByTitle(String keyword) {
        log.debug("Searching memos by title keyword: {}", keyword);

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo search attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo search");
        }

        // Search memos by title keyword
        List<Memo> matchingMemos = memoRepository
                .findByCreatedByAndTitleContainingIgnoreCaseOrderByCreatedAtDesc(currentUserId, keyword);
        
        log.debug("Found {} memos matching title keyword '{}' for user: {}", 
                matchingMemos.size(), keyword, currentUserId);

        // Convert entities to response DTOs
        return matchingMemos.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }

    /**
     * Searches user's memos by content containing the specified keyword.
     * 
     * This method searches through the current user's memos to find those
     * with content containing the specified keyword. The search is case-
     * insensitive and supports partial matches for comprehensive content discovery.
     * 
     * @param keyword The keyword to search for in memo content
     * @return List of MemoResponseDto containing matching memos
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Search capabilities:
     * - Case-insensitive content search
     * - Partial match support within memo text
     * - User-specific search scope
     * - Chronological result ordering (newest first)
     * 
     * Usage scenarios:
     * - Comprehensive memo content search
     * - Information retrieval from memo collection
     * - Content-based memo organization
     * - Research and reference lookup
     */
    public List<MemoResponseDto> searchMemosByContent(String keyword) {
        log.debug("Searching memos by content keyword: {}", keyword);

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo content search attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo search");
        }

        // Search memos by content keyword
        List<Memo> matchingMemos = memoRepository
                .findByCreatedByAndMemoContainingIgnoreCaseOrderByCreatedAtDesc(currentUserId, keyword);
        
        log.debug("Found {} memos matching content keyword '{}' for user: {}", 
                matchingMemos.size(), keyword, currentUserId);

        // Convert entities to response DTOs
        return matchingMemos.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }

    /**
     * Gets statistics about the current user's memo collection.
     * 
     * This method provides analytics and statistics about the user's
     * memo collection, including total count and other useful metrics
     * for dashboard displays and user insights.
     * 
     * @return Long representing the total number of user's memos
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Statistics provided:
     * - Total memo count for the user
     * - Efficient counting without data transfer
     * - Real-time statistics
     * 
     * Usage scenarios:
     * - User dashboard statistics
     * - Quota management and limits
     * - User activity analytics
     * - Storage and usage reporting
     */
    public Long getUserMemoCount() {
        log.debug("Getting memo count for current user");

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Memo count request attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo statistics");
        }

        // Get total memo count for user
        long memoCount = memoRepository.countByCreatedBy(currentUserId);
        
        log.debug("User {} has {} total memos", currentUserId, memoCount);

        return memoCount;
    }

    /**
     * Gets recent memos for the current user with a specified limit.
     * 
     * This method retrieves the most recently created memos for the user
     * with a configurable limit. It's optimized for dashboard displays
     * and quick access to recent user activity.
     * 
     * @param limit Maximum number of recent memos to return
     * @return List of MemoResponseDto containing recent memos
     * @throws IllegalStateException if no authenticated user is found
     * 
     * Performance benefits:
     * - LIMIT clause reduces data transfer and processing
     * - Optimized query for recent memo access
     * - Efficient for dashboard and widget displays
     * 
     * Usage scenarios:
     * - User dashboard with recent memo display
     * - Quick access widgets and summaries
     * - Mobile applications with limited screen space
     * - Performance-optimized memo previews
     */
    public List<MemoResponseDto> getRecentMemos(int limit) {
        log.debug("Getting {} recent memos for current user", limit);

        // Verify user authentication
        Long currentUserId = userContextService.getCurrentUserId();
        if (currentUserId == null) {
            log.warn("Recent memos request attempted without authenticated user");
            throw new IllegalStateException("User authentication required for memo access");
        }

        // Get recent memos with limit
        List<Memo> recentMemos = memoRepository.findRecentMemosByUser(currentUserId, limit);
        
        log.debug("Retrieved {} recent memos for user: {}", recentMemos.size(), currentUserId);

        // Convert entities to response DTOs
        return recentMemos.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }

    /**
     * Converts a Memo entity to a MemoResponseDto.
     * 
     * Private utility method that transforms a Memo entity into a complete
     * MemoResponseDto with all information including content statistics
     * and auditing metadata.
     * 
     * @param memo The Memo entity to convert
     * @return MemoResponseDto with complete memo information
     * 
     * Conversion includes:
     * - All memo data (ID, title, content)
     * - Auditing information (creator, timestamps)
     * - Content statistics (length, remaining, limits)
     * - Preview content for list displays
     * 
     * Performance considerations:
     * - Efficient field mapping
     * - Calculated fields computed once
     * - Reusable across all service methods
     * - Consistent DTO structure
     */
    private MemoResponseDto convertToResponseDto(Memo memo) {
        return MemoResponseDto.builder()
                .memoId(memo.getMemoId())
                .title(memo.getTitle())
                .memo(memo.getMemo())
                .createdBy(memo.getCreatedBy())
                .createdAt(memo.getCreatedAt())
                .lastModifiedBy(memo.getLastModifiedBy())
                .lastModifiedAt(memo.getLastModifiedAt())
                .contentLength(memo.getContentLength())
                .remainingCharacters(memo.getRemainingCharacters())
                .nearLimit(memo.isNearLimit())
                .preview(memo.getPreview())
                .build();
    }
}
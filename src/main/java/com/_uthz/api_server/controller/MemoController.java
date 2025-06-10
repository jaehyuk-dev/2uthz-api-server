package com._uthz.api_server.controller;

import com._uthz.api_server.dto.CreateMemoRequestDto;
import com._uthz.api_server.dto.MemoResponseDto;
import com._uthz.api_server.dto.UpdateMemoRequestDto;
import com._uthz.api_server.service.MemoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST controller for memo management operations.
 * 
 * This controller provides the API endpoints for the memo functionality,
 * which serves as the main service of the application. It handles all
 * memo-related HTTP requests including creation, retrieval, updating,
 * and deletion of personal memos.
 * 
 * Key responsibilities:
 * - HTTP request/response handling for memo operations
 * - Input validation and error handling
 * - Authorization through Spring Security integration
 * - Comprehensive API documentation via Swagger annotations
 * - RESTful API design following HTTP conventions
 * 
 * Security features:
 * - All endpoints require JWT authentication
 * - User-specific memo access through service layer authorization
 * - Input validation to prevent malicious data
 * - Proper HTTP status codes for different scenarios
 * - Error responses that don't leak sensitive information
 * 
 * API design principles:
 * - RESTful URL patterns and HTTP methods
 * - Consistent response formats across endpoints
 * - Comprehensive error handling with appropriate status codes
 * - Pagination support for large data sets
 * - Search and filtering capabilities
 * 
 * Swagger documentation:
 * - Complete API documentation for all endpoints
 * - Request/response schema definitions
 * - Example payloads and responses
 * - Authentication requirements clearly specified
 * - Error response documentation
 * 
 * Usage pattern:
 * - Entry point for all memo-related API requests
 * - Integrates with MemoService for business logic
 * - Handles HTTP protocol concerns (status codes, headers, etc.)
 * - Provides clean RESTful interface for client applications
 */
@RestController
@RequestMapping("/api/memos")
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance
@Tag(name = "Memo Management", description = "Personal memo creation, management, and organization operations")
public class MemoController {

    /**
     * Service for memo business logic and data operations.
     * Handles all memo-related operations with proper authorization.
     */
    private final MemoService memoService;

    /**
     * Creates a new memo for the authenticated user.
     * 
     * This endpoint allows users to create new personal memos with a title
     * and content. The memo is automatically associated with the authenticated
     * user and includes validation for title length and content size.
     * 
     * @param createRequest The memo creation request containing title and content
     * @return ResponseEntity with created memo information and HTTP 201 status
     * 
     * HTTP method: POST /api/memos
     * Authentication: Required (JWT Bearer token)
     * Request body: CreateMemoRequestDto with title and memo content
     * Response: MemoResponseDto with created memo information
     * 
     * Validation performed:
     * - Title: Required, maximum 50 characters
     * - Content: Required, maximum 255 characters
     * - Input sanitization and normalization
     * 
     * Success response (201 Created):
     * - Complete memo information including ID and timestamps
     * - Creator information and auditing metadata
     * - Content statistics for user feedback
     * 
     * Error responses:
     * - 400 Bad Request: Invalid input data or validation failures
     * - 401 Unauthorized: Missing or invalid authentication
     * - 422 Unprocessable Entity: Business rule violations
     */
    @PostMapping
    @Operation(
        summary = "Create a new memo",
        description = "Creates a new personal memo with title and content. The memo is automatically associated " +
                     "with the authenticated user and includes validation for character limits."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "201",
            description = "Memo created successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = MemoResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid input data or validation error",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "422",
            description = "Unprocessable entity - business rule violation",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<MemoResponseDto> createMemo(
            @Valid @RequestBody CreateMemoRequestDto createRequest) {
        
        log.info("API request to create memo with title: {}", createRequest.getTitle());

        try {
            // Create memo through service layer
            MemoResponseDto createdMemo = memoService.createMemo(createRequest);
            
            log.info("Memo created successfully with ID: {}", createdMemo.getMemoId());
            
            // Return created memo with HTTP 201 Created status
            return ResponseEntity.status(HttpStatus.CREATED).body(createdMemo);
            
        } catch (IllegalStateException e) {
            log.warn("Memo creation failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo creation: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Retrieves all memos for the authenticated user.
     * 
     * This endpoint returns a list of all memos owned by the authenticated user,
     * ordered by creation date (newest first). Only memos belonging to the
     * current user are returned, ensuring data privacy and security.
     * 
     * @return ResponseEntity with list of user's memos and HTTP 200 status
     * 
     * HTTP method: GET /api/memos
     * Authentication: Required (JWT Bearer token)
     * Response: List of MemoResponseDto with user's memos
     * 
     * Data returned:
     * - All memos owned by the authenticated user
     * - Ordered by creation timestamp (newest first)
     * - Complete memo information including metadata
     * - Empty list if user has no memos
     * 
     * Success response (200 OK):
     * - Array of memo objects with complete information
     * - Consistent ordering for predictable user experience
     * - Auditing information for each memo
     * 
     * Error responses:
     * - 401 Unauthorized: Missing or invalid authentication
     * - 500 Internal Server Error: Unexpected system error
     */
    @GetMapping
    @Operation(
        summary = "Get all user memos",
        description = "Retrieves all memos owned by the authenticated user, ordered by creation date (newest first). " +
                     "Only returns memos belonging to the current user for data privacy."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Memos retrieved successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = MemoResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<MemoResponseDto>> getAllMemos() {
        
        log.debug("API request to get all memos for authenticated user");

        try {
            // Retrieve all user memos through service layer
            List<MemoResponseDto> userMemos = memoService.getUserMemos();
            
            log.debug("Retrieved {} memos for user", userMemos.size());
            
            // Return memo list with HTTP 200 OK status
            return ResponseEntity.ok(userMemos);
            
        } catch (IllegalStateException e) {
            log.warn("Memo retrieval failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo retrieval: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Retrieves memos for the authenticated user with pagination support.
     * 
     * This endpoint provides paginated access to user memos, enabling efficient
     * handling of users with large memo collections. It supports configurable
     * page sizes and sorting options.
     * 
     * @param page Page number (0-based, default: 0)
     * @param size Page size (default: 10, max: 100)
     * @param sort Sort criteria (default: createdAt,desc)
     * @return ResponseEntity with paginated memo results and HTTP 200 status
     * 
     * HTTP method: GET /api/memos/paginated
     * Authentication: Required (JWT Bearer token)
     * Query parameters:
     * - page: Page number (0-based)
     * - size: Number of items per page
     * - sort: Sorting criteria
     * 
     * Pagination features:
     * - Configurable page size with reasonable limits
     * - Sorting support for different memo fields
     * - Pagination metadata in response
     * - Efficient database queries
     * 
     * Success response (200 OK):
     * - Paginated memo results with metadata
     * - Total count and page information
     * - Sorted according to specified criteria
     */
    @GetMapping("/paginated")
    @Operation(
        summary = "Get user memos with pagination",
        description = "Retrieves memos owned by the authenticated user with pagination support. " +
                     "Enables efficient handling of large memo collections with configurable page sizes and sorting."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Paginated memos retrieved successfully",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid pagination parameters",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Page<MemoResponseDto>> getMemosPaginated(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @Parameter(description = "Page size (maximum 100)")
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size,
            @Parameter(description = "Sort criteria (e.g., createdAt,desc)")
            @RequestParam(defaultValue = "createdAt,desc") String sort) {
        
        log.debug("API request for paginated memos - page: {}, size: {}, sort: {}", page, size, sort);

        try {
            // Parse sort parameter
            String[] sortParams = sort.split(",");
            String sortField = sortParams[0];
            Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) 
                ? Sort.Direction.DESC : Sort.Direction.ASC;
            
            // Create pageable object with sorting
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
            
            // Retrieve paginated memos through service layer
            Page<MemoResponseDto> memoPage = memoService.getUserMemosPaginated(pageable);
            
            log.debug("Retrieved page {} of {} with {} memos", 
                    memoPage.getNumber(), memoPage.getTotalPages(), memoPage.getNumberOfElements());
            
            // Return paginated results with HTTP 200 OK status
            return ResponseEntity.ok(memoPage);
            
        } catch (IllegalStateException e) {
            log.warn("Paginated memo retrieval failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (IllegalArgumentException e) {
            log.warn("Invalid pagination parameters: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during paginated memo retrieval: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Retrieves a specific memo by ID if owned by the authenticated user.
     * 
     * This endpoint fetches a memo by its unique identifier, but only if
     * the memo is owned by the currently authenticated user. This ensures
     * users cannot access other users' memos even with knowledge of memo IDs.
     * 
     * @param memoId The unique identifier of the memo to retrieve
     * @return ResponseEntity with memo information and HTTP 200 status
     * 
     * HTTP method: GET /api/memos/{memoId}
     * Authentication: Required (JWT Bearer token)
     * Path parameter: memoId (Long) - unique memo identifier
     * Response: MemoResponseDto with memo information
     * 
     * Security implementation:
     * - Ownership verification before data return
     * - No information leakage about other users' memos
     * - Consistent error responses for unauthorized access
     * 
     * Success response (200 OK):
     * - Complete memo information including metadata
     * - Auditing information and content statistics
     * - Full memo content and details
     * 
     * Error responses:
     * - 401 Unauthorized: Missing or invalid authentication
     * - 404 Not Found: Memo not found or not owned by user
     * - 500 Internal Server Error: Unexpected system error
     */
    @GetMapping("/{memoId}")
    @Operation(
        summary = "Get memo by ID",
        description = "Retrieves a specific memo by its ID if owned by the authenticated user. " +
                     "Ensures users can only access their own memos for data privacy and security."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Memo retrieved successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = MemoResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Memo not found or access denied",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<MemoResponseDto> getMemoById(
            @Parameter(description = "Unique identifier of the memo")
            @PathVariable Long memoId) {
        
        log.debug("API request to get memo with ID: {}", memoId);

        try {
            // Retrieve specific memo through service layer
            MemoResponseDto memo = memoService.getMemoById(memoId);
            
            log.debug("Successfully retrieved memo ID: {}", memoId);
            
            // Return memo with HTTP 200 OK status
            return ResponseEntity.ok(memo);
            
        } catch (IllegalStateException e) {
            log.warn("Memo retrieval failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (IllegalArgumentException e) {
            log.warn("Memo not found or access denied for ID: {}", memoId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo retrieval for ID {}: {}", memoId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Updates an existing memo if owned by the authenticated user.
     * 
     * This endpoint allows users to update the title and content of their
     * existing memos. The update is only permitted if the memo is owned
     * by the currently authenticated user.
     * 
     * @param memoId The unique identifier of the memo to update
     * @param updateRequest The update request containing new title and content
     * @return ResponseEntity with updated memo information and HTTP 200 status
     * 
     * HTTP method: PUT /api/memos/{memoId}
     * Authentication: Required (JWT Bearer token)
     * Path parameter: memoId (Long) - unique memo identifier
     * Request body: UpdateMemoRequestDto with new title and content
     * Response: MemoResponseDto with updated memo information
     * 
     * Validation performed:
     * - Title: Required, maximum 50 characters
     * - Content: Required, maximum 255 characters
     * - Ownership verification before update
     * 
     * Success response (200 OK):
     * - Updated memo information with new content
     * - Updated modification timestamp and modifier
     * - Complete memo metadata and statistics
     * 
     * Error responses:
     * - 400 Bad Request: Invalid input data or validation failures
     * - 401 Unauthorized: Missing or invalid authentication
     * - 404 Not Found: Memo not found or not owned by user
     * - 422 Unprocessable Entity: Business rule violations
     */
    @PutMapping("/{memoId}")
    @Operation(
        summary = "Update memo by ID",
        description = "Updates an existing memo's title and content if owned by the authenticated user. " +
                     "Includes validation for character limits and automatic modification tracking."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Memo updated successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = MemoResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid input data or validation error",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Memo not found or access denied",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "422",
            description = "Unprocessable entity - business rule violation",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<MemoResponseDto> updateMemo(
            @Parameter(description = "Unique identifier of the memo to update")
            @PathVariable Long memoId,
            @Valid @RequestBody UpdateMemoRequestDto updateRequest) {
        
        log.info("API request to update memo ID: {} with title: {}", memoId, updateRequest.getTitle());

        try {
            // Update memo through service layer
            MemoResponseDto updatedMemo = memoService.updateMemo(memoId, updateRequest);
            
            log.info("Memo updated successfully with ID: {}", memoId);
            
            // Return updated memo with HTTP 200 OK status
            return ResponseEntity.ok(updatedMemo);
            
        } catch (IllegalStateException e) {
            log.warn("Memo update failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (IllegalArgumentException e) {
            log.warn("Memo not found or access denied for update ID: {}", memoId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo update for ID {}: {}", memoId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Deletes a memo if owned by the authenticated user.
     * 
     * This endpoint permanently removes a memo from the system, but only
     * if the memo is owned by the currently authenticated user. The
     * deletion is permanent and cannot be undone.
     * 
     * @param memoId The unique identifier of the memo to delete
     * @return ResponseEntity with HTTP 204 No Content status
     * 
     * HTTP method: DELETE /api/memos/{memoId}
     * Authentication: Required (JWT Bearer token)
     * Path parameter: memoId (Long) - unique memo identifier
     * Response: No content (empty body)
     * 
     * Security implementation:
     * - Ownership verification before deletion
     * - Permanent removal from system
     * - No cross-user memo deletion possible
     * 
     * Success response (204 No Content):
     * - Empty response body
     * - Confirms successful deletion
     * - Permanent removal completed
     * 
     * Error responses:
     * - 401 Unauthorized: Missing or invalid authentication
     * - 404 Not Found: Memo not found or not owned by user
     * - 500 Internal Server Error: Unexpected system error
     */
    @DeleteMapping("/{memoId}")
    @Operation(
        summary = "Delete memo by ID",
        description = "Permanently deletes a memo if owned by the authenticated user. " +
                     "This operation cannot be undone and completely removes the memo from the system."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "204",
            description = "Memo deleted successfully",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Memo not found or access denied",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Void> deleteMemo(
            @Parameter(description = "Unique identifier of the memo to delete")
            @PathVariable Long memoId) {
        
        log.info("API request to delete memo with ID: {}", memoId);

        try {
            // Delete memo through service layer
            memoService.deleteMemo(memoId);
            
            log.info("Memo deleted successfully with ID: {}", memoId);
            
            // Return HTTP 204 No Content status
            return ResponseEntity.noContent().build();
            
        } catch (IllegalStateException e) {
            log.warn("Memo deletion failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (IllegalArgumentException e) {
            log.warn("Memo not found or access denied for deletion ID: {}", memoId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo deletion for ID {}: {}", memoId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Searches user's memos by title containing the specified keyword.
     * 
     * This endpoint searches through the current user's memos to find those
     * with titles containing the specified keyword. The search is case-
     * insensitive and supports partial matches.
     * 
     * @param keyword The keyword to search for in memo titles
     * @return ResponseEntity with list of matching memos and HTTP 200 status
     * 
     * HTTP method: GET /api/memos/search/title
     * Authentication: Required (JWT Bearer token)
     * Query parameter: keyword (String) - search term for titles
     * Response: List of MemoResponseDto with matching memos
     * 
     * Search features:
     * - Case-insensitive title search
     * - Partial match support
     * - User-specific search scope
     * - Results ordered by creation date
     * 
     * Success response (200 OK):
     * - Array of matching memos
     * - Empty array if no matches found
     * - Complete memo information for each result
     */
    @GetMapping("/search/title")
    @Operation(
        summary = "Search memos by title",
        description = "Searches user's memos by title containing the specified keyword. " +
                     "Case-insensitive search with partial match support for flexible memo discovery."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Search completed successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = MemoResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid search parameters",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<MemoResponseDto>> searchMemosByTitle(
            @Parameter(description = "Keyword to search for in memo titles")
            @RequestParam String keyword) {
        
        log.debug("API request to search memos by title keyword: {}", keyword);

        try {
            // Search memos by title through service layer
            List<MemoResponseDto> matchingMemos = memoService.searchMemosByTitle(keyword);
            
            log.debug("Found {} memos matching title keyword: {}", matchingMemos.size(), keyword);
            
            // Return search results with HTTP 200 OK status
            return ResponseEntity.ok(matchingMemos);
            
        } catch (IllegalStateException e) {
            log.warn("Memo search failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo title search: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Searches user's memos by content containing the specified keyword.
     * 
     * This endpoint searches through the current user's memos to find those
     * with content containing the specified keyword. The search is case-
     * insensitive and supports partial matches for comprehensive content discovery.
     * 
     * @param keyword The keyword to search for in memo content
     * @return ResponseEntity with list of matching memos and HTTP 200 status
     * 
     * HTTP method: GET /api/memos/search/content
     * Authentication: Required (JWT Bearer token)
     * Query parameter: keyword (String) - search term for content
     * Response: List of MemoResponseDto with matching memos
     * 
     * Search capabilities:
     * - Case-insensitive content search
     * - Partial match support within memo text
     * - User-specific search scope
     * - Results ordered by creation date
     * 
     * Success response (200 OK):
     * - Array of matching memos with highlighted content
     * - Empty array if no matches found
     * - Complete memo information for each result
     */
    @GetMapping("/search/content")
    @Operation(
        summary = "Search memos by content",
        description = "Searches user's memos by content containing the specified keyword. " +
                     "Case-insensitive search for comprehensive memo content discovery and information retrieval."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Search completed successfully",
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = MemoResponseDto.class)
            )
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid search parameters",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<MemoResponseDto>> searchMemosByContent(
            @Parameter(description = "Keyword to search for in memo content")
            @RequestParam String keyword) {
        
        log.debug("API request to search memos by content keyword: {}", keyword);

        try {
            // Search memos by content through service layer
            List<MemoResponseDto> matchingMemos = memoService.searchMemosByContent(keyword);
            
            log.debug("Found {} memos matching content keyword: {}", matchingMemos.size(), keyword);
            
            // Return search results with HTTP 200 OK status
            return ResponseEntity.ok(matchingMemos);
            
        } catch (IllegalStateException e) {
            log.warn("Memo content search failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during memo content search: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Gets statistics and recent memos for the authenticated user's dashboard.
     * 
     * This endpoint provides a comprehensive dashboard view including user
     * memo statistics and recent memos for quick access. It's designed for
     * dashboard widgets and summary displays.
     * 
     * @param limit Maximum number of recent memos to include (default: 5, max: 20)
     * @return ResponseEntity with dashboard data and HTTP 200 status
     * 
     * HTTP method: GET /api/memos/dashboard
     * Authentication: Required (JWT Bearer token)
     * Query parameter: limit (optional) - number of recent memos to include
     * Response: Dashboard data with statistics and recent memos
     * 
     * Dashboard information:
     * - Total memo count for the user
     * - Recent memos for quick access
     * - Summary statistics
     * - User activity overview
     * 
     * Success response (200 OK):
     * - Total memo count
     * - Array of recent memos
     * - Dashboard metadata and statistics
     */
    @GetMapping("/dashboard")
    @Operation(
        summary = "Get user memo dashboard",
        description = "Retrieves dashboard information including memo statistics and recent memos " +
                     "for the authenticated user. Designed for dashboard widgets and summary displays."
    )
    @ApiResponses(value = {
        @ApiResponse(
            responseCode = "200",
            description = "Dashboard data retrieved successfully",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid dashboard parameters",
            content = @Content(mediaType = "application/json")
        ),
        @ApiResponse(
            responseCode = "401",
            description = "Authentication required - missing or invalid JWT token",
            content = @Content(mediaType = "application/json")
        )
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Map<String, Object>> getDashboard(
            @Parameter(description = "Maximum number of recent memos to include (max 20)")
            @RequestParam(defaultValue = "5") @Min(1) @Max(20) int limit) {
        
        log.debug("API request for user dashboard with limit: {}", limit);

        try {
            // Get memo statistics and recent memos through service layer
            Long totalMemoCount = memoService.getUserMemoCount();
            List<MemoResponseDto> recentMemos = memoService.getRecentMemos(limit);
            
            // Build dashboard response
            Map<String, Object> dashboardData = new HashMap<>();
            dashboardData.put("totalMemos", totalMemoCount);
            dashboardData.put("recentMemos", recentMemos);
            dashboardData.put("hasMoreMemos", totalMemoCount > limit);
            dashboardData.put("dashboardGeneratedAt", java.time.LocalDateTime.now());
            
            log.debug("Dashboard data generated - total: {}, recent: {}", 
                    totalMemoCount, recentMemos.size());
            
            // Return dashboard data with HTTP 200 OK status
            return ResponseEntity.ok(dashboardData);
            
        } catch (IllegalStateException e) {
            log.warn("Dashboard request failed due to authentication issue: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            
        } catch (Exception e) {
            log.error("Unexpected error during dashboard generation: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
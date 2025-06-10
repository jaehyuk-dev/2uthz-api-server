package com._uthz.api_server.repository;

import com._uthz.api_server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for User entity database operations.
 * 
 * This repository provides data access methods for user-related operations
 * including authentication, user management, and profile queries.
 * Extends JpaRepository to inherit standard CRUD operations.
 * 
 * Key functionalities:
 * - User authentication by email lookup
 * - Email uniqueness validation
 * - Standard CRUD operations through JPA inheritance
 * - Custom query methods for specific business needs
 * 
 * The repository follows Spring Data JPA conventions for method naming
 * and automatically generates implementations at runtime.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Finds a user by their email address.
     * 
     * This method is primarily used for authentication purposes where
     * the email serves as the unique username for login.
     * 
     * @param email The email address to search for (case-sensitive)
     * @return Optional containing the User if found, empty Optional otherwise
     * 
     * Usage examples:
     * - User authentication during login
     * - Email validation during registration
     * - Password reset functionality
     * 
     * Note: Email lookup is case-sensitive. Consider normalizing
     * email case in the service layer if needed.
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user with the given email already exists.
     * 
     * This method is used for validation during user registration
     * to ensure email uniqueness across the system.
     * 
     * @param email The email address to check for existence
     * @return true if a user with this email exists, false otherwise
     * 
     * Usage:
     * - Registration validation to prevent duplicate accounts
     * - Email availability checking in real-time
     * 
     * Performance note: This method only checks existence without
     * fetching the full User entity, making it more efficient
     * than findByEmail() when only existence check is needed.
     */
    boolean existsByEmail(String email);

    /**
     * Checks if a user with the given nickname already exists.
     * 
     * While nicknames don't need to be unique for functionality,
     * this method can be used if the business logic requires
     * unique nicknames or for suggestion purposes.
     * 
     * @param nickname The nickname to check for existence
     * @return true if a user with this nickname exists, false otherwise
     * 
     * Potential usage:
     * - Nickname uniqueness validation (if required)
     * - Suggesting alternative nicknames during registration
     * - Preventing confusing similar nicknames
     */
    boolean existsByNickname(String nickname);

    /**
     * Custom query to find users by partial nickname match (case-insensitive).
     * 
     * This method demonstrates custom JPQL query usage for more complex
     * search functionality beyond standard method naming conventions.
     * 
     * @param nicknamePattern The pattern to search for (supports wildcards)
     * @return List of users whose nicknames match the pattern
     * 
     * Usage examples:
     * - User search functionality
     * - Auto-complete for user mentions
     * - Admin user management interfaces
     * 
     * Example: findByNicknameContainingIgnoreCase("john") would find
     * users with nicknames like "John", "johnny", "Johnson", etc.
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.nickname) LIKE LOWER(CONCAT('%', :nickname, '%'))")
    java.util.List<User> findByNicknameContainingIgnoreCase(@Param("nickname") String nickname);

    /**
     * Finds users created within a specific date range.
     * 
     * This custom query is useful for analytics, reporting, and
     * administrative functions to track user registration patterns.
     * 
     * @param startDate The start of the date range (inclusive)
     * @param endDate The end of the date range (inclusive)
     * @return List of users created within the specified date range
     * 
     * Usage:
     * - User registration analytics
     * - Monthly/yearly user growth reports
     * - Admin dashboard statistics
     */
    @Query("SELECT u FROM User u WHERE u.createdAt BETWEEN :startDate AND :endDate ORDER BY u.createdAt DESC")
    java.util.List<User> findUsersCreatedBetween(
        @Param("startDate") java.time.LocalDateTime startDate,
        @Param("endDate") java.time.LocalDateTime endDate
    );
}
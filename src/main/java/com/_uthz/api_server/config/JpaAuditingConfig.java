package com._uthz.api_server.config;

import com._uthz.api_server.service.UserContextService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.util.Optional;

/**
 * Configuration class for JPA Auditing functionality.
 * 
 * This configuration enables automatic auditing of entity creation and modification
 * by integrating with Spring Security to capture the current authenticated user.
 * It provides the infrastructure for BaseEntity auditing fields to be automatically
 * populated with user and timestamp information.
 * 
 * Key responsibilities:
 * - Enable JPA Auditing for all entities extending BaseEntity
 * - Configure AuditorAware to capture current authenticated user
 * - Integrate with UserContextService for user identification
 * - Handle both authenticated and unauthenticated contexts
 * 
 * Auditing features enabled:
 * - @CreatedBy and @LastModifiedBy annotations
 * - @CreatedDate and @LastModifiedDate annotations
 * - Automatic timestamp generation
 * - Current user identification from Spring Security context
 * 
 * Security integration:
 * - Uses UserContextService for secure user identification
 * - Handles unauthenticated requests gracefully
 * - Respects Spring Security authentication state
 * - No manual user ID setting required
 * 
 * Usage:
 * - Automatically applied to all entities extending BaseEntity
 * - No additional configuration required in entity classes
 * - Works with standard JPA operations (save, update, etc.)
 * - Compatible with Spring Data repositories
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider") // Enable JPA Auditing with custom auditor provider
@RequiredArgsConstructor // Lombok: generates constructor for final fields
@Slf4j // Lombok: provides logger instance for debugging
public class JpaAuditingConfig {

    /**
     * UserContextService for extracting current authenticated user information.
     * Used to identify the user performing entity operations for auditing purposes.
     */
    private final UserContextService userContextService;

    /**
     * Provides the current auditor (user) for JPA Auditing.
     * 
     * This bean implements AuditorAware interface to supply the current user ID
     * for auditing purposes. It integrates with the UserContextService to extract
     * the authenticated user from the Spring Security context.
     * 
     * @return AuditorAware<Long> implementation that returns current user ID
     * 
     * Auditor resolution logic:
     * 1. Attempts to get current user ID from UserContextService
     * 2. Returns Optional.of(userId) if user is authenticated
     * 3. Returns Optional.empty() if no authenticated user
     * 4. Logs audit events for monitoring and debugging
     * 
     * Behavior in different contexts:
     * - Authenticated requests: Returns the current user's ID
     * - Unauthenticated requests: Returns empty Optional
     * - System operations: Returns empty Optional (handled gracefully)
     * - Background tasks: Returns empty Optional (no user context)
     * 
     * Security considerations:
     * - User ID extraction respects Spring Security authentication
     * - No user ID spoofing or manual override possible
     * - Handles authentication edge cases gracefully
     * - Provides audit trail for all user operations
     * 
     * Error handling:
     * - Gracefully handles UserContextService exceptions
     * - Returns empty Optional for any error conditions
     * - Logs errors for debugging without exposing sensitive information
     * - Ensures auditing doesn't break entity operations
     */
    @Bean
    public AuditorAware<Long> auditorProvider() {
        return () -> {
            try {
                // Attempt to get current authenticated user ID
                Long currentUserId = userContextService.getCurrentUserId();
                
                if (currentUserId != null) {
                    // User is authenticated - return user ID for auditing
                    log.debug("JPA Auditing: Using user ID {} for entity auditing", currentUserId);
                    return Optional.of(currentUserId);
                } else {
                    // No authenticated user - return empty for system operations
                    log.debug("JPA Auditing: No authenticated user found, auditing with null user");
                    return Optional.empty();
                }
                
            } catch (Exception e) {
                // Handle any errors in user context extraction gracefully
                log.warn("JPA Auditing: Error extracting current user for auditing: {}", e.getMessage());
                return Optional.empty();
            }
        };
    }
}
package com._uthz.api_server.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Base entity class providing common auditing fields for all domain entities.
 * 
 * This abstract base class implements JPA Auditing to automatically track
 * creation and modification metadata for all entities that extend it.
 * It provides a consistent approach to auditing across the application
 * and eliminates the need to duplicate auditing fields in every entity.
 * 
 * Key features:
 * - Automatic creation timestamp and user tracking
 * - Automatic last modification timestamp and user tracking
 * - Reusable across all domain entities in the application
 * - Integrated with Spring Data JPA Auditing
 * - Thread-safe auditing implementation
 * 
 * Auditing information captured:
 * - createdBy: User ID of the entity creator
 * - createdAt: Timestamp when the entity was first persisted
 * - lastModifiedBy: User ID of the last user to modify the entity
 * - lastModifiedAt: Timestamp of the last modification
 * 
 * Usage pattern:
 * ```java
 * @Entity
 * public class MyEntity extends BaseEntity {
 *     // Entity-specific fields go here
 *     // Auditing fields are inherited from BaseEntity
 * }
 * ```
 * 
 * Security considerations:
 * - User IDs are automatically captured from Spring Security context
 * - Timestamps are immutable once set (creation) or automatically updated (modification)
 * - Auditing information cannot be manually overridden
 * - Provides complete audit trail for compliance and debugging
 * 
 * Database design:
 * - All extending entities will have consistent auditing columns
 * - Auditing fields use standard naming conventions
 * - Timestamps stored with precision for accurate tracking
 * - User IDs stored as Long to match User entity primary key
 */
@MappedSuperclass // Indicates this is a base class for entities, not an entity itself
@EntityListeners(AuditingEntityListener.class) // Enables JPA Auditing for this entity
@Getter // Lombok: generates getter methods for all fields
@Setter // Lombok: generates setter methods for all fields
public abstract class BaseEntity {

    /**
     * User ID of the entity creator.
     * 
     * This field is automatically populated when the entity is first persisted
     * using Spring Data JPA Auditing. The user ID is extracted from the current
     * Spring Security authentication context.
     * 
     * Auditing behavior:
     * - Set automatically on entity creation
     * - Never updated after initial creation
     * - Cannot be manually overridden
     * - Null if entity is created outside authenticated context
     * 
     * Usage scenarios:
     * - Tracking entity ownership for authorization
     * - Audit trails for compliance requirements
     * - User activity monitoring and analytics
     * - Data retention and cleanup operations
     * 
     * Database storage:
     * - Column name: created_by
     * - Type: BIGINT (matches User entity primary key)
     * - Nullable: true (for system-created entities)
     * - Updatable: false (immutable after creation)
     */
    @CreatedBy
    @Column(name = "created_by", nullable = true, updatable = false)
    private Long createdBy;

    /**
     * Timestamp when the entity was first created.
     * 
     * This field is automatically populated with the current timestamp
     * when the entity is first persisted to the database. It provides
     * an immutable record of when the entity was originally created.
     * 
     * Auditing behavior:
     * - Set automatically on entity creation
     * - Never updated after initial creation
     * - Cannot be manually overridden
     * - Uses server timezone for consistency
     * 
     * Timestamp precision:
     * - Uses LocalDateTime for timezone-neutral storage
     * - Precision depends on database configuration
     * - Recommended to use UTC timezone in production
     * 
     * Usage scenarios:
     * - Audit trails and compliance reporting
     * - Data retention and archival policies
     * - Performance monitoring and analytics
     * - Chronological ordering and filtering
     * 
     * Database storage:
     * - Column name: created_at
     * - Type: TIMESTAMP (with precision)
     * - Nullable: false (always set on creation)
     * - Updatable: false (immutable after creation)
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * User ID of the last user to modify the entity.
     * 
     * This field is automatically updated whenever the entity is modified
     * and persisted to the database. It tracks the user responsible for
     * the most recent changes to the entity.
     * 
     * Auditing behavior:
     * - Updated automatically on every entity modification
     * - Initially set to the same value as createdBy
     * - Cannot be manually overridden
     * - Null if entity is modified outside authenticated context
     * 
     * Modification tracking:
     * - Updated on any field change that triggers entity save
     * - Includes both direct field updates and relationship changes
     * - Tracks the authenticated user making the change
     * - Provides accountability for data modifications
     * 
     * Usage scenarios:
     * - Tracking responsibility for entity changes
     * - Audit trails for compliance and security
     * - User activity monitoring
     * - Change approval and review workflows
     * 
     * Database storage:
     * - Column name: last_modified_by
     * - Type: BIGINT (matches User entity primary key)
     * - Nullable: true (for system-modified entities)
     * - Updatable: true (updated on modifications)
     */
    @LastModifiedBy
    @Column(name = "last_modified_by", nullable = true)
    private Long lastModifiedBy;

    /**
     * Timestamp of the last modification to the entity.
     * 
     * This field is automatically updated with the current timestamp
     * whenever the entity is modified and persisted. It provides a
     * record of when the entity was most recently changed.
     * 
     * Auditing behavior:
     * - Updated automatically on every entity modification
     * - Initially set to the same value as createdAt
     * - Cannot be manually overridden
     * - Uses server timezone for consistency
     * 
     * Modification detection:
     * - Triggered by any field change that results in entity persistence
     * - Includes cascade operations that modify the entity
     * - Updated even for minor field changes
     * - Provides precise timing of last modification
     * 
     * Usage scenarios:
     * - Cache invalidation strategies
     * - Optimistic locking and conflict resolution
     * - Data synchronization and replication
     * - Performance monitoring and optimization
     * 
     * Database storage:
     * - Column name: last_modified_at
     * - Type: TIMESTAMP (with precision)
     * - Nullable: false (always updated on modification)
     * - Updatable: true (updated on modifications)
     */
    @LastModifiedDate
    @Column(name = "last_modified_at", nullable = false)
    private LocalDateTime lastModifiedAt;

    /**
     * Checks if this entity was created by the specified user.
     * 
     * Convenience method for authorization checks and ownership validation.
     * This method provides a clean way to verify if a user is the original
     * creator of the entity, which is commonly used for authorization logic.
     * 
     * @param userId The user ID to check against the creator
     * @return true if the specified user created this entity, false otherwise
     * 
     * Usage patterns:
     * ```java
     * if (entity.isCreatedBy(currentUserId)) {
     *     // User has creator privileges
     * }
     * ```
     * 
     * Authorization scenarios:
     * - Owner-only operations (edit, delete)
     * - Creator privilege checks
     * - Resource access control
     * - User activity filtering
     * 
     * Null safety:
     * - Returns false if createdBy is null
     * - Returns false if userId parameter is null
     * - Safe to use in authorization logic
     */
    public boolean isCreatedBy(Long userId) {
        return userId != null && userId.equals(this.createdBy);
    }

    /**
     * Checks if this entity was last modified by the specified user.
     * 
     * Convenience method for tracking modification responsibility and
     * implementing user-specific change tracking logic.
     * 
     * @param userId The user ID to check against the last modifier
     * @return true if the specified user last modified this entity, false otherwise
     * 
     * Usage scenarios:
     * - Change tracking and accountability
     * - User activity monitoring
     * - Modification attribution
     * - Audit trail analysis
     */
    public boolean isLastModifiedBy(Long userId) {
        return userId != null && userId.equals(this.lastModifiedBy);
    }

    /**
     * Checks if this entity has been modified since creation.
     * 
     * Determines whether the entity has been updated after its initial creation
     * by comparing the creation and last modification timestamps.
     * 
     * @return true if the entity has been modified since creation, false otherwise
     * 
     * Usage scenarios:
     * - Change detection logic
     * - Audit trail analysis
     * - Data quality monitoring
     * - Cache invalidation decisions
     * 
     * Implementation notes:
     * - Compares timestamps for inequality
     * - Handles null timestamps gracefully
     * - Returns false if either timestamp is null
     */
    public boolean hasBeenModified() {
        return createdAt != null && lastModifiedAt != null && 
               !createdAt.equals(lastModifiedAt);
    }

    /**
     * Gets the age of the entity in days since creation.
     * 
     * Calculates the number of days between the entity creation timestamp
     * and the current time. Useful for data retention policies and analytics.
     * 
     * @return Number of days since entity creation, or 0 if createdAt is null
     * 
     * Usage scenarios:
     * - Data retention and archival policies
     * - Age-based filtering and queries
     * - Analytics and reporting
     * - Performance optimization decisions
     */
    public long getAgeDays() {
        if (createdAt == null) {
            return 0;
        }
        return java.time.temporal.ChronoUnit.DAYS.between(createdAt, LocalDateTime.now());
    }

    /**
     * Returns a string representation of the auditing information.
     * 
     * Provides a human-readable summary of the entity's auditing fields
     * for debugging, logging, and monitoring purposes.
     * 
     * @return String representation of auditing information
     * 
     * Security considerations:
     * - Includes user IDs which may be sensitive
     * - Intended for internal logging and debugging
     * - Should not be exposed in public APIs
     */
    @Override
    public String toString() {
        return String.format("BaseEntity{createdBy=%d, createdAt=%s, lastModifiedBy=%d, lastModifiedAt=%s}",
                           createdBy, createdAt, lastModifiedBy, lastModifiedAt);
    }
}
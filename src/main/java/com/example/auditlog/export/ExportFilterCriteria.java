package com.example.auditlog.export;

import java.util.Objects;
import org.springframework.util.StringUtils;

/**
 * Filter criteria for bulk audit event export.
 *
 * <p>Enforces mutual exclusivity between {@code actorId} and {@code resourceId}.
 * Exactly one of them must be provided and must not be blank.
 * {@code includeArchived} defaults to {@code true}.
 */
public record ExportFilterCriteria(
        FilterType filterType,
        String filterValue,
        boolean includeArchived) {

    public enum FilterType {
        ACTOR_ID,
        RESOURCE_ID
    }

    public static ExportFilterCriteria of(String actorId, String resourceId, Boolean includeArchived) {
        boolean hasActor = StringUtils.hasText(actorId);
        boolean hasResource = StringUtils.hasText(resourceId);

        // Check for blank strings explicitly if non-null
        if (actorId != null && !hasActor) {
            throw new IllegalArgumentException("'actorId' must not be blank");
        }
        if (resourceId != null && !hasResource) {
            throw new IllegalArgumentException("'resourceId' must not be blank");
        }

        if (!hasActor && !hasResource) {
            throw new IllegalArgumentException("Either 'actorId' or 'resourceId' must be provided");
        }
        if (hasActor && hasResource) {
            throw new IllegalArgumentException("Parameters 'actorId' and 'resourceId' are mutually exclusive; provide exactly one");
        }

        boolean resolvedIncludeArchived = includeArchived == null || includeArchived;

        if (hasActor) {
            return new ExportFilterCriteria(FilterType.ACTOR_ID, actorId.trim(), resolvedIncludeArchived);
        } else {
            return new ExportFilterCriteria(FilterType.RESOURCE_ID, resourceId.trim(), resolvedIncludeArchived);
        }
    }
}

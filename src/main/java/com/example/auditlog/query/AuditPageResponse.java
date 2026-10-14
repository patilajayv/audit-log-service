package com.example.auditlog.query;

import java.util.List;

/**
 * Standard paginated response structure containing query results and pagination metadata.
 *
 * @param <T> the item type contained in the page
 */
public record AuditPageResponse<T>(
        List<T> events,
        int page,
        int size,
        long totalElements,
        int totalPages,
        boolean first,
        boolean last) {

    public static <T> AuditPageResponse<T> of(List<T> events, int page, int size, long totalElements) {
        int totalPages = totalElements == 0 ? 0 : (int) Math.ceil((double) totalElements / size);
        boolean first = page == 0;
        boolean last = totalPages == 0 || page >= totalPages - 1;
        return new AuditPageResponse<>(events, page, size, totalElements, totalPages, first, last);
    }
}

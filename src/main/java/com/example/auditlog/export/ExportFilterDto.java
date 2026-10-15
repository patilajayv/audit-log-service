package com.example.auditlog.export;

/**
 * Filter metadata included in the export bundle manifest.
 */
public record ExportFilterDto(
        String filterType,
        String filterValue,
        boolean includeArchived) {
}

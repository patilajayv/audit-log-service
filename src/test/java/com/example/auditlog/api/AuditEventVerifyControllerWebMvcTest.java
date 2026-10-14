package com.example.auditlog.api;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auditlog.AuditLogConfiguration;
import com.example.auditlog.hashing.AuditHashService;
import com.example.auditlog.verify.AuditVerificationResponse;
import com.example.auditlog.verify.AuditVerificationService;
import com.example.auditlog.verify.ChainViolation;
import com.example.auditlog.verify.ChainViolationType;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * WebMvc slice tests for {@code GET /audit/verify} validating HTTP contract,
 * response serialization for intact and corrupted chains, and diagnostic status.
 */
@WebMvcTest(AuditVerificationController.class)
@Import({AuditLogConfiguration.class, AuditControllerAdvice.class, AuditHashService.class})
class AuditEventVerifyControllerWebMvcTest {

    private static final String SAMPLE_RECORD_HASH =
            "d4fdc27004f4d0ab21f89b9259ea15175f0a7b85fcc6bfa2c0bb1713c573e00e";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuditVerificationService verificationService;

    @Test
    @DisplayName("GET /audit/verify returns 200 OK with INTACT status for valid chain")
    void testVerifyChain_intact() throws Exception {
        AuditVerificationResponse intactResponse = AuditVerificationResponse.intact(
                5L, 5L, SAMPLE_RECORD_HASH, 5L, SAMPLE_RECORD_HASH);

        when(verificationService.verifyChain()).thenReturn(intactResponse);

        mockMvc.perform(get("/audit/verify")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.status").value("INTACT"))
                .andExpect(jsonPath("$.recordsVerified").value(5))
                .andExpect(jsonPath("$.headSequenceNo").value(5))
                .andExpect(jsonPath("$.headRecordHash").value(SAMPLE_RECORD_HASH))
                .andExpect(jsonPath("$.lastVerifiedSequenceNo").value(5))
                .andExpect(jsonPath("$.lastVerifiedRecordHash").value(SAMPLE_RECORD_HASH))
                .andExpect(jsonPath("$.violation").doesNotExist());

        verify(verificationService).verifyChain();
    }

    @Test
    @DisplayName("GET /audit/verify returns 200 OK with CORRUPTED status and violation details")
    void testVerifyChain_corrupted() throws Exception {
        UUID eventId = UUID.randomUUID();
        ChainViolation violation = new ChainViolation(
                ChainViolationType.CONTENT_HASH_MISMATCH,
                3L,
                eventId,
                "expected-hash-value",
                "actual-tampered-hash",
                "Content hash mismatch at sequence 3");

        AuditVerificationResponse corruptedResponse = AuditVerificationResponse.corrupted(
                2L, 5L, SAMPLE_RECORD_HASH, 2L, "hash-at-2", violation);

        when(verificationService.verifyChain()).thenReturn(corruptedResponse);

        mockMvc.perform(get("/audit/verify")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CORRUPTED"))
                .andExpect(jsonPath("$.recordsVerified").value(2))
                .andExpect(jsonPath("$.headSequenceNo").value(5))
                .andExpect(jsonPath("$.headRecordHash").value(SAMPLE_RECORD_HASH))
                .andExpect(jsonPath("$.lastVerifiedSequenceNo").value(2))
                .andExpect(jsonPath("$.lastVerifiedRecordHash").value("hash-at-2"))
                .andExpect(jsonPath("$.violation.type").value("CONTENT_HASH_MISMATCH"))
                .andExpect(jsonPath("$.violation.sequenceNo").value(3))
                .andExpect(jsonPath("$.violation.eventId").value(eventId.toString()))
                .andExpect(jsonPath("$.violation.expected").value("expected-hash-value"))
                .andExpect(jsonPath("$.violation.actual").value("actual-tampered-hash"))
                .andExpect(jsonPath("$.violation.message").value("Content hash mismatch at sequence 3"));

        verify(verificationService).verifyChain();
    }

    @Test
    @DisplayName("GET /audit/verify accepts and traces correlation ID")
    void testVerifyChain_withCorrelationId() throws Exception {
        AuditVerificationResponse intactResponse = AuditVerificationResponse.intact(
                0L, 0L, AuditHashService.GENESIS_HASH, 0L, AuditHashService.GENESIS_HASH);

        when(verificationService.verifyChain()).thenReturn(intactResponse);

        mockMvc.perform(get("/audit/verify")
                        .header("X-Correlation-ID", "corr-test-12345")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("INTACT"))
                .andExpect(jsonPath("$.recordsVerified").value(0));

        verify(verificationService).verifyChain();
    }
}

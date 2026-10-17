package com.recordlogs.domain;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BatchHeaderTest {

    private static final String ROOT = "ab".repeat(32);

    @Test
    void roundTripsThroughBlockDataString() {
        BatchHeader header = new BatchHeader(ROOT, 100);
        assertThat(header.toData()).isEqualTo("MERKLE|" + ROOT + "|100");
        Optional<BatchHeader> parsed = BatchHeader.tryParse(header.toData());
        assertThat(parsed.isPresent()).isTrue();
        assertThat(parsed.get()).isEqualTo(header);
    }

    @Test
    void tryParseRejectsMalformedData() {
        String[] bad = {
                null, "", "GENESIS",
                "MERKLE|" + ROOT,                       // missing count
                "MERKLE|" + ROOT + "|5|extra",          // extra part
                "merkle|" + ROOT + "|5",                // wrong tag case
                "MERKLE|" + "AB".repeat(32) + "|5",     // uppercase root
                "MERKLE|" + "ab".repeat(31) + "|5",     // short root
                "MERKLE|" + ROOT + "|0",                // count < 1
                "MERKLE|" + ROOT + "|-3",
                "MERKLE|" + ROOT + "|+5",               // non-canonical number
                "MERKLE|" + ROOT + "|05",
                "MERKLE|" + ROOT + "|five",
                "MERKLE|" + ROOT + "|99999999999"       // overflows int
        };
        for (String data : bad) {
            assertThat(BatchHeader.tryParse(data).isPresent()).as("data=" + data).isFalse();
        }
    }

    @Test
    void constructorRejectsInvalidValues() {
        assertThatThrownBy(() -> new BatchHeader("short", 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BatchHeader(null, 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BatchHeader(ROOT, 0)).isInstanceOf(IllegalArgumentException.class);
    }
}

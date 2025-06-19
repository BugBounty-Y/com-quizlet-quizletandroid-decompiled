package com.quizlet.eventlogger.features.studymodes.test;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@Metadata
/* loaded from: classes2.dex */
public final class TestEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);
    private TestPayload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public TestEventLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public void setPayload(TestPayload testPayload) {
        this.payload = testPayload;
    }

    public /* synthetic */ TestEventLog(TestPayload testPayload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : testPayload);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    public TestPayload getPayload() {
        return this.payload;
    }

    public TestEventLog(@JsonProperty("payload") TestPayload testPayload) {
        this.payload = testPayload;
    }
}

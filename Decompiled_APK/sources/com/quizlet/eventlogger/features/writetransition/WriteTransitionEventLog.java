package com.quizlet.eventlogger.features.writetransition;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;

@Metadata
/* loaded from: classes2.dex */
public final class WriteTransitionEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);
    private final WriteTransitionPayload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public WriteTransitionEventLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public /* synthetic */ WriteTransitionEventLog(WriteTransitionPayload writeTransitionPayload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : writeTransitionPayload);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    public WriteTransitionPayload getPayload() {
        return this.payload;
    }

    public WriteTransitionEventLog(@JsonProperty("payload") WriteTransitionPayload writeTransitionPayload) {
        this.payload = writeTransitionPayload;
    }
}

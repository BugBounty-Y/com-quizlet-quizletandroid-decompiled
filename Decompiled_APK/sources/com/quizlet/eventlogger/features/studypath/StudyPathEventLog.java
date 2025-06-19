package com.quizlet.eventlogger.features.studypath;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class StudyPathEventLog extends StandardizedEventLog {
    private StudyPathPayload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        new Companion(null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public StudyPathEventLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudyPathEventLog) && Intrinsics.b(this.payload, ((StudyPathEventLog) obj).payload);
    }

    public final int hashCode() {
        StudyPathPayload studyPathPayload = this.payload;
        if (studyPathPayload == null) {
            return 0;
        }
        return studyPathPayload.hashCode();
    }

    public void setPayload(StudyPathPayload studyPathPayload) {
        this.payload = studyPathPayload;
    }

    public final String toString() {
        return "StudyPathEventLog(payload=" + this.payload + ")";
    }

    public /* synthetic */ StudyPathEventLog(StudyPathPayload studyPathPayload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : studyPathPayload);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    public StudyPathPayload getPayload() {
        return this.payload;
    }

    public StudyPathEventLog(@JsonProperty("payload") StudyPathPayload studyPathPayload) {
        this.payload = studyPathPayload;
    }
}

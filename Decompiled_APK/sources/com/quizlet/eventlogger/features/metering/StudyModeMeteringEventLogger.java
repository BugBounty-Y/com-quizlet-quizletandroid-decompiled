package com.quizlet.eventlogger.features.metering;

import com.braze.requests.framework.m;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.learnonboarding.b;
import com.quizlet.shared.enums.MeteredEventType$Companion;
import com.quizlet.shared.enums.h;
import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudyModeMeteringEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    @Metadata
    public /* synthetic */ class WhenMappings {
        static {
            int[] iArr = new int[h.values().length];
            try {
                iArr[1] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                MeteredEventType$Companion meteredEventType$Companion = h.Companion;
                iArr[2] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    public StudyModeMeteringEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(long j) {
        EventLoggerExt.c(this.eventLogger, new m(4, j));
    }

    public final void b(long j, StudiableMeteringData studiableMeteringData, String str, String str2) {
        EventLoggerExt.c(this.eventLogger, new b(j, studiableMeteringData, str2, str));
    }

    public final void c(long j, String studySessionId, StudiableMeteringData meteringData) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        int iOrdinal = meteringData.a.ordinal();
        b(j, meteringData, studySessionId, iOrdinal != 1 ? iOrdinal != 2 ? null : "test_remaining_attempts_toast_dismiss" : "learn_remaining_rounds_toast_dismiss");
    }

    public final void d(long j, String studySessionId, StudiableMeteringData meteringData) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        int iOrdinal = meteringData.a.ordinal();
        b(j, meteringData, studySessionId, iOrdinal != 1 ? iOrdinal != 2 ? null : "test_remaining_attempts_toast_impression" : "learn_remaining_rounds_toast_impression");
    }
}

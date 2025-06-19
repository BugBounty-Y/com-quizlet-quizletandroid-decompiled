package com.quizlet.eventlogger;

import com.quizlet.shared.schemas.eventlogger.events.LoggingEventType$Companion;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class KmpEventLogger implements com.quizlet.shared.eventlogger.a {

    @NotNull
    private final EventLogger eventLogger;

    @Metadata
    public /* synthetic */ class WhenMappings {
        static {
            int[] iArr = new int[com.quizlet.shared.schemas.eventlogger.events.b.values().length];
            try {
                LoggingEventType$Companion loggingEventType$Companion = com.quizlet.shared.schemas.eventlogger.events.b.Companion;
                iArr[0] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                LoggingEventType$Companion loggingEventType$Companion2 = com.quizlet.shared.schemas.eventlogger.events.b.Companion;
                iArr[1] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    public KmpEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }
}

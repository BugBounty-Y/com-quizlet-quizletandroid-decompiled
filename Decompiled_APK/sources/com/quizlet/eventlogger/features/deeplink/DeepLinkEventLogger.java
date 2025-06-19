package com.quizlet.eventlogger.features.deeplink;

import com.quizlet.eventlogger.EventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class DeepLinkEventLogger {
    public static final /* synthetic */ int a = 0;

    @NotNull
    private final EventLogger eventLogger;

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

    public DeepLinkEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(DeepLinkEventLog deepLinkEventLog) {
        c.a.a("%s, action=%s, payload=%s", deepLinkEventLog, deepLinkEventLog.getAction(), deepLinkEventLog.getPayload());
        this.eventLogger.l(deepLinkEventLog);
    }
}

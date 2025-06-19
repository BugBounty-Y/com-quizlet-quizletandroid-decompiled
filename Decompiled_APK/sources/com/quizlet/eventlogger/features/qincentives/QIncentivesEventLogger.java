package com.quizlet.eventlogger.features.qincentives;

import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class QIncentivesEventLogger {

    @NotNull
    private static final a Companion = new a();

    @NotNull
    private final EventLogger eventLogger;

    public QIncentivesEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a() {
        EventLoggerExt.a(this.eventLogger, "free_trial_confirmation_shown", new Z(6));
    }

    public final void b() {
        EventLoggerExt.a(this.eventLogger, "free_trial_deep_link_opened", new Z(6));
    }

    public final void c() {
        EventLoggerExt.a(this.eventLogger, "free_trial_failed", new Z(6));
    }

    public final void d() {
        EventLoggerExt.a(this.eventLogger, "free_trial_requested", new Z(6));
    }

    public final void e() {
        EventLoggerExt.a(this.eventLogger, "free_trial_success", new Z(6));
    }
}

package com.quizlet.eventlogger.features.authentication;

import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SignUpWallEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    public SignUpWallEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a() {
        EventLoggerExt.a(this.eventLogger, "did_tap_sign_up_banner_close_button", new Z(9));
    }

    public final void b() {
        EventLoggerExt.a(this.eventLogger, "did_tap_sign_up_banner_log_in_button", new Z(11));
    }

    public final void c(Function1 otherLogging) {
        Intrinsics.checkNotNullParameter(otherLogging, "otherLogging");
        EventLoggerExt.a(this.eventLogger, "did_show_sign_up_banner", otherLogging);
    }

    public final void d() {
        EventLoggerExt.a(this.eventLogger, "did_tap_sign_up_banner_sign_up_button", new Z(10));
    }
}

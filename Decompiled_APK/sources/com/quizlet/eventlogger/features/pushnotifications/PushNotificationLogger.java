package com.quizlet.eventlogger.features.pushnotifications;

import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class PushNotificationLogger {

    @NotNull
    private static final String PUSH_NOTIFICATION_PERMISSION_DENIED = "push_notification_permission_denied";

    @NotNull
    private static final String PUSH_NOTIFICATION_PERMISSION_GRANTED = "push_notification_permission_granted";

    @NotNull
    private static final String PUSH_NOTIFICATION_SYSTEM_PROMPT_SEEN = "push_notification_system_prompt_seen";

    @NotNull
    private static final String PUSH_PRIMER_ACCEPTED = "push_primer_accepted";

    @NotNull
    private static final String PUSH_PRIMER_DENIED = "push_primer_denied";

    @NotNull
    private static final String PUSH_PRIMER_SEEN = "push_primer_seen";
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

    public PushNotificationLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a() {
        EventLoggerExt.c(this.eventLogger, new Z(18));
    }

    public final void b() {
        EventLoggerExt.c(this.eventLogger, new Z(19));
    }

    public final void c() {
        EventLoggerExt.c(this.eventLogger, new Z(17));
    }

    public final void d() {
        EventLoggerExt.c(this.eventLogger, new Z(20));
    }

    public final void e() {
        EventLoggerExt.c(this.eventLogger, new Z(16));
    }
}

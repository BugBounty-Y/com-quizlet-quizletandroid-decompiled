package com.quizlet.eventlogger;

import com.quizlet.eventlogger.model.AndroidEventLog;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class EventLoggerExt {
    public static final void a(EventLogger eventLogger, String action, Function1 modifier) {
        Intrinsics.checkNotNullParameter(eventLogger, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(modifier, "modifier");
        AndroidEventLog androidEventLogB = AndroidEventLog.Companion.b(AndroidEventLog.b, action, EventLogger.a, 12);
        modifier.invoke(androidEventLogB);
        eventLogger.l(androidEventLogB);
    }

    public static final void c(EventLogger eventLogger, Function1 modifier) {
        Intrinsics.checkNotNullParameter(eventLogger, "<this>");
        Intrinsics.checkNotNullParameter(modifier, "modifier");
        a(eventLogger, "user_action", modifier);
    }
}

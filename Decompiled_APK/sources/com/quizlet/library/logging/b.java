package com.quizlet.library.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.LibraryEventLog;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final EventLogger a;

    public b(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(LibraryEventLog libraryEventLog) {
        this.a.l(libraryEventLog);
    }
}
